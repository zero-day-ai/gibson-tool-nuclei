package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"github.com/zero-day-ai/gibson-tool-nuclei/gen"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName        = "nuclei"
	ToolVersion     = "1.0.0"
	ToolDescription = `Vulnerability scanner powered by Nuclei templates. Automatically outputs JSONL format.

TEMPLATE SELECTION:
  -t, -templates           Template IDs or paths to use (comma-separated)
  -tags                    Filter templates by tags (comma-separated)
  -severity                Filter by severity (info,low,medium,high,critical)
  -author                  Filter templates by author
  -exclude-tags            Exclude templates with specific tags
  -exclude-severity        Exclude specific severities
  -include-templates       Include specific template files/dirs
  -exclude-templates       Exclude specific template files/dirs

RATE LIMITING:
  -c, -threads N           Number of concurrent threads (default: 25)
  -rate-limit N            Maximum requests per second
  -timeout N               Request timeout in seconds (default: 10)
  -retries N               Number of retries for failed requests
  -bulk-size N             Targets to process in parallel per template

HTTP OPTIONS:
  -follow-redirects        Follow HTTP redirects
  -follow-host-redirects   Follow redirects to different hosts
  -max-redirects N         Maximum number of redirects to follow

HEADLESS:
  -headless                Enable headless browser support
  -page-timeout N          Timeout for headless page operations (seconds)
  -show-browser            Show browser in headless mode

ADVANCED:
  -disable-update-check    Disable automatic template updates
  -update-templates        Force template updates before scanning
  -system-resolvers        Use system DNS resolvers
  -passive                 Enable passive scan mode (no active probing)
  -offline-http            Process HTTP raw requests from stdin

COMMON EXAMPLES:
  Basic scan: targets=["http://example.com"]
  CVE scan: targets=["http://example.com"], tags=["cve"]
  High severity: targets=["http://example.com"], severity=["high","critical"]
  Specific templates: targets=["http://example.com"], templates=["cves/2021/","exposures/"]
  Fast scan: targets=["http://example.com"], threads=50, rate_limit=150`
	BinaryName = "nuclei"
)

// ToolImpl implements the nuclei tool
type ToolImpl struct{}

// NewTool creates a new nuclei tool instance
func NewTool() tool.Tool {
	return &ToolImpl{}
}

// Name returns the tool name
func (t *ToolImpl) Name() string {
	return ToolName
}

// Version returns the tool version
func (t *ToolImpl) Version() string {
	return ToolVersion
}

// Description returns the tool description
func (t *ToolImpl) Description() string {
	return ToolDescription
}

// Tags returns the tool tags
func (t *ToolImpl) Tags() []string {
	return []string{
		"discovery",
		"vuln-scan",
		"T1595", // Active Scanning
		"T1190", // Exploit Public-Facing Application
	}
}

// InputMessageType returns the proto message type for input
func (t *ToolImpl) InputMessageType() string {
	return "gibson.tools.nuclei.NucleiRequest"
}

// OutputMessageType returns the proto message type for output
func (t *ToolImpl) OutputMessageType() string {
	return "gibson.tools.nuclei.NucleiResponse"
}

// InputProto returns a prototype instance of the input message.
// Implements the serve.SchemaProvider interface for reliable schema extraction.
func (t *ToolImpl) InputProto() proto.Message {
	return &gen.NucleiRequest{}
}

// OutputProto returns a prototype instance of the output message.
// Implements the serve.SchemaProvider interface for reliable schema extraction.
func (t *ToolImpl) OutputProto() proto.Message {
	return &gen.NucleiResponse{}
}

// ExecuteProto runs the nuclei tool with proto message input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert input to NucleiRequest
	req, ok := input.(*gen.NucleiRequest)
	if !ok {
		return nil, fmt.Errorf("invalid input type: expected *gen.NucleiRequest, got %T", input)
	}

	// Validate required fields
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}

	// Build nuclei command arguments
	args := buildArgs(req)

	// Execute nuclei command with targets via stdin
	targetInput := strings.Join(req.Targets, "\n")
	result, err := exec.Run(ctx, exec.Config{
		Command:   BinaryName,
		Args:      args,
		StdinData: []byte(targetInput),
		Timeout:   10 * time.Minute, // Default timeout for vulnerability scanning
	})

	if err != nil {
		// Classify execution errors based on underlying cause
		errClass := classifyExecutionError(err)
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).
			WithCause(err).
			WithClass(errClass)
	}

	// Parse nuclei JSONL output to proto types
	discoveryResult, matches, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).
			WithCause(err).
			WithClass(toolerr.ErrorClassSemantic)
	}

	// Convert discovery result to NucleiResponse
	scanDuration := time.Since(startTime).Seconds()
	response := convertToProtoResponse(discoveryResult, matches, scanDuration)

	return response, nil
}

// Health checks if the nuclei binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// NucleiJSONResult represents the JSONL output from nuclei
type NucleiJSONResult struct {
	TemplateID       string                 `json:"template-id"`
	TemplatePath     string                 `json:"template-path"`
	Info             NucleiInfo             `json:"info"`
	MatcherName      string                 `json:"matcher-name,omitempty"`
	Type             string                 `json:"type"`
	Host             string                 `json:"host"`
	MatchedAt        string                 `json:"matched-at"`
	ExtractedResults []string               `json:"extracted-results,omitempty"`
	IP               string                 `json:"ip,omitempty"`
	Timestamp        string                 `json:"timestamp"`
	CurlCommand      string                 `json:"curl-command,omitempty"`
	Request          string                 `json:"request,omitempty"`
	Response         string                 `json:"response,omitempty"`
	Metadata         map[string]string      `json:"metadata,omitempty"`
}

// NucleiInfo represents nuclei template metadata
type NucleiInfo struct {
	Name           string                `json:"name"`
	Author         []string              `json:"author"`
	Severity       string                `json:"severity"`
	Description    string                `json:"description,omitempty"`
	Reference      []string              `json:"reference,omitempty"`
	Tags           []string              `json:"tags,omitempty"`
	Classification *NucleiClassification `json:"classification,omitempty"`
	Remediation    string                `json:"remediation,omitempty"`
}

// NucleiClassification represents CVE/CWE classification data
type NucleiClassification struct {
	CVEId       []string `json:"cve-id,omitempty"`
	CWEId       []string `json:"cwe-id,omitempty"`
	CVSSMetrics string   `json:"cvss-metrics,omitempty"`
	CVSSScore   float64  `json:"cvss-score,omitempty"`
}

// parseOutput parses the JSONL output from nuclei and returns proto DiscoveryResult and matches
func parseOutput(data []byte) (*graphragpb.DiscoveryResult, []*gen.TemplateMatch, error) {
	result := &graphragpb.DiscoveryResult{}
	var matches []*gen.TemplateMatch

	// Track unique hosts to avoid duplicates
	seenHosts := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var jsonResult NucleiJSONResult
		if err := json.Unmarshal(line, &jsonResult); err != nil {
			// Skip malformed lines
			continue
		}

		// Convert to proto TemplateMatch
		protoMatch := convertJSONToProtoMatch(&jsonResult)
		matches = append(matches, protoMatch)

		// Extract discovery information - create Host and Vulnerability entities
		hostID := jsonResult.Host
		if hostID == "" {
			// Try to extract host from matched-at URL
			if jsonResult.MatchedAt != "" {
				if parsedURL, err := url.Parse(jsonResult.MatchedAt); err == nil {
					hostID = parsedURL.Hostname()
				}
			}
		}

		// Skip if no host identified
		if hostID == "" {
			continue
		}

		// Create Host node if not seen before
		if !seenHosts[hostID] {
			hostNode := &graphragpb.Host{
				Ip: hostID,
			}
			// If we have an IP in the result, use host as hostname
			if jsonResult.IP != "" && jsonResult.IP != hostID {
				hostNode.Ip = jsonResult.IP
				hostNode.Hostname = ptrStr(hostID)
			}
			result.Hosts = append(result.Hosts, hostNode)
			seenHosts[hostID] = true
		}

		// Create Finding entity for each vulnerability match
		finding := &graphragpb.Finding{
			Title:       jsonResult.Info.Name,
			Severity:    jsonResult.Info.Severity,
			Description: &jsonResult.Info.Description,
			ParentId:    &hostID,
			ParentType:  ptrStr("host"),
		}

		// Set category based on template type
		category := "vulnerability"
		finding.Category = &category

		// Add CVE/CWE/CVSS information if available
		if jsonResult.Info.Classification != nil {
			if len(jsonResult.Info.Classification.CVEId) > 0 {
				cveIds := strings.Join(jsonResult.Info.Classification.CVEId, ",")
				finding.CveIds = &cveIds
			}
			if jsonResult.Info.Classification.CVSSScore > 0 {
				score := jsonResult.Info.Classification.CVSSScore
				finding.CvssScore = &score
			}
		}

		// Add remediation if available
		if jsonResult.Info.Remediation != "" {
			finding.Remediation = &jsonResult.Info.Remediation
		}

		result.Findings = append(result.Findings, finding)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to scan nuclei output: %w", err)
	}

	return result, matches, nil
}

// convertJSONToProtoMatch converts nuclei JSON result to proto TemplateMatch
func convertJSONToProtoMatch(jsonResult *NucleiJSONResult) *gen.TemplateMatch {
	protoMatch := &gen.TemplateMatch{
		TemplateId:       jsonResult.TemplateID,
		TemplateName:     jsonResult.Info.Name,
		TemplatePath:     jsonResult.TemplatePath,
		MatcherName:      jsonResult.MatcherName,
		Type:             jsonResult.Type,
		Host:             jsonResult.Host,
		Url:              jsonResult.MatchedAt,
		MatchedAt:        jsonResult.MatchedAt,
		ExtractedResults: jsonResult.ExtractedResults,
		Request:          jsonResult.Request,
		Response:         jsonResult.Response,
		Ip:               jsonResult.IP,
		CurlCommand:      jsonResult.CurlCommand,
		Metadata:         jsonResult.Metadata,
	}

	// Parse timestamp
	if jsonResult.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, jsonResult.Timestamp); err == nil {
			protoMatch.Timestamp = t.Unix()
		}
	}

	// Convert template info
	protoMatch.Info = &gen.TemplateInfo{
		Name:        jsonResult.Info.Name,
		Severity:    jsonResult.Info.Severity,
		Description: jsonResult.Info.Description,
		Reference:   jsonResult.Info.Reference,
		Tags:        jsonResult.Info.Tags,
		Remediation: jsonResult.Info.Remediation,
	}

	// Join authors into single string
	if len(jsonResult.Info.Author) > 0 {
		protoMatch.Info.Author = strings.Join(jsonResult.Info.Author, ", ")
	}

	// Convert classification
	if jsonResult.Info.Classification != nil {
		protoMatch.Info.Classification = &gen.TemplateClassification{
			CveId:       jsonResult.Info.Classification.CVEId,
			CweId:       jsonResult.Info.Classification.CWEId,
			CvssMetrics: jsonResult.Info.Classification.CVSSMetrics,
			CvssScore:   jsonResult.Info.Classification.CVSSScore,
		}
	}

	return protoMatch
}

// ptrStr returns a pointer to the given string
func ptrStr(s string) *string {
	return &s
}

// convertToProtoResponse converts DiscoveryResult and matches to NucleiResponse
func convertToProtoResponse(discoveryResult *graphragpb.DiscoveryResult, matches []*gen.TemplateMatch, scanDuration float64) *gen.NucleiResponse {
	totalMatches := int32(len(matches))

	// Count unique templates executed (approximation based on unique template IDs)
	seenTemplates := make(map[string]bool)
	for _, match := range matches {
		seenTemplates[match.TemplateId] = true
	}
	templatesExecuted := int32(len(seenTemplates))

	response := &gen.NucleiResponse{
		Results:           matches,
		TotalMatches:      totalMatches,
		Duration:          scanDuration,
		TemplatesExecuted: templatesExecuted,
		Discovery:         discoveryResult,
	}

	return response
}

// classifyExecutionError determines the error class based on the underlying error
func classifyExecutionError(err error) toolerr.ErrorClass {
	if err == nil {
		return toolerr.ErrorClassTransient
	}

	errMsg := err.Error()

	// Check for binary not found errors
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "executable file not found") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for timeout errors
	if strings.Contains(errMsg, "timed out") || strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline exceeded") {
		return toolerr.ErrorClassTransient
	}

	// Check for permission errors
	if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "access denied") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for network errors
	if strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "host unreachable") || strings.Contains(errMsg, "no route to host") {
		return toolerr.ErrorClassTransient
	}

	// Check for cancellation
	if strings.Contains(errMsg, "cancelled") || strings.Contains(errMsg, "canceled") {
		return toolerr.ErrorClassTransient
	}

	// Default to transient for unknown execution errors
	return toolerr.ErrorClassTransient
}

// buildArgs builds the command line arguments for nuclei
func buildArgs(req *gen.NucleiRequest) []string {
	// Always start with -jsonl for JSONL output, -silent (no banner), -no-color
	args := []string{"-jsonl", "-silent", "-no-color"}

	// Templates
	if len(req.Templates) > 0 {
		args = append(args, "-t", strings.Join(req.Templates, ","))
	}

	// Tags
	if len(req.Tags) > 0 {
		args = append(args, "-tags", strings.Join(req.Tags, ","))
	}

	// Severity
	if len(req.Severity) > 0 {
		args = append(args, "-severity", strings.Join(req.Severity, ","))
	}

	// Author
	if len(req.Author) > 0 {
		args = append(args, "-author", strings.Join(req.Author, ","))
	}

	// Exclude tags
	if len(req.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(req.ExcludeTags, ","))
	}

	// Exclude severity
	if len(req.ExcludeSeverity) > 0 {
		args = append(args, "-exclude-severity", strings.Join(req.ExcludeSeverity, ","))
	}

	// Include templates
	if len(req.IncludeTemplates) > 0 {
		for _, tmpl := range req.IncludeTemplates {
			args = append(args, "-include-templates", tmpl)
		}
	}

	// Exclude templates
	if len(req.ExcludeTemplates) > 0 {
		for _, tmpl := range req.ExcludeTemplates {
			args = append(args, "-exclude-templates", tmpl)
		}
	}

	// Threads (concurrency)
	if req.Threads > 0 {
		args = append(args, "-c", strconv.Itoa(int(req.Threads)))
	}

	// Rate limit
	if req.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(int(req.RateLimit)))
	}

	// Timeout
	if req.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(int(req.Timeout)))
	}

	// Retries
	if req.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(int(req.Retries)))
	}

	// Bulk size
	if req.BulkSize > 0 {
		args = append(args, "-bulk-size", strconv.Itoa(int(req.BulkSize)))
	}

	// Follow redirects
	if req.FollowRedirects {
		args = append(args, "-follow-redirects")
	}

	// Follow host redirects
	if req.FollowHostRedirects {
		args = append(args, "-follow-host-redirects")
	}

	// Max redirects
	if req.MaxRedirects > 0 {
		args = append(args, "-max-redirects", strconv.Itoa(int(req.MaxRedirects)))
	}

	// Disable update check
	if req.DisableUpdateCheck {
		args = append(args, "-disable-update-check")
	}

	// Update templates
	if req.UpdateTemplates {
		args = append(args, "-update-templates")
	}

	// Headless
	if req.Headless {
		args = append(args, "-headless")
	}

	// Page timeout
	if req.PageTimeout > 0 {
		args = append(args, "-page-timeout", strconv.Itoa(int(req.PageTimeout)))
	}

	// Show browser
	if req.ShowBrowser {
		args = append(args, "-show-browser")
	}

	// System resolvers
	if req.SystemResolvers {
		args = append(args, "-system-resolvers")
	}

	// Passive mode
	if req.Passive {
		args = append(args, "-passive")
	}

	// Offline HTTP
	if req.OfflineHttp {
		args = append(args, "-offline-http")
	}

	return args
}
