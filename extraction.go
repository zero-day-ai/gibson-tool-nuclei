package nuclei

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/extraction"
	"google.golang.org/protobuf/proto"
)

// NucleiExtractor extracts entities from nuclei vulnerability scan results.
// It converts NucleiResponse proto messages into DiscoveryResult containing:
//   - Finding entities (vulnerability type, severity, title, description)
//   - Evidence entities (matched content, extracted data)
//   - Endpoint entities (target URLs)
type NucleiExtractor struct{}

func NewNucleiExtractor() *NucleiExtractor { return &NucleiExtractor{} }

func (e *NucleiExtractor) ToolName() string              { return "nuclei" }
func (e *NucleiExtractor) CanExtract(msg proto.Message) bool { _, ok := msg.(*toolspb.NucleiResponse); return ok }

func (e *NucleiExtractor) Extract(ctx context.Context, msg proto.Message) (*graphragpb.DiscoveryResult, error) {
	resp, ok := msg.(*toolspb.NucleiResponse)
	if !ok {
		return nil, fmt.Errorf("expected *toolspb.NucleiResponse, got %T", msg)
	}

	if len(resp.Results) == 0 {
		return &graphragpb.DiscoveryResult{}, nil
	}

	discovery := &graphragpb.DiscoveryResult{}
	endpointMap := make(map[string]bool)

	for _, match := range resp.Results {
		if match.Info == nil {
			continue
		}

		findingID := generateFindingID(match.TemplateId, match.Host, match.MatchedAt)

		finding := &graphragpb.Finding{
			Id:       &findingID,
			Title:    match.Info.Name,
			Severity: normalizeSeverity(match.Info.Severity),
		}
		if match.Info.Description != "" {
			finding.Description = extraction.StringPtr(match.Info.Description)
		}
		if match.Info.Remediation != "" {
			finding.Remediation = extraction.StringPtr(match.Info.Remediation)
		}
		if len(match.Info.Tags) > 0 {
			finding.Category = extraction.StringPtr(strings.Join(match.Info.Tags, ","))
		}
		if match.Info.Classification != nil {
			if len(match.Info.Classification.CveId) > 0 {
				finding.CveIds = extraction.StringPtr(strings.Join(match.Info.Classification.CveId, ","))
			}
			if match.Info.Classification.CvssScore > 0 {
				s := match.Info.Classification.CvssScore
				finding.CvssScore = &s
			}
		}
		conf := 1.0
		finding.Confidence = &conf

		// Link finding to endpoint
		if match.Url != "" {
			endpointID := extraction.EndpointID("", match.Url, "")
			finding.ParentId = extraction.StringPtr(endpointID)
			finding.ParentType = extraction.StringPtr("endpoint")

			if !endpointMap[endpointID] {
				endpoint := &graphragpb.Endpoint{
					Id:  &endpointID,
					Url: match.Url,
				}
				if match.Type == "http" {
					endpoint.Method = extraction.StringPtr("GET")
				}
				discovery.Endpoints = append(discovery.Endpoints, endpoint)
				endpointMap[endpointID] = true
			}
		}

		discovery.Findings = append(discovery.Findings, finding)

		// Extract evidence
		for idx, extracted := range match.ExtractedResults {
			evidenceID := generateEvidenceID(findingID, idx)
			evidence := &graphragpb.Evidence{
				Id:        &evidenceID,
				FindingId: findingID,
				Type:      "extracted_data",
			}
			if extracted != "" {
				evidence.Content = extraction.StringPtr(extracted)
			}
			if match.Url != "" {
				evidence.Url = extraction.StringPtr(match.Url)
			}
			discovery.Evidence = append(discovery.Evidence, evidence)
		}

		if len(match.ExtractedResults) == 0 && match.MatchedAt != "" {
			evidenceID := generateEvidenceID(findingID, 0)
			content := fmt.Sprintf("Matched at: %s", match.MatchedAt)
			if match.MatcherName != "" {
				content += fmt.Sprintf(" (matcher: %s)", match.MatcherName)
			}
			evidence := &graphragpb.Evidence{
				Id:        &evidenceID,
				FindingId: findingID,
				Type:      "match_location",
				Content:   extraction.StringPtr(content),
			}
			if match.Url != "" {
				evidence.Url = extraction.StringPtr(match.Url)
			}
			discovery.Evidence = append(discovery.Evidence, evidence)
		}
	}

	return discovery, nil
}

func normalizeSeverity(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "info", "low", "medium", "high", "critical":
		return s
	default:
		return "info"
	}
}

func generateFindingID(templateID, host, matchedAt string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("finding:nuclei:%s:%s:%s", templateID, host, matchedAt))).String()
}

func generateEvidenceID(findingID string, index int) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("evidence:%s:%d", findingID, index))).String()
}
