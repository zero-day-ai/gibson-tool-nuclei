package nuclei

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/gibson-tool-nuclei/gen"
)

func TestToolImpl_Name(t *testing.T) {
	tool := &ToolImpl{}
	assert.Equal(t, "nuclei", tool.Name())
}

func TestToolImpl_Version(t *testing.T) {
	tool := &ToolImpl{}
	assert.Equal(t, "1.0.0", tool.Version())
}

func TestToolImpl_InputMessageType(t *testing.T) {
	tool := &ToolImpl{}
	expected := "gibson.tools.nuclei.NucleiRequest"
	assert.Equal(t, expected, tool.InputMessageType())
}

func TestToolImpl_OutputMessageType(t *testing.T) {
	tool := &ToolImpl{}
	expected := "gibson.tools.nuclei.NucleiResponse"
	assert.Equal(t, expected, tool.OutputMessageType())
}

func TestToolImpl_Tags(t *testing.T) {
	tool := &ToolImpl{}
	tags := tool.Tags()

	expectedTags := []string{
		"discovery",
		"vuln-scan",
		"T1595", // Active Scanning
		"T1190", // Exploit Public-Facing Application
	}

	assert.Equal(t, expectedTags, tags)
}

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		name     string
		request  *gen.NucleiRequest
		expected []string
	}{
		{
			name: "basic targets only",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color"},
		},
		{
			name: "with single template",
			request: &gen.NucleiRequest{
				Targets:   []string{"http://example.com"},
				Templates: []string{"cves/2021/CVE-2021-44228.yaml"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-t", "cves/2021/CVE-2021-44228.yaml"},
		},
		{
			name: "with multiple templates",
			request: &gen.NucleiRequest{
				Targets:   []string{"http://example.com"},
				Templates: []string{"cves/2021/", "exposures/", "misconfigurations/"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-t", "cves/2021/,exposures/,misconfigurations/"},
		},
		{
			name: "with single tag",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
				Tags:    []string{"cve"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-tags", "cve"},
		},
		{
			name: "with multiple tags",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
				Tags:    []string{"cve", "rce", "sqli"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-tags", "cve,rce,sqli"},
		},
		{
			name: "with single severity",
			request: &gen.NucleiRequest{
				Targets:  []string{"http://example.com"},
				Severity: []string{"critical"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-severity", "critical"},
		},
		{
			name: "with multiple severities",
			request: &gen.NucleiRequest{
				Targets:  []string{"http://example.com"},
				Severity: []string{"high", "critical"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-severity", "high,critical"},
		},
		{
			name: "with author filter",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
				Author:  []string{"pdteam", "geeknik"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-author", "pdteam,geeknik"},
		},
		{
			name: "with exclude tags",
			request: &gen.NucleiRequest{
				Targets:     []string{"http://example.com"},
				ExcludeTags: []string{"dos", "fuzz"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-exclude-tags", "dos,fuzz"},
		},
		{
			name: "with exclude severity",
			request: &gen.NucleiRequest{
				Targets:         []string{"http://example.com"},
				ExcludeSeverity: []string{"info", "low"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-exclude-severity", "info,low"},
		},
		{
			name: "with include templates",
			request: &gen.NucleiRequest{
				Targets:          []string{"http://example.com"},
				IncludeTemplates: []string{"cves/", "exposures/"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-include-templates", "cves/", "-include-templates", "exposures/"},
		},
		{
			name: "with exclude templates",
			request: &gen.NucleiRequest{
				Targets:          []string{"http://example.com"},
				ExcludeTemplates: []string{"fuzzing/", "dos/"},
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-exclude-templates", "fuzzing/", "-exclude-templates", "dos/"},
		},
		{
			name: "with threads",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
				Threads: 50,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-c", "50"},
		},
		{
			name: "with rate limit",
			request: &gen.NucleiRequest{
				Targets:   []string{"http://example.com"},
				RateLimit: 100,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-rate-limit", "100"},
		},
		{
			name: "with timeout",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
				Timeout: 30,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-timeout", "30"},
		},
		{
			name: "with retries",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
				Retries: 3,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-retries", "3"},
		},
		{
			name: "with bulk size",
			request: &gen.NucleiRequest{
				Targets:  []string{"http://example.com"},
				BulkSize: 25,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-bulk-size", "25"},
		},
		{
			name: "with follow redirects",
			request: &gen.NucleiRequest{
				Targets:         []string{"http://example.com"},
				FollowRedirects: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-follow-redirects"},
		},
		{
			name: "with follow host redirects",
			request: &gen.NucleiRequest{
				Targets:             []string{"http://example.com"},
				FollowHostRedirects: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-follow-host-redirects"},
		},
		{
			name: "with max redirects",
			request: &gen.NucleiRequest{
				Targets:      []string{"http://example.com"},
				MaxRedirects: 5,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-max-redirects", "5"},
		},
		{
			name: "with disable update check",
			request: &gen.NucleiRequest{
				Targets:            []string{"http://example.com"},
				DisableUpdateCheck: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-disable-update-check"},
		},
		{
			name: "with update templates",
			request: &gen.NucleiRequest{
				Targets:         []string{"http://example.com"},
				UpdateTemplates: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-update-templates"},
		},
		{
			name: "with headless",
			request: &gen.NucleiRequest{
				Targets:  []string{"http://example.com"},
				Headless: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-headless"},
		},
		{
			name: "with page timeout",
			request: &gen.NucleiRequest{
				Targets:     []string{"http://example.com"},
				PageTimeout: 20,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-page-timeout", "20"},
		},
		{
			name: "with show browser",
			request: &gen.NucleiRequest{
				Targets:     []string{"http://example.com"},
				ShowBrowser: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-show-browser"},
		},
		{
			name: "with system resolvers",
			request: &gen.NucleiRequest{
				Targets:         []string{"http://example.com"},
				SystemResolvers: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-system-resolvers"},
		},
		{
			name: "with passive mode",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
				Passive: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-passive"},
		},
		{
			name: "with offline http",
			request: &gen.NucleiRequest{
				Targets:     []string{"http://example.com"},
				OfflineHttp: true,
			},
			expected: []string{"-jsonl", "-silent", "-no-color", "-offline-http"},
		},
		{
			name: "comprehensive test with all options",
			request: &gen.NucleiRequest{
				Targets:             []string{"http://example.com"},
				Templates:           []string{"cves/2021/", "exposures/"},
				Tags:                []string{"cve", "rce"},
				Severity:            []string{"high", "critical"},
				Author:              []string{"pdteam"},
				ExcludeTags:         []string{"dos"},
				ExcludeSeverity:     []string{"info"},
				Threads:             50,
				RateLimit:           100,
				Timeout:             30,
				Retries:             3,
				BulkSize:            25,
				FollowRedirects:     true,
				FollowHostRedirects: true,
				MaxRedirects:        5,
				DisableUpdateCheck:  true,
				Headless:            true,
				PageTimeout:         20,
				SystemResolvers:     true,
				Passive:             true,
			},
			expected: []string{
				"-jsonl", "-silent", "-no-color",
				"-t", "cves/2021/,exposures/",
				"-tags", "cve,rce",
				"-severity", "high,critical",
				"-author", "pdteam",
				"-exclude-tags", "dos",
				"-exclude-severity", "info",
				"-c", "50",
				"-rate-limit", "100",
				"-timeout", "30",
				"-retries", "3",
				"-bulk-size", "25",
				"-follow-redirects",
				"-follow-host-redirects",
				"-max-redirects", "5",
				"-disable-update-check",
				"-headless",
				"-page-timeout", "20",
				"-system-resolvers",
				"-passive",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildArgs(tt.request)
			assert.Equal(t, tt.expected, args)
		})
	}
}

func TestParseOutput(t *testing.T) {
	t.Run("parse single vulnerability match", func(t *testing.T) {
		jsonLine := `{"template-id":"CVE-2021-44228","template-path":"/templates/cves/2021/CVE-2021-44228.yaml","info":{"name":"Apache Log4j RCE","author":["pdteam"],"severity":"critical","description":"Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],"classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0},"tags":["cve","rce","log4j"],"remediation":"Update to Log4j 2.15.0 or later"},"type":"http","host":"https://example.com","matched-at":"https://example.com/api","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Verify template match
		match := matches[0]
		assert.Equal(t, "CVE-2021-44228", match.TemplateId)
		assert.Equal(t, "Apache Log4j RCE", match.TemplateName)
		assert.Equal(t, "/templates/cves/2021/CVE-2021-44228.yaml", match.TemplatePath)
		assert.Equal(t, "http", match.Type)
		assert.Equal(t, "https://example.com", match.Host)
		assert.Equal(t, "https://example.com/api", match.MatchedAt)
		assert.Equal(t, "93.184.216.34", match.Ip)
		assert.Equal(t, int64(1705314600), match.Timestamp)

		// Verify template info
		require.NotNil(t, match.Info)
		assert.Equal(t, "Apache Log4j RCE", match.Info.Name)
		assert.Equal(t, "critical", match.Info.Severity)
		assert.Contains(t, match.Info.Description, "Apache Log4j2")
		assert.Equal(t, "pdteam", match.Info.Author)
		require.Len(t, match.Info.Reference, 1)
		assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", match.Info.Reference[0])
		require.Len(t, match.Info.Tags, 3)
		assert.Equal(t, []string{"cve", "rce", "log4j"}, match.Info.Tags)
		assert.Equal(t, "Update to Log4j 2.15.0 or later", match.Info.Remediation)

		// Verify classification
		require.NotNil(t, match.Info.Classification)
		require.Len(t, match.Info.Classification.CveId, 1)
		assert.Equal(t, "CVE-2021-44228", match.Info.Classification.CveId[0])
		require.Len(t, match.Info.Classification.CweId, 1)
		assert.Equal(t, "CWE-502", match.Info.Classification.CweId[0])
		assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", match.Info.Classification.CvssMetrics)
		assert.Equal(t, 10.0, match.Info.Classification.CvssScore)

		// Verify discovery result
		require.Len(t, discoveryResult.Hosts, 1)
		assert.Equal(t, "93.184.216.34", discoveryResult.Hosts[0].Ip)
		require.NotNil(t, discoveryResult.Hosts[0].Hostname)
		assert.Equal(t, "https://example.com", *discoveryResult.Hosts[0].Hostname)

		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]
		assert.Equal(t, "Apache Log4j RCE", finding.Title)
		assert.Equal(t, "critical", finding.Severity)
		require.NotNil(t, finding.Description)
		assert.Contains(t, *finding.Description, "Apache Log4j2")
		require.NotNil(t, finding.Category)
		assert.Equal(t, "vulnerability", *finding.Category)
		require.NotNil(t, finding.CveIds)
		assert.Equal(t, "CVE-2021-44228", *finding.CveIds)
		require.NotNil(t, finding.CvssScore)
		assert.Equal(t, 10.0, *finding.CvssScore)
		require.NotNil(t, finding.Remediation)
		assert.Equal(t, "Update to Log4j 2.15.0 or later", *finding.Remediation)
		require.NotNil(t, finding.ParentId)
		assert.Equal(t, "https://example.com", *finding.ParentId)
		require.NotNil(t, finding.ParentType)
		assert.Equal(t, "host", *finding.ParentType)
	})

	t.Run("parse multiple matches", func(t *testing.T) {
		jsonLines := `{"template-id":"CVE-2021-44228","template-path":"/templates/cves/2021/CVE-2021-44228.yaml","info":{"name":"Apache Log4j RCE","author":["pdteam"],"severity":"critical","description":"Log4j vulnerability","classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0}},"type":"http","host":"https://example.com","matched-at":"https://example.com/api","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}
{"template-id":"exposed-panel","template-path":"/templates/exposures/panels/admin-panel.yaml","info":{"name":"Admin Panel Exposed","author":["geeknik"],"severity":"medium","description":"Admin panel accessible","classification":{"cvss-score":5.3}},"type":"http","host":"http://test.com","matched-at":"http://test.com/admin","ip":"1.2.3.4","timestamp":"2024-01-15T10:31:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLines))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 2)

		// First match
		assert.Equal(t, "CVE-2021-44228", matches[0].TemplateId)
		assert.Equal(t, "Apache Log4j RCE", matches[0].TemplateName)
		assert.Equal(t, "critical", matches[0].Info.Severity)
		assert.Equal(t, "93.184.216.34", matches[0].Ip)

		// Second match
		assert.Equal(t, "exposed-panel", matches[1].TemplateId)
		assert.Equal(t, "Admin Panel Exposed", matches[1].TemplateName)
		assert.Equal(t, "medium", matches[1].Info.Severity)
		assert.Equal(t, "1.2.3.4", matches[1].Ip)

		// Discovery should have 2 hosts
		require.Len(t, discoveryResult.Hosts, 2)
		assert.Equal(t, "93.184.216.34", discoveryResult.Hosts[0].Ip)
		assert.Equal(t, "1.2.3.4", discoveryResult.Hosts[1].Ip)

		// Discovery should have 2 findings
		require.Len(t, discoveryResult.Findings, 2)
	})

	t.Run("parse with CVE/CWE/CVSS data", func(t *testing.T) {
		jsonLine := `{"template-id":"CVE-2022-0001","template-path":"/templates/cves/2022/CVE-2022-0001.yaml","info":{"name":"Test Vulnerability","author":["test"],"severity":"high","description":"Test CVE","classification":{"cve-id":["CVE-2022-0001","CVE-2022-0002"],"cwe-id":["CWE-79","CWE-89"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","cvss-score":7.1}},"type":"http","host":"http://vulnerable.com","matched-at":"http://vulnerable.com/page","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Verify multiple CVEs
		match := matches[0]
		require.NotNil(t, match.Info.Classification)
		require.Len(t, match.Info.Classification.CveId, 2)
		assert.Equal(t, "CVE-2022-0001", match.Info.Classification.CveId[0])
		assert.Equal(t, "CVE-2022-0002", match.Info.Classification.CveId[1])

		// Verify multiple CWEs
		require.Len(t, match.Info.Classification.CweId, 2)
		assert.Equal(t, "CWE-79", match.Info.Classification.CweId[0])
		assert.Equal(t, "CWE-89", match.Info.Classification.CweId[1])

		// Verify CVSS
		assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", match.Info.Classification.CvssMetrics)
		assert.Equal(t, 7.1, match.Info.Classification.CvssScore)

		// Verify finding has CVEs joined
		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]
		require.NotNil(t, finding.CveIds)
		assert.Equal(t, "CVE-2022-0001,CVE-2022-0002", *finding.CveIds)
		require.NotNil(t, finding.CvssScore)
		assert.Equal(t, 7.1, *finding.CvssScore)
	})

	t.Run("parse without classification", func(t *testing.T) {
		jsonLine := `{"template-id":"misconfiguration-001","template-path":"/templates/misconfigurations/test.yaml","info":{"name":"Configuration Issue","author":["test"],"severity":"low","description":"Misconfiguration found"},"type":"http","host":"http://test.com","matched-at":"http://test.com/config","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Verify no classification
		match := matches[0]
		assert.Nil(t, match.Info.Classification)

		// Verify finding still created but without CVE/CVSS
		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]
		assert.Equal(t, "Configuration Issue", finding.Title)
		assert.Equal(t, "low", finding.Severity)
		assert.Nil(t, finding.CveIds)
		assert.Nil(t, finding.CvssScore)
	})

	t.Run("parse with extracted results", func(t *testing.T) {
		jsonLine := `{"template-id":"extractor-test","template-path":"/templates/test.yaml","info":{"name":"Extractor Test","author":["test"],"severity":"info","description":"Test extraction"},"type":"http","host":"http://test.com","matched-at":"http://test.com/page","extracted-results":["result1","result2","result3"],"timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Verify extracted results
		match := matches[0]
		require.Len(t, match.ExtractedResults, 3)
		assert.Equal(t, "result1", match.ExtractedResults[0])
		assert.Equal(t, "result2", match.ExtractedResults[1])
		assert.Equal(t, "result3", match.ExtractedResults[2])
	})

	t.Run("parse with request and response", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://test.com","matched-at":"http://test.com/","request":"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n","response":"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nBody","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Verify request and response
		match := matches[0]
		assert.Contains(t, match.Request, "GET / HTTP/1.1")
		assert.Contains(t, match.Response, "HTTP/1.1 200 OK")
	})

	t.Run("parse with curl command", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://test.com","matched-at":"http://test.com/","curl-command":"curl -X GET 'http://test.com/' -H 'User-Agent: test'","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Verify curl command
		match := matches[0]
		assert.Contains(t, match.CurlCommand, "curl -X GET")
		assert.Contains(t, match.CurlCommand, "http://test.com/")
	})

	t.Run("parse with metadata", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://test.com","matched-at":"http://test.com/","metadata":{"key1":"value1","key2":"value2"},"timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Verify metadata
		match := matches[0]
		require.NotNil(t, match.Metadata)
		assert.Equal(t, "value1", match.Metadata["key1"])
		assert.Equal(t, "value2", match.Metadata["key2"])
	})

	t.Run("parse empty output", func(t *testing.T) {
		discoveryResult, matches, err := parseOutput([]byte(""))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		assert.Len(t, matches, 0)
		assert.Len(t, discoveryResult.Hosts, 0)
		assert.Len(t, discoveryResult.Findings, 0)
	})

	t.Run("parse malformed JSON line is skipped", func(t *testing.T) {
		jsonLines := `{"template-id":"test1","template-path":"/templates/test.yaml","info":{"name":"Test1","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://test.com","matched-at":"http://test.com/","timestamp":"2024-01-15T10:30:00Z"}
this is not valid JSON
{"template-id":"test2","template-path":"/templates/test.yaml","info":{"name":"Test2","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://test2.com","matched-at":"http://test2.com/","timestamp":"2024-01-15T10:31:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLines))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)

		// Should have 2 valid results (malformed line skipped)
		require.Len(t, matches, 2)
		assert.Equal(t, "test1", matches[0].TemplateId)
		assert.Equal(t, "test2", matches[1].TemplateId)
	})

	t.Run("parse result without host extracts from matched-at", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test","author":["test"],"severity":"info","description":"Test"},"type":"http","matched-at":"https://example.com:8443/path","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Should extract host from matched-at URL
		require.Len(t, discoveryResult.Hosts, 1)
		assert.Equal(t, "example.com", discoveryResult.Hosts[0].Ip)

		require.Len(t, discoveryResult.Findings, 1)
		require.NotNil(t, discoveryResult.Findings[0].ParentId)
		assert.Equal(t, "example.com", *discoveryResult.Findings[0].ParentId)
	})

	t.Run("parse result with IP separates host and IP", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"example.com","matched-at":"http://example.com/","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		// Host should have IP and hostname separated
		require.Len(t, discoveryResult.Hosts, 1)
		assert.Equal(t, "93.184.216.34", discoveryResult.Hosts[0].Ip)
		require.NotNil(t, discoveryResult.Hosts[0].Hostname)
		assert.Equal(t, "example.com", *discoveryResult.Hosts[0].Hostname)
	})

	t.Run("duplicate hosts are deduplicated", func(t *testing.T) {
		jsonLines := `{"template-id":"test1","template-path":"/templates/test.yaml","info":{"name":"Test1","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://example.com","matched-at":"http://example.com/page1","timestamp":"2024-01-15T10:30:00Z"}
{"template-id":"test2","template-path":"/templates/test.yaml","info":{"name":"Test2","author":["test"],"severity":"medium","description":"Test"},"type":"http","host":"http://example.com","matched-at":"http://example.com/page2","timestamp":"2024-01-15T10:31:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLines))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 2)

		// Should only have 1 host (deduplicated)
		require.Len(t, discoveryResult.Hosts, 1)
		assert.Equal(t, "http://example.com", discoveryResult.Hosts[0].Ip)

		// But should have 2 findings
		require.Len(t, discoveryResult.Findings, 2)
	})
}

func TestClassifyExecutionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected toolerr.ErrorClass
	}{
		{
			name:     "binary not found",
			err:      errors.New("exec: \"nuclei\": executable file not found in $PATH"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "binary not found alternative",
			err:      errors.New("nuclei not found"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "timeout error",
			err:      errors.New("command timed out after 600s"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "deadline exceeded",
			err:      errors.New("context deadline exceeded"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "timeout keyword",
			err:      errors.New("request timeout occurred"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "permission denied",
			err:      errors.New("permission denied: requires root"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "access denied",
			err:      errors.New("access denied"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "network unreachable",
			err:      errors.New("network unreachable"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "host unreachable",
			err:      errors.New("host unreachable"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "no route to host",
			err:      errors.New("no route to host"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "cancelled",
			err:      errors.New("command cancelled"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "canceled",
			err:      errors.New("context canceled"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "network error",
			err:      errors.New("network error occurred"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "connection error",
			err:      errors.New("connection error"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "unknown error",
			err:      errors.New("some unknown error occurred"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: toolerr.ErrorClassTransient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyExecutionError(tt.err)
			assert.Equal(t, tt.expected, got, "classifyExecutionError() = %v, want %v", got, tt.expected)
		})
	}
}

func TestValidation(t *testing.T) {
	tool := NewTool()

	tests := []struct {
		name        string
		request     *gen.NucleiRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid request",
			request: &gen.NucleiRequest{
				Targets: []string{"http://example.com"},
			},
			expectError: false,
		},
		{
			name: "empty targets",
			request: &gen.NucleiRequest{
				Targets: []string{},
			},
			expectError: true,
			errorMsg:    "at least one target is required",
		},
		{
			name: "nil targets",
			request: &gen.NucleiRequest{
				Targets: nil,
			},
			expectError: true,
			errorMsg:    "at least one target is required",
		},
		{
			name: "multiple targets",
			request: &gen.NucleiRequest{
				Targets: []string{
					"http://example.com",
					"https://test.com",
					"http://192.168.1.1:8080",
				},
			},
			expectError: false,
		},
		{
			name: "valid request with all options",
			request: &gen.NucleiRequest{
				Targets:             []string{"http://example.com"},
				Templates:           []string{"cves/2021/"},
				Tags:                []string{"cve", "rce"},
				Severity:            []string{"high", "critical"},
				Threads:             50,
				RateLimit:           100,
				Timeout:             30,
				FollowRedirects:     true,
				FollowHostRedirects: true,
				MaxRedirects:        5,
				Headless:            true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only test cases that expect validation errors
			// Valid requests would require the nuclei binary to be installed
			if !tt.expectError {
				// Skip valid request tests - they would try to execute the binary
				// These are covered by integration tests
				t.Skip("skipping valid request test - requires nuclei binary")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			_, err := tool.ExecuteProto(ctx, tt.request)

			require.Error(t, err)
			if tt.errorMsg != "" {
				assert.Contains(t, err.Error(), tt.errorMsg)
			}
		})
	}
}

func TestDiscoveryResult(t *testing.T) {
	t.Run("hosts are created correctly", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"example.com","matched-at":"http://example.com/","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)
		require.Len(t, matches, 1)

		require.Len(t, discoveryResult.Hosts, 1)
		host := discoveryResult.Hosts[0]
		assert.Equal(t, "93.184.216.34", host.Ip)
		require.NotNil(t, host.Hostname)
		assert.Equal(t, "example.com", *host.Hostname)
	})

	t.Run("findings are created with correct severity", func(t *testing.T) {
		jsonLines := `{"template-id":"critical-vuln","template-path":"/templates/test.yaml","info":{"name":"Critical Issue","author":["test"],"severity":"critical","description":"Critical vulnerability"},"type":"http","host":"http://example.com","matched-at":"http://example.com/","timestamp":"2024-01-15T10:30:00Z"}
{"template-id":"medium-vuln","template-path":"/templates/test.yaml","info":{"name":"Medium Issue","author":["test"],"severity":"medium","description":"Medium vulnerability"},"type":"http","host":"http://test.com","matched-at":"http://test.com/","timestamp":"2024-01-15T10:31:00Z"}`

		discoveryResult, _, err := parseOutput([]byte(jsonLines))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)

		require.Len(t, discoveryResult.Findings, 2)

		// First finding
		finding1 := discoveryResult.Findings[0]
		assert.Equal(t, "Critical Issue", finding1.Title)
		assert.Equal(t, "critical", finding1.Severity)
		require.NotNil(t, finding1.Category)
		assert.Equal(t, "vulnerability", *finding1.Category)

		// Second finding
		finding2 := discoveryResult.Findings[1]
		assert.Equal(t, "Medium Issue", finding2.Title)
		assert.Equal(t, "medium", finding2.Severity)
	})

	t.Run("findings are linked to hosts", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test Vulnerability","author":["test"],"severity":"high","description":"Test"},"type":"http","host":"http://example.com","matched-at":"http://example.com/page","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, _, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)

		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]

		require.NotNil(t, finding.ParentId)
		assert.Equal(t, "http://example.com", *finding.ParentId)
		require.NotNil(t, finding.ParentType)
		assert.Equal(t, "host", *finding.ParentType)
	})

	t.Run("CVE IDs are joined correctly", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Multiple CVEs","author":["test"],"severity":"critical","description":"Test","classification":{"cve-id":["CVE-2021-0001","CVE-2021-0002","CVE-2021-0003"]}},"type":"http","host":"http://example.com","matched-at":"http://example.com/","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, _, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)

		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]

		require.NotNil(t, finding.CveIds)
		assert.Equal(t, "CVE-2021-0001,CVE-2021-0002,CVE-2021-0003", *finding.CveIds)
	})

	t.Run("CVSS score is populated", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"CVSS Test","author":["test"],"severity":"high","description":"Test","classification":{"cvss-score":8.6}},"type":"http","host":"http://example.com","matched-at":"http://example.com/","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, _, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)

		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]

		require.NotNil(t, finding.CvssScore)
		assert.Equal(t, 8.6, *finding.CvssScore)
	})

	t.Run("remediation is populated", func(t *testing.T) {
		jsonLine := `{"template-id":"test","template-path":"/templates/test.yaml","info":{"name":"Test","author":["test"],"severity":"high","description":"Test","remediation":"Apply security patch 1.2.3"},"type":"http","host":"http://example.com","matched-at":"http://example.com/","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, _, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)

		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]

		require.NotNil(t, finding.Remediation)
		assert.Equal(t, "Apply security patch 1.2.3", *finding.Remediation)
	})

	t.Run("complete discovery result with all fields", func(t *testing.T) {
		jsonLine := `{"template-id":"CVE-2021-44228","template-path":"/templates/cves/2021/CVE-2021-44228.yaml","info":{"name":"Apache Log4j RCE","author":["pdteam"],"severity":"critical","description":"Apache Log4j2 vulnerability","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0},"remediation":"Update to Log4j 2.15.0"},"type":"http","host":"example.com","matched-at":"https://example.com/api","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, _, err := parseOutput([]byte(jsonLine))
		require.NoError(t, err)
		require.NotNil(t, discoveryResult)

		// Verify host
		require.Len(t, discoveryResult.Hosts, 1)
		host := discoveryResult.Hosts[0]
		assert.Equal(t, "93.184.216.34", host.Ip)
		require.NotNil(t, host.Hostname)
		assert.Equal(t, "example.com", *host.Hostname)

		// Verify finding
		require.Len(t, discoveryResult.Findings, 1)
		finding := discoveryResult.Findings[0]
		assert.Equal(t, "Apache Log4j RCE", finding.Title)
		assert.Equal(t, "critical", finding.Severity)
		require.NotNil(t, finding.Description)
		assert.Contains(t, *finding.Description, "Apache Log4j2")
		require.NotNil(t, finding.Category)
		assert.Equal(t, "vulnerability", *finding.Category)
		require.NotNil(t, finding.CveIds)
		assert.Equal(t, "CVE-2021-44228", *finding.CveIds)
		require.NotNil(t, finding.CvssScore)
		assert.Equal(t, 10.0, *finding.CvssScore)
		require.NotNil(t, finding.Remediation)
		assert.Equal(t, "Update to Log4j 2.15.0", *finding.Remediation)
		require.NotNil(t, finding.ParentId)
		assert.Equal(t, "example.com", *finding.ParentId)
		require.NotNil(t, finding.ParentType)
		assert.Equal(t, "host", *finding.ParentType)
	})
}

func TestConvertToProtoResponse(t *testing.T) {
	t.Run("converts discovery result and matches to response", func(t *testing.T) {
		jsonLines := `{"template-id":"test1","template-path":"/templates/test.yaml","info":{"name":"Test1","author":["test"],"severity":"high","description":"Test"},"type":"http","host":"http://example.com","matched-at":"http://example.com/","timestamp":"2024-01-15T10:30:00Z"}
{"template-id":"test2","template-path":"/templates/test.yaml","info":{"name":"Test2","author":["test"],"severity":"medium","description":"Test"},"type":"http","host":"http://test.com","matched-at":"http://test.com/","timestamp":"2024-01-15T10:31:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLines))
		require.NoError(t, err)

		response := convertToProtoResponse(discoveryResult, matches, 5.5)

		assert.Equal(t, int32(2), response.TotalMatches)
		assert.Equal(t, 5.5, response.Duration)
		assert.Len(t, response.Results, 2)
		assert.NotNil(t, response.Discovery)
	})

	t.Run("calculates templates executed from unique template IDs", func(t *testing.T) {
		jsonLines := `{"template-id":"template1","template-path":"/templates/test.yaml","info":{"name":"Test1","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://example.com","matched-at":"http://example.com/page1","timestamp":"2024-01-15T10:30:00Z"}
{"template-id":"template1","template-path":"/templates/test.yaml","info":{"name":"Test1","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://example.com","matched-at":"http://example.com/page2","timestamp":"2024-01-15T10:30:00Z"}
{"template-id":"template2","template-path":"/templates/test.yaml","info":{"name":"Test2","author":["test"],"severity":"info","description":"Test"},"type":"http","host":"http://example.com","matched-at":"http://example.com/page3","timestamp":"2024-01-15T10:30:00Z"}`

		discoveryResult, matches, err := parseOutput([]byte(jsonLines))
		require.NoError(t, err)

		response := convertToProtoResponse(discoveryResult, matches, 1.0)

		// 3 matches but only 2 unique templates
		assert.Equal(t, int32(3), response.TotalMatches)
		assert.Equal(t, int32(2), response.TemplatesExecuted)
	})

	t.Run("empty results", func(t *testing.T) {
		discoveryResult, matches, err := parseOutput([]byte(""))
		require.NoError(t, err)

		response := convertToProtoResponse(discoveryResult, matches, 0.1)

		assert.Equal(t, int32(0), response.TotalMatches)
		assert.Equal(t, int32(0), response.TemplatesExecuted)
		assert.Equal(t, 0.1, response.Duration)
		assert.Len(t, response.Results, 0)
		assert.NotNil(t, response.Discovery)
	})
}
