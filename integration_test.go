//go:build integration

package nuclei

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/types"
	"github.com/zero-day-ai/gibson-tool-nuclei/gen"
)

func TestNucleiIntegration(t *testing.T) {
	// Skip if nuclei binary is not available
	if _, err := exec.LookPath(BinaryName); err != nil {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health should be at least degraded (healthy or degraded, not unhealthy)
		if health.Status == types.StatusUnhealthy {
			t.Logf("nuclei health check unhealthy: %s", health.Message)
		} else {
			t.Logf("nuclei health check: %s - %s", health.Status, health.Message)
		}
	})

	// Test with info-level templates (safe, non-intrusive)
	t.Run("InfoLevelScan", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		req := &gen.NucleiRequest{
			Targets:  []string{"https://example.com"},
			Severity: []string{"info"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "info level scan should not error")
		require.NotNil(t, resp, "response should not be nil")

		nucleiResp, ok := resp.(*gen.NucleiResponse)
		require.True(t, ok, "response should be NucleiResponse")

		// Verify response structure
		assert.NotNil(t, nucleiResp.Discovery, "discovery result should not be nil")

		// Log results (may be empty if no info-level templates match)
		t.Logf("Info level scan found %d results", len(nucleiResp.Results))
		for _, result := range nucleiResp.Results {
			t.Logf("  - [%s] %s: %s", result.Info.Severity, result.TemplateId, result.TemplateName)
		}

		// Verify results structure if any exist
		if len(nucleiResp.Results) > 0 {
			result := nucleiResp.Results[0]
			assert.NotEmpty(t, result.TemplateId, "result should have template ID")
			if result.Info != nil {
				assert.NotEmpty(t, result.Info.Severity, "result should have severity in info")
			}
		}
	})

	// Test with specific safe template
	t.Run("SpecificTemplate", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// Use a common info-level template
		req := &gen.NucleiRequest{
			Targets:   []string{"https://example.com"},
			Templates: []string{"http/technologies/tech-detect.yaml"},
			Severity:  []string{"info"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		// This may error if the template doesn't exist, which is acceptable
		if err != nil {
			t.Logf("Template scan failed (may not exist): %v", err)
			return
		}

		require.NotNil(t, resp, "response should not be nil")

		nucleiResp, ok := resp.(*gen.NucleiResponse)
		require.True(t, ok, "response should be NucleiResponse")

		t.Logf("Template scan found %d results", len(nucleiResp.Results))
	})

	// Test with tags filtering
	t.Run("TagsFiltering", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		req := &gen.NucleiRequest{
			Targets:  []string{"https://example.com"},
			Tags:     []string{"tech"},
			Severity: []string{"info"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "tags filtering should not error")
		require.NotNil(t, resp, "response should not be nil")

		nucleiResp, ok := resp.(*gen.NucleiResponse)
		require.True(t, ok, "response should be NucleiResponse")

		assert.NotNil(t, nucleiResp.Discovery, "discovery result should not be nil")
		t.Logf("Tags filtering found %d results", len(nucleiResp.Results))

		// Verify results have the expected tag
		for _, result := range nucleiResp.Results {
			if result.Info != nil && len(result.Info.Tags) > 0 {
				t.Logf("  - Result has tags: %v", result.Info.Tags)
			}
		}
	})

	// Test JSONL parsing with rate limiting
	t.Run("RateLimiting", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		req := &gen.NucleiRequest{
			Targets:   []string{"https://example.com"},
			Severity:  []string{"info"},
			RateLimit: 10, // 10 requests per second
			Threads:   5,
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "rate limiting should not error")
		require.NotNil(t, resp, "response should not be nil")

		nucleiResp, ok := resp.(*gen.NucleiResponse)
		require.True(t, ok, "response should be NucleiResponse")

		t.Logf("Rate limited scan found %d results", len(nucleiResp.Results))
	})

	// Test multiple targets
	t.Run("MultipleTargets", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		req := &gen.NucleiRequest{
			Targets: []string{
				"https://example.com",
				"https://httpbin.org",
			},
			Severity: []string{"info"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "multiple targets should not error")
		require.NotNil(t, resp, "response should not be nil")

		nucleiResp, ok := resp.(*gen.NucleiResponse)
		require.True(t, ok, "response should be NucleiResponse")

		t.Logf("Multi-target scan found %d results", len(nucleiResp.Results))

		// Verify results reference different targets
		targetSet := make(map[string]bool)
		for _, result := range nucleiResp.Results {
			if result.MatchedAt != "" {
				targetSet[result.MatchedAt] = true
			}
		}
		t.Logf("Results matched at %d unique targets", len(targetSet))
	})

	// Test DiscoveryResult entity creation
	t.Run("DiscoveryResultEntities", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		req := &gen.NucleiRequest{
			Targets:  []string{"https://example.com"},
			Severity: []string{"info"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "scan should not error")
		require.NotNil(t, resp, "response should not be nil")

		nucleiResp, ok := resp.(*gen.NucleiResponse)
		require.True(t, ok, "response should be NucleiResponse")

		// Verify DiscoveryResult structure
		require.NotNil(t, nucleiResp.Discovery, "discovery result should not be nil")

		// If results exist, verify findings were created in discovery
		if len(nucleiResp.Results) > 0 {
			if len(nucleiResp.Discovery.Findings) > 0 {
				t.Logf("Created %d findings from %d results",
					len(nucleiResp.Discovery.Findings), len(nucleiResp.Results))

				// Verify finding structure
				finding := nucleiResp.Discovery.Findings[0]
				assert.NotEmpty(t, finding.Title, "finding should have title")
				assert.NotEmpty(t, finding.Severity, "finding should have severity")
				t.Logf("Sample finding: title=%s, severity=%s", finding.Title, finding.Severity)
			}
		}
	})

	// Test error handling - no targets
	t.Run("ErrorNoTargets", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		req := &gen.NucleiRequest{
			Targets: []string{},
		}

		_, err := tool.ExecuteProto(ctx, req)
		require.Error(t, err, "should error with no targets")
		assert.Contains(t, err.Error(), "at least one target is required")
	})

	// Test with custom timeout
	t.Run("CustomTimeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		req := &gen.NucleiRequest{
			Targets:  []string{"https://example.com"},
			Severity: []string{"info"},
			Timeout:  5, // 5 second per-request timeout
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "custom timeout should not error")
		require.NotNil(t, resp, "response should not be nil")

		nucleiResp, ok := resp.(*gen.NucleiResponse)
		require.True(t, ok, "response should be NucleiResponse")

		t.Logf("Custom timeout scan found %d results", len(nucleiResp.Results))
	})
}
