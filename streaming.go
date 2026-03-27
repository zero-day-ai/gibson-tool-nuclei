package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/gibson-tool-nuclei/gen"
	"google.golang.org/protobuf/proto"
)

// Ensure ToolImpl implements StreamingTool
var _ tool.StreamingTool = (*ToolImpl)(nil)

// StreamExecuteProto implements streaming nuclei execution with real-time progress updates
// and graceful cancellation support.
func (t *ToolImpl) StreamExecuteProto(ctx context.Context, input proto.Message, stream tool.ToolStream) error {
	startTime := time.Now()

	// Type assert and validate input
	req, ok := input.(*gen.NucleiRequest)
	if !ok {
		return stream.Error(fmt.Errorf("invalid input type: expected *gen.NucleiRequest, got %T", input), true)
	}

	// Validate required fields
	if len(req.Targets) == 0 {
		return stream.Error(fmt.Errorf("at least one target is required"), true)
	}

	// Emit initial progress
	if err := stream.Progress(0, "init", "Starting nuclei vulnerability scan"); err != nil {
		return fmt.Errorf("failed to emit initial progress: %w", err)
	}

	// Build command arguments
	args := buildArgs(req)

	// Create command with context
	cmd := exec.CommandContext(ctx, BinaryName, args...)

	// Setup stdin pipe for targets
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return stream.Error(fmt.Errorf("failed to create stdin pipe: %w", err), true)
	}

	// Setup stdout and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return stream.Error(fmt.Errorf("failed to create stdout pipe: %w", err), true)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return stream.Error(fmt.Errorf("failed to create stderr pipe: %w", err), true)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return stream.Error(fmt.Errorf("failed to start nuclei: %w", err), true)
	}

	// Write targets to stdin in goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdin.Close()

		for _, target := range req.Targets {
			if _, err := fmt.Fprintln(stdin, target); err != nil {
				stream.Warning(fmt.Sprintf("failed to write target to stdin: %v", err), "stdin_write")
				return
			}
		}
	}()

	// Buffer for collecting stdout (JSONL vulnerability matches)
	var stdoutBuf bytes.Buffer
	var stdoutMu sync.Mutex

	// Track progress
	totalTargets := len(req.Targets)
	var matchCount int
	var progressMu sync.Mutex
	lastProgressUpdate := time.Now()

	// Read and parse stdout line by line for vulnerability matches
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)

		for scanner.Scan() {
			line := scanner.Bytes()

			// Store the line for final parsing
			stdoutMu.Lock()
			stdoutBuf.Write(line)
			stdoutBuf.WriteByte('\n')
			stdoutMu.Unlock()

			// Count JSON lines as vulnerability matches (skip empty lines)
			if len(line) > 0 {
				progressMu.Lock()
				matchCount++
				currentMatches := matchCount
				progressMu.Unlock()

				// Send progress update every 5 matches or every 3 seconds
				now := time.Now()
				if currentMatches%5 == 0 || now.Sub(lastProgressUpdate) >= 3*time.Second {
					lastProgressUpdate = now

					// Calculate approximate percentage (harder to estimate for nuclei)
					// Use a heuristic: assume we're progressing through templates
					pct := 50 // Default to 50% while scanning
					if currentMatches > totalTargets*10 {
						pct = 75 // High match count = deep into scanning
					}

					// Build progress message
					msg := fmt.Sprintf("Found %d vulnerabilities so far...", currentMatches)

					// Emit progress update (ignore errors to not interrupt scanning)
					stream.Progress(pct, "scanning", msg)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			stream.Warning(fmt.Sprintf("error reading stdout: %v", err), "stdout_scan")
		}
	}()

	// Read stderr for info messages in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		var stderrLines []string

		for scanner.Scan() {
			line := scanner.Text()
			stderrLines = append(stderrLines, line)

			// nuclei outputs info messages to stderr like "[INF] Using 100 templates"
			// Extract useful information for progress updates
			if strings.Contains(line, "[INF]") {
				// Send informational messages as progress updates
				if strings.Contains(line, "Using") && strings.Contains(line, "template") {
					stream.Progress(10, "loading", strings.TrimPrefix(line, "[INF] "))
				}
			}

			// Log significant errors as warnings
			lowerLine := strings.ToLower(line)
			if strings.Contains(lowerLine, "[err]") || strings.Contains(lowerLine, "error") || strings.Contains(lowerLine, "failed") {
				stream.Warning(line, "nuclei_error")
			}
		}

		if err := scanner.Err(); err != nil {
			stream.Warning(fmt.Sprintf("error reading stderr: %v", err), "stderr_scan")
		}

		// If we got stderr output and no stdout progress, warn the user
		if len(stderrLines) > 0 {
			progressMu.Lock()
			matches := matchCount
			progressMu.Unlock()

			if matches == 0 {
				// Filter out non-error lines
				var errorLines []string
				for _, line := range stderrLines {
					if strings.Contains(line, "[ERR]") || strings.Contains(strings.ToLower(line), "error") {
						errorLines = append(errorLines, line)
					}
				}
				if len(errorLines) > 0 {
					stream.Warning(fmt.Sprintf("nuclei stderr: %s", strings.Join(errorLines, "; ")), "nuclei_stderr")
				}
			}
		}
	}()

	// Handle cancellation in goroutine
	cancelDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(cancelDone)

		select {
		case <-stream.Cancelled():
			// User requested cancellation
			stream.Warning("Scan cancellation requested", "cancellation")

			// Kill the process (nuclei can take time to shutdown gracefully)
			if cmd.Process != nil {
				if err := cmd.Process.Kill(); err != nil {
					stream.Warning(fmt.Sprintf("failed to kill process: %v", err), "cancellation")
				}
			}

		case <-ctx.Done():
			// Context cancelled (timeout or parent cancellation)
			stream.Warning(fmt.Sprintf("Context cancelled: %v", ctx.Err()), "context_cancel")

			// Kill the process
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		}
	}()

	// Wait for command to complete
	cmdErr := cmd.Wait()

	// Wait for all goroutines to finish
	wg.Wait()

	// Get the collected output
	stdoutMu.Lock()
	jsonlOutput := stdoutBuf.Bytes()
	stdoutMu.Unlock()

	// Emit parsing progress
	if err := stream.Progress(90, "parsing", "Parsing nuclei output"); err != nil {
		// Continue even if progress emission fails
	}

	// Parse output even if command errored (might have partial results)
	discoveryResult, matches, parseErr := parseOutput(jsonlOutput)

	// Handle different error scenarios
	if parseErr != nil {
		if cmdErr != nil {
			// Both command and parsing failed
			select {
			case <-stream.Cancelled():
				// Cancellation was requested - this is expected
				return stream.Error(fmt.Errorf("scan cancelled: %v", cmdErr), true)
			default:
				// Unexpected failure
				return stream.Error(fmt.Errorf("command failed: %v, parse failed: %v", cmdErr, parseErr), true)
			}
		}
		// Command succeeded but parsing failed (unusual)
		return stream.Error(fmt.Errorf("failed to parse nuclei output: %w", parseErr), true)
	}

	// If command errored but we got partial results, emit warning
	if cmdErr != nil {
		select {
		case <-stream.Cancelled():
			stream.Warning("Scan cancelled, returning partial results", "cancellation")
		default:
			stream.Warning(fmt.Sprintf("Command exited with error: %v, but partial results available", cmdErr), "command_error")
		}
	}

	// Build response
	scanDuration := time.Since(startTime).Seconds()
	response := convertToProtoResponse(discoveryResult, matches, scanDuration)

	// Emit final progress
	finalMsg := fmt.Sprintf("Scan finished: %d vulnerabilities found across %d targets",
		response.TotalMatches, totalTargets)

	if err := stream.Progress(100, "complete", finalMsg); err != nil {
		// Continue even if progress emission fails
	}

	// Complete the stream with final result
	return stream.Complete(response)
}
