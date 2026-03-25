package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

// CCVersionTraits holds all captured request headers from a real Claude Code invocation.
// The Headers map is the source of truth for mimic mode — any new headers Anthropic adds
// are automatically captured and replayed.
type CCVersionTraits struct {
	CCVersion  string            `json:"cc_version"` // e.g., "2.1.81"
	Headers    map[string]string `json:"headers"`    // ALL captured request headers
	CapturedAt time.Time         `json:"captured_at"`
}

// CCProbeService probes a locally installed Claude Code binary to capture
// version-dependent request headers via mitmproxy.
type CCProbeService struct {
	cfg             *config.CCProbeConfig
	cache           CCProbeCache
	mu              sync.RWMutex
	latestTraits    *CCVersionTraits
	fallbackFile    string // path to persist last-known-good traits
	stopCh          chan struct{}
	wg              sync.WaitGroup
	probeInProgress atomic.Bool // prevents overlapping probes
}

// CCProbeConfigPublic is a JSON-safe view of the cc_probe config section.
// It is read-only — changes require restarting the service.
type CCProbeConfigPublic struct {
	Enabled            bool   `json:"enabled"`
	CCBinaryPath       string `json:"cc_binary_path"`
	AutoUpdateCC       bool   `json:"auto_update_cc"`
	UpdateCommand      string `json:"update_command"`
	ProbeModel         string `json:"probe_model"`
	CheckIntervalHours int    `json:"check_interval_hours"`
}

// PublicConfig returns a JSON-safe view of the current cc_probe configuration.
func (s *CCProbeService) PublicConfig() CCProbeConfigPublic {
	if s.cfg == nil {
		return CCProbeConfigPublic{}
	}
	interval := s.cfg.CheckIntervalHours
	if interval == 0 {
		interval = 1
	}
	probeModel := s.cfg.ProbeModel
	if probeModel == "" {
		probeModel = "claude-haiku-4-5"
	}
	return CCProbeConfigPublic{
		Enabled:            s.cfg.Enabled,
		CCBinaryPath:       s.cfg.CCBinaryPath,
		AutoUpdateCC:       s.cfg.AutoUpdateCC,
		UpdateCommand:      s.updateCommand(),
		ProbeModel:         probeModel,
		CheckIntervalHours: interval,
	}
}

// CCProbeCache defines the cache interface for CC probe traits.
type CCProbeCache interface {
	GetCCTraits(ctx context.Context) (*CCVersionTraits, error)
	SetCCTraits(ctx context.Context, traits *CCVersionTraits) error
}

// NewCCProbeService creates a new CCProbeService.
func NewCCProbeService(cfg *config.CCProbeConfig, cache CCProbeCache) *CCProbeService {
	fallbackDir := os.Getenv("SUB2API_DATA_DIR")
	if fallbackDir == "" {
		fallbackDir = "/tmp"
	}
	svc := &CCProbeService{
		cfg:          cfg,
		cache:        cache,
		fallbackFile: filepath.Join(fallbackDir, "cc_probe_traits.json"),
	}

	return svc
}

// Start loads cached traits on startup (Redis → file fallback → defaults).
func (s *CCProbeService) Start() {
	if s.cfg == nil || !s.cfg.Enabled {
		slog.Debug("cc_probe.disabled")
		return
	}

	s.mu.Lock()
	if s.stopCh != nil {
		s.mu.Unlock()
		return
	}
	stopCh := make(chan struct{})
	s.stopCh = stopCh
	s.wg.Add(1)
	s.mu.Unlock()

	if s.cache != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if traits, err := s.cache.GetCCTraits(ctx); err == nil && traits != nil {
			s.mu.Lock()
			s.latestTraits = traits
			s.mu.Unlock()
			slog.Info("cc_probe.loaded_from_cache", "cc_version", traits.CCVersion, "header_count", len(traits.Headers))
		} else if err != nil {
			slog.Warn("cc_probe.cache_load_error", "error", err)
		}
	}

	if s.latestTraits == nil {
		if traits, err := s.loadFromFile(); err == nil && traits != nil {
			s.mu.Lock()
			s.latestTraits = traits
			s.mu.Unlock()
			slog.Info("cc_probe.loaded_from_file", "cc_version", traits.CCVersion, "header_count", len(traits.Headers))
		} else {
			slog.Info("cc_probe.no_cached_traits", "fallback", "DefaultHeaders")
		}
	}

	// Startup probe if no cached traits
	if s.latestTraits == nil {
		select {
		case <-stopCh:
		default:
			go s.probeWithRecover("startup")
		}
	}

	// Periodic version check
	go s.versionCheckLoop()
}

// Stop gracefully shuts down the version check loop.
func (s *CCProbeService) Stop() {
	s.mu.Lock()
	stopCh := s.stopCh
	if stopCh == nil {
		s.mu.Unlock()
		return
	}
	s.stopCh = nil
	s.mu.Unlock()

	slog.Info("cc_probe.stopping")
	close(stopCh)
	s.wg.Wait()
	slog.Info("cc_probe.stopped")
}

func (s *CCProbeService) versionCheckLoop() {
	defer s.wg.Done()

	s.mu.RLock()
	stopCh := s.stopCh
	s.mu.RUnlock()
	if stopCh == nil {
		return
	}

	interval := time.Duration(s.cfg.CheckIntervalHours) * time.Hour
	if interval == 0 {
		interval = 1 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			s.checkAndProbeIfNeeded()
		}
	}
}

func (s *CCProbeService) checkAndProbeIfNeeded() {
	// Update CC first so getInstalledCCVersion() sees the new version.
	// On the deploy machine CC auto-update is disabled; sub2api drives updates.
	if s.cfg.AutoUpdateCC {
		s.runUpdate()
	}

	installedVersion := s.getInstalledCCVersion()
	if installedVersion == "" {
		return
	}

	s.mu.RLock()
	cachedVersion := ""
	if s.latestTraits != nil {
		cachedVersion = s.latestTraits.CCVersion
	}
	s.mu.RUnlock()

	if installedVersion == cachedVersion {
		return
	}

	slog.Info("cc_probe.version_changed",
		"installed", installedVersion,
		"cached", cachedVersion)
	s.probeWithRecover("version_changed")
}

func (s *CCProbeService) getInstalledCCVersion() string {
	ccBinary := s.cfg.CCBinaryPath
	if ccBinary == "" {
		ccBinary = "claude"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ccBinary, "--version").Output()
	if err != nil {
		slog.Debug("cc_probe.version_check_failed", "error", err)
		return ""
	}
	version := strings.TrimSpace(string(out))
	if idx := strings.IndexByte(version, ' '); idx >= 0 {
		version = version[:idx]
	}
	return version
}

// updateCommand returns the configured update command, or derives a default
// from the CC binary path to avoid shell PATH lookup issues.
func (s *CCProbeService) updateCommand() string {
	if s.cfg.UpdateCommand != "" {
		return s.cfg.UpdateCommand
	}
	ccBinary := s.cfg.CCBinaryPath
	if ccBinary == "" {
		ccBinary = "claude"
	}
	return ccBinary + " update"
}

// runUpdate executes the configured update command (e.g. "claude update").
// It is a no-op when CC is already on the latest version.
func (s *CCProbeService) runUpdate() {
	updateCmd := s.updateCommand()
	slog.Info("cc_probe.running_update", "command", updateCmd)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", updateCmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Error("cc_probe.update_failed", "error", err, "output", string(out))
	}
}

func (s *CCProbeService) probeWithRecover(reason string) {
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Error("cc_probe.probe_panic", "reason", reason, "panic", recovered)
		}
	}()

	if s.cfg.AutoUpdateCC {
		slog.Info("cc_probe.auto_update", "reason", reason)
		s.runUpdate()
	}

	probeCtx, probeCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer probeCancel()
	if err := s.ProbeInstalledCC(probeCtx); err != nil {
		slog.Error("cc_probe.probe_failed", "reason", reason, "error", err)
	}
}

// TriggerProbe initiates an async probe for the given reason.
// It is safe to call from multiple goroutines concurrently; overlapping probes
// are silently dropped so only one probe runs at a time.
func (s *CCProbeService) TriggerProbe(reason string) {
	if !s.probeInProgress.CompareAndSwap(false, true) {
		slog.Info("cc_probe.trigger_skipped", "reason", reason, "cause", "probe_in_progress")
		return
	}
	go func() {
		defer s.probeInProgress.Store(false)
		s.probeWithRecover(reason)
	}()
}

// GetLatestTraits returns the most recent captured traits.
// Returns nil if no traits have been captured yet (cold start without cache).
func (s *CCProbeService) GetLatestTraits() *CCVersionTraits {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latestTraits
}

// ProbeInstalledCC executes a mitmproxy-based capture of the locally installed Claude Code.
// It starts mitmdump, runs CC with a minimal prompt, and parses the captured headers.
func (s *CCProbeService) ProbeInstalledCC(ctx context.Context) error {
	if s.cfg == nil || !s.cfg.Enabled {
		return fmt.Errorf("cc_probe: disabled")
	}

	ccBinary := s.cfg.CCBinaryPath
	if ccBinary == "" {
		ccBinary = "claude"
	}

	// Verify claude binary exists
	if _, err := exec.LookPath(ccBinary); err != nil {
		return fmt.Errorf("cc_probe: claude binary not found at %q: %w", ccBinary, err)
	}

	// Verify mitmdump exists
	if _, err := exec.LookPath("mitmdump"); err != nil {
		return fmt.Errorf("cc_probe: mitmdump not found: %w", err)
	}

	// Create temp dir for capture artifacts
	tmpDir, err := os.MkdirTemp("", "cc_probe_*")
	if err != nil {
		return fmt.Errorf("cc_probe: failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	captureScript := filepath.Join(tmpDir, "capture.py")
	capturedFile := filepath.Join(tmpDir, "captured.json")

	// Write capture script
	scriptContent := fmt.Sprintf(`from mitmproxy import http
import json

def request(flow: http.HTTPFlow):
    if "messages" in flow.request.path:
        data = {"headers": dict(flow.request.headers)}
        with open(%q, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
`, capturedFile)
	if err := os.WriteFile(captureScript, []byte(scriptContent), 0644); err != nil {
		return fmt.Errorf("cc_probe: failed to write capture script: %w", err)
	}

	// Start mitmdump
	probeCtx, probeCancel := context.WithTimeout(ctx, 120*time.Second)
	defer probeCancel()

	mitmPort := "8999"
	mitmCmd := exec.CommandContext(probeCtx, "mitmdump",
		"-p", mitmPort,
		"--set", "block_global=false",
		"-s", captureScript,
		"--quiet",
	)
	mitmCmd.Stdout = os.Stderr
	mitmCmd.Stderr = os.Stderr

	if err := mitmCmd.Start(); err != nil {
		return fmt.Errorf("cc_probe: failed to start mitmdump: %w", err)
	}
	defer func() {
		_ = mitmCmd.Process.Kill()
		_ = mitmCmd.Wait()
	}()

	// Wait for mitmdump to be ready (TCP readiness poll)
	if err := waitForTCPReady(probeCtx, "127.0.0.1:"+mitmPort, 100*time.Millisecond, 10*time.Second); err != nil {
		return fmt.Errorf("cc_probe: mitmdump not ready: %w", err)
	}
	slog.Debug("cc_probe.mitmdump_ready")

	// Run Claude Code with proxy
	probeModel := s.cfg.ProbeModel
	if probeModel == "" {
		probeModel = "claude-haiku-4-5"
	}

	claudeCmd := exec.CommandContext(probeCtx, ccBinary,
		"-p", "hi",
		"--output-format", "json",
		"--model", probeModel,
	)
	claudeCmd.Env = append(os.Environ(),
		fmt.Sprintf("HTTPS_PROXY=http://127.0.0.1:%s", mitmPort),
		"NODE_TLS_REJECT_UNAUTHORIZED=0",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
	)
	claudeCmd.Stdout = os.Stderr
	claudeCmd.Stderr = os.Stderr

	if err := claudeCmd.Run(); err != nil {
		slog.Warn("cc_probe.claude_run_error", "error", err)
		// Don't return error — captured.json may still exist from the request
	}

	// Parse captured headers
	data, err := os.ReadFile(capturedFile)
	if err != nil {
		return fmt.Errorf("cc_probe: no captured data (capture file not created): %w", err)
	}

	var captured struct {
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(data, &captured); err != nil {
		return fmt.Errorf("cc_probe: failed to parse captured data: %w", err)
	}

	if len(captured.Headers) == 0 {
		return fmt.Errorf("cc_probe: captured headers are empty")
	}

	// Normalize header keys to lowercase for consistent lookup.
	// mitmproxy preserves the original HTTP header casing (title-case for HTTP/1.1).
	normalized := make(map[string]string, len(captured.Headers))
	for k, v := range captured.Headers {
		normalized[strings.ToLower(k)] = v
	}

	// Extract CC version from User-Agent
	ccVersion := extractCCVersionFromUA(normalized["user-agent"])

	traits := &CCVersionTraits{
		CCVersion:  ccVersion,
		Headers:    normalized,
		CapturedAt: time.Now(),
	}

	// Store in memory, Redis, and file
	s.mu.Lock()
	s.latestTraits = traits
	s.mu.Unlock()

	storeCtx, storeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer storeCancel()

	if err := s.cache.SetCCTraits(storeCtx, traits); err != nil {
		slog.Warn("cc_probe.cache_store_error", "error", err)
	}

	if err := s.saveToFile(traits); err != nil {
		slog.Warn("cc_probe.file_save_error", "error", err)
	}

	slog.Info("cc_probe.captured",
		"cc_version", traits.CCVersion,
		"header_count", len(traits.Headers),
		"user_agent", captured.Headers["user-agent"],
	)

	return nil
}

// extractCCVersionFromUA extracts the CC version from a User-Agent string.
// e.g., "claude-cli/2.1.81 (external, cli)" → "2.1.81"
func extractCCVersionFromUA(ua string) string {
	if ua == "" {
		return ""
	}
	parts := strings.SplitN(ua, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	version := parts[1]
	if idx := strings.IndexByte(version, ' '); idx >= 0 {
		version = version[:idx]
	}
	return version
}

// loadFromFile reads last-known-good traits from the fallback file.
func (s *CCProbeService) loadFromFile() (*CCVersionTraits, error) {
	data, err := os.ReadFile(s.fallbackFile)
	if err != nil {
		return nil, err
	}
	var traits CCVersionTraits
	if err := json.Unmarshal(data, &traits); err != nil {
		return nil, err
	}
	if len(traits.Headers) == 0 {
		return nil, fmt.Errorf("empty traits in file")
	}
	return &traits, nil
}

// saveToFile persists traits to the fallback file.
func (s *CCProbeService) saveToFile(traits *CCVersionTraits) error {
	data, err := json.MarshalIndent(traits, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.fallbackFile, data, 0644)
}

// ApplyMimicHeadersFromProbe applies captured CC headers to a request,
// overriding only the version-dependent headers (User-Agent, X-Stainless-Package-Version).
// Platform-identity headers (OS, Arch, Runtime, RuntimeVersion, Lang) are NOT overridden here
// because they come from the TLS profile identity instead.
func (s *CCProbeService) ApplyVersionHeaders(req *http.Request) {
	s.mu.RLock()
	traits := s.latestTraits
	s.mu.RUnlock()

	if traits == nil || len(traits.Headers) == 0 {
		slog.Debug("cc_probe.apply_headers_skipped", "reason", "no_traits")
		return
	}

	// Only apply version-dependent headers from probe
	versionHeaders := []string{
		"user-agent",
		"x-stainless-package-version",
	}
	for _, key := range versionHeaders {
		if v, ok := traits.Headers[key]; ok && v != "" {
			req.Header.Set(key, v)
		}
	}
}

// waitForTCPReady polls until a TCP connection to addr succeeds or timeout expires.
func waitForTCPReady(ctx context.Context, addr string, interval, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for %s after %s", addr, timeout)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, interval)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(interval)
	}
}

// ProbeVersionOverrides returns the probe-captured User-Agent and X-Stainless-Package-Version.
// Returns empty strings when no probe traits are available.
func (s *CCProbeService) ProbeVersionOverrides() (userAgent, packageVersion string) {
	s.mu.RLock()
	traits := s.latestTraits
	s.mu.RUnlock()

	if traits == nil || len(traits.Headers) == 0 {
		slog.Debug("cc_probe.version_overrides_empty")
		return "", ""
	}

	return traits.Headers["user-agent"], traits.Headers["x-stainless-package-version"]
}
