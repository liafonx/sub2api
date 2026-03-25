package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
)

// ClaudeCodeVersionDetectService 定期从 npm 检测最新 Claude Code 稳定版本号，
// 当 auto_detect_min_claude_code_version 设置为 true 时，自动更新最低版本号要求。
type ClaudeCodeVersionDetectService struct {
	settingService *SettingService
	httpClient     *http.Client
	stopCh         chan struct{}
	stopOnce       sync.Once
	triggerCh      chan struct{} // 收到信号时立即检测并重置计时器
	wg             sync.WaitGroup
	registryURL    string
	detectInterval time.Duration
	onNewVersion   func() // called when a new npm version is detected and stored
}

// NewClaudeCodeVersionDetectService 创建检测服务实例
// proxyURL 为空时直连 npm，支持 http/https/socks5/socks5h 协议
func NewClaudeCodeVersionDetectService(settingService *SettingService, proxyURL string, allowDirectOnProxyError bool, registryURL string, intervalHours int) *ClaudeCodeVersionDetectService {
	client, err := httpclient.GetClient(httpclient.Options{
		Timeout:  30 * time.Second,
		ProxyURL: proxyURL,
	})
	if err != nil {
		if strings.TrimSpace(proxyURL) != "" && !allowDirectOnProxyError {
			slog.Warn("claude_code_version_detect.proxy_init_failed", "error", err)
			client = nil // will prevent fetches — fail closed for proxy-only environments
		} else {
			slog.Warn("claude_code_version_detect.proxy_init_failed", "error", fmt.Errorf("falling back to direct: %w", err))
			client = &http.Client{Timeout: 30 * time.Second}
		}
	}
	if intervalHours < 1 {
		intervalHours = 1
	}
	return &ClaudeCodeVersionDetectService{
		settingService: settingService,
		httpClient:     client,
		stopCh:         make(chan struct{}),
		triggerCh:      make(chan struct{}, 1), // buffered: one pending trigger at a time
		registryURL:    registryURL,
		detectInterval: time.Duration(intervalHours) * time.Hour,
	}
}

// Start 启动检测服务，在后台 goroutine 中异步执行检测循环。
func (s *ClaudeCodeVersionDetectService) Start() {
	s.wg.Add(1)
	go s.loop()

	slog.Info("claude_code_version_detect.started", "interval", s.detectInterval.String())
}

// Stop 停止检测服务，等待后台 goroutine 退出
func (s *ClaudeCodeVersionDetectService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
	slog.Info("claude_code_version_detect.stopped")
}

// SetOnNewVersionCallback registers a callback invoked after a new npm version
// is successfully stored. Must be called before Start() to avoid missing the
// first detection.
func (s *ClaudeCodeVersionDetectService) SetOnNewVersionCallback(cb func()) {
	s.onNewVersion = cb
}

// Trigger 立即触发一次版本检测并重置计时器（间隔由配置决定）。
// 用于管理员在设置页面开启自动检测时立刻生效。
// 非阻塞：若上一次触发尚未处理，本次触发被忽略。
func (s *ClaudeCodeVersionDetectService) Trigger() {
	select {
	case s.triggerCh <- struct{}{}:
	default: // already a pending trigger, skip
	}
}

func (s *ClaudeCodeVersionDetectService) loop() {
	defer s.wg.Done()

	s.detectAndUpdate() // initial detection before entering the ticker loop

	ticker := time.NewTicker(s.detectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.detectAndUpdate()
		case <-s.triggerCh:
			// Reset timer so next auto-tick is from now
			ticker.Reset(s.detectInterval)
			s.detectAndUpdate()
		case <-s.stopCh:
			return
		}
	}
}

// npmPackageInfo is a minimal struct for parsing the npm registry response.
type npmPackageInfo struct {
	Version string `json:"version"`
}

// detectAndUpdate 执行一次检测，如果启用了自动检测且版本有变化则更新数据库。
func (s *ClaudeCodeVersionDetectService) detectAndUpdate() {
	if s.httpClient == nil {
		slog.Warn("claude_code_version_detect.fetch_network_error", "error", "http client not initialized (proxy error at startup)")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	settings, err := s.settingService.GetAllSettings(ctx)
	if err != nil {
		slog.Warn("claude_code_version_detect.fetch_network_error", "error", fmt.Errorf("failed to read settings: %w", err))
		return
	}

	if !settings.AutoDetectMinClaudeCodeVersion {
		slog.Debug("claude_code_version_detect.skip_disabled")
		return
	}

	newVersion, err := s.fetchStableVersion(ctx)
	if err != nil {
		return // error already logged inside fetchStableVersion
	}

	currentVersion := settings.MinClaudeCodeVersion
	if currentVersion == newVersion {
		slog.Debug("claude_code_version_detect.version_unchanged", "version", newVersion)
		return
	}

	if err := s.settingService.UpdateMinClaudeCodeVersionFromDetect(ctx, newVersion); err != nil {
		slog.Error("claude_code_version_detect.db_update_failed", "version", newVersion, "error", err)
		return
	}

	slog.Info("claude_code_version_detect.version_updated", "old_version", currentVersion, "new_version", newVersion)

	if s.onNewVersion != nil {
		slog.Info("claude_code_version_detect.triggering_probe")
		s.onNewVersion()
	}
}

// fetchStableVersion 从 npm 注册表获取稳定版本号
func (s *ClaudeCodeVersionDetectService) fetchStableVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.registryURL, nil)
	if err != nil {
		slog.Warn("claude_code_version_detect.fetch_network_error", "error", err)
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		slog.Warn("claude_code_version_detect.fetch_network_error", "error", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("claude_code_version_detect.fetch_failed", "status_code", resp.StatusCode)
		return "", fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		slog.Warn("claude_code_version_detect.invalid_response", "error", err)
		return "", err
	}

	var info npmPackageInfo
	if err := json.Unmarshal(body, &info); err != nil {
		slog.Warn("claude_code_version_detect.invalid_response", "error", err)
		return "", err
	}

	version := strings.TrimSpace(info.Version)
	if !SemverPattern.MatchString(version) {
		slog.Warn("claude_code_version_detect.invalid_semver", "raw_version", version)
		return "", fmt.Errorf("invalid semver from npm: %q", version)
	}

	return version, nil
}
