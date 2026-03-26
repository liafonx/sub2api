package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultPromptArchiveURL  = "https://raw.githubusercontent.com/Piebald-AI/tweakcc/main/data/prompts/prompts-%s.json"
	maxPromptArchiveVersions = 5
	snapshotStaleThreshold   = 7 * 24 * time.Hour
)

// CCTraitRegistryCache is the Redis persistence layer for the trait registry.
type CCTraitRegistryCache interface {
	GetSnapshot(ctx context.Context) (*CCTraitSnapshot, error)
	SetSnapshot(ctx context.Context, snapshot *CCTraitSnapshot) error
}

// CCTraitSnapshot is immutable after creation. New snapshots are always built
// as new structs and swapped atomically via mu. Never mutate after publishing.
type CCTraitSnapshot struct {
	Version              string          `json:"version"`
	ExpectedHeaderKeys   []string        `json:"expected_header_keys"`
	BetaFlags            []string        `json:"beta_flags"`
	BetaFlagSet          map[string]bool `json:"-"` // pre-computed set from BetaFlags; not persisted
	XAppValue            string          `json:"x_app_value"`
	SystemPromptPrefixes []string        `json:"system_prompt_prefixes"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

// IsStale returns true if the snapshot is older than 7 days.
func (s *CCTraitSnapshot) IsStale() bool {
	return time.Since(s.UpdatedAt) > snapshotStaleThreshold
}

var sensitiveHeaderSet = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"x-api-key":           true,
	"proxy-authorization": true,
}

// CCTraitRegistry is the single source of truth for expected CC client traits.
// It persists to Redis (primary) and a local file (fallback), updating atomically.
type CCTraitRegistry struct {
	cache        CCTraitRegistryCache
	mu           sync.RWMutex
	wg           sync.WaitGroup
	snapshot     *CCTraitSnapshot
	fallbackFile string
	archiveDir   string
}

// NewCCTraitRegistry creates a new CCTraitRegistry with Redis cache.
func NewCCTraitRegistry(cache CCTraitRegistryCache) *CCTraitRegistry {
	dataDir := os.Getenv("SUB2API_DATA_DIR")
	if dataDir == "" {
		dataDir = "/tmp"
	}
	return &CCTraitRegistry{
		cache:        cache,
		fallbackFile: filepath.Join(dataDir, "cc_trait_snapshot.json"),
		archiveDir:   filepath.Join(dataDir, "prompt_archives"),
	}
}

// Start loads the snapshot synchronously: Redis → file → nil. No background goroutine.
func (r *CCTraitRegistry) Start() {
	if r.cache != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if snap, err := r.cache.GetSnapshot(ctx); err == nil && snap != nil {
			snap.BetaFlagSet = buildBetaFlagSet(snap.BetaFlags)
			r.mu.Lock()
			r.snapshot = snap
			r.mu.Unlock()
			slog.Info("cc_trait_registry.loaded_from_redis",
				"version", snap.Version,
				"updated_at", snap.UpdatedAt)
			return
		} else if err != nil {
			slog.Warn("cc_trait_registry.redis_load_error", "error", err)
		}
	}

	if snap, err := r.loadFromFile(); err == nil && snap != nil {
		snap.BetaFlagSet = buildBetaFlagSet(snap.BetaFlags)
		r.mu.Lock()
		r.snapshot = snap
		r.mu.Unlock()
		slog.Info("cc_trait_registry.loaded_from_file",
			"version", snap.Version,
			"updated_at", snap.UpdatedAt)
		return
	}

	slog.Info("cc_trait_registry.no_snapshot", "fallback", "hardcoded_defaults")
}

// Stop waits for any in-flight background goroutines to finish.
func (r *CCTraitRegistry) Stop() {
	r.wg.Wait()
}

// GetSnapshot returns a pointer to the current immutable snapshot, or nil if none.
// Callers may read the returned struct concurrently without locking.
func (r *CCTraitRegistry) GetSnapshot() *CCTraitSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot
}

// UpdateFromProbe builds a new snapshot from probe output, persists it, and swaps atomically.
// Sensitive header keys (authorization, cookie, x-api-key, proxy-authorization) are filtered out.
// A background goroutine is spawned to enrich with tweakcc archive (non-fatal).
func (r *CCTraitRegistry) UpdateFromProbe(traits *CCVersionTraits, bodyTraits *CapturedBodyTraits) {
	if traits == nil {
		return
	}

	// Extract and filter header keys (lowercase, no values stored)
	headerKeys := make([]string, 0, len(traits.Headers))
	for k := range traits.Headers {
		lower := strings.ToLower(k)
		if !sensitiveHeaderSet[lower] {
			headerKeys = append(headerKeys, lower)
		}
	}
	sort.Strings(headerKeys)

	// Parse beta flags from anthropic-beta header
	var betaFlags []string
	if betaVal := traits.Headers["anthropic-beta"]; betaVal != "" {
		for _, f := range strings.Split(betaVal, ",") {
			if f = strings.TrimSpace(f); f != "" {
				betaFlags = append(betaFlags, f)
			}
		}
	}

	// Build system prompt prefixes: probe body → hardcoded fallback, deduped
	prompts := make([]string, 0)
	if bodyTraits != nil {
		prompts = append(prompts, bodyTraits.SystemPromptPrefixes...)
	}
	prompts = deduplicateStrings(append(prompts, claudeCodeSystemPrompts...))

	snap := &CCTraitSnapshot{
		Version:              traits.CCVersion,
		ExpectedHeaderKeys:   headerKeys,
		BetaFlags:            betaFlags,
		BetaFlagSet:          buildBetaFlagSet(betaFlags),
		XAppValue:            traits.Headers["x-app"],
		SystemPromptPrefixes: prompts,
		UpdatedAt:            time.Now(),
	}

	r.mu.Lock()
	r.snapshot = snap
	r.mu.Unlock()

	r.persist(snap)

	slog.Info("cc_trait_registry.updated",
		"version", snap.Version,
		"header_keys", len(snap.ExpectedHeaderKeys),
		"beta_flags", len(snap.BetaFlags),
		"prompt_prefixes", len(snap.SystemPromptPrefixes),
	)

	// Enrich from tweakcc archive asynchronously (non-fatal)
	if traits.CCVersion != "" {
		version := traits.CCVersion
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.fetchAndEnrichFromArchive(version)
		}()
	}
}

// EnrichFromPromptArchive merges additional prompt prefixes into the current snapshot.
// Always builds a NEW snapshot — never mutates the existing one.
func (r *CCTraitRegistry) EnrichFromPromptArchive(prompts []string) {
	if len(prompts) == 0 {
		return
	}

	r.mu.RLock()
	current := r.snapshot
	r.mu.RUnlock()

	if current == nil {
		return
	}

	merged := deduplicateStrings(append(current.SystemPromptPrefixes, prompts...))
	if len(merged) == len(current.SystemPromptPrefixes) {
		return // no new prefixes
	}

	snap := &CCTraitSnapshot{
		Version:              current.Version,
		ExpectedHeaderKeys:   current.ExpectedHeaderKeys,
		BetaFlags:            current.BetaFlags,
		BetaFlagSet:          current.BetaFlagSet,
		XAppValue:            current.XAppValue,
		SystemPromptPrefixes: merged,
		UpdatedAt:            current.UpdatedAt,
	}

	r.mu.Lock()
	r.snapshot = snap
	r.mu.Unlock()

	r.persist(snap)

	slog.Info("cc_trait_registry.enriched",
		"version", snap.Version,
		"total_prefixes", len(snap.SystemPromptPrefixes),
		"added", len(merged)-len(current.SystemPromptPrefixes),
	)
}

// persist saves the snapshot to Redis and the fallback file (both non-fatal on error).
func (r *CCTraitRegistry) persist(snap *CCTraitSnapshot) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if r.cache != nil {
		if err := r.cache.SetSnapshot(ctx, snap); err != nil {
			slog.Warn("cc_trait_registry.redis_save_error", "error", err)
		}
	}

	if err := r.saveToFile(snap); err != nil {
		slog.Warn("cc_trait_registry.file_save_error", "error", err)
	}
}

// fetchAndEnrichFromArchive downloads and parses the tweakcc prompt archive for a CC version.
// Non-fatal: logs warning on failure.
func (r *CCTraitRegistry) fetchAndEnrichFromArchive(version string) {
	prompts, err := r.downloadPromptArchive(version)
	if err != nil {
		slog.Warn("cc_trait_registry.archive_download_failed", "version", version, "error", err)
		return
	}
	if len(prompts) > 0 {
		r.EnrichFromPromptArchive(prompts)
	}
	r.rotateArchiveVersions()
}

// downloadPromptArchive fetches, saves, and parses the tweakcc archive for a CC version.
func (r *CCTraitRegistry) downloadPromptArchive(version string) ([]string, error) {
	url := fmt.Sprintf(defaultPromptArchiveURL, version)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("archive not found for version %s (404)", version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d for version %s", resp.StatusCode, version)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Persist archive file for version rotation
	if mkErr := os.MkdirAll(r.archiveDir, 0755); mkErr != nil {
		slog.Warn("cc_trait_registry.archive_mkdir_failed", "error", mkErr)
	} else {
		archivePath := filepath.Join(r.archiveDir, fmt.Sprintf("prompts-%s.json", version))
		if writeErr := os.WriteFile(archivePath, body, 0644); writeErr != nil {
			slog.Warn("cc_trait_registry.archive_write_failed", "error", writeErr)
		}
	}

	// Parse tweakcc format: array of prompt objects, each with a "pieces" string array
	var items []struct {
		Pieces []string `json:"pieces"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	var prompts []string
	for _, item := range items {
		if len(item.Pieces) == 0 {
			continue
		}
		if prefix := extractIdentityPrefix(item.Pieces[0]); prefix != "" {
			prompts = append(prompts, prefix)
		}
	}
	return prompts, nil
}

// extractIdentityPrefix returns the first 200 chars of text if it starts with
// an identity-defining pattern. Returns "" otherwise.
func extractIdentityPrefix(text string) string {
	if text == "" {
		return ""
	}
	for _, pfx := range []string{"You are", "Your task", "You will"} {
		if strings.HasPrefix(text, pfx) {
			if len(text) > 200 {
				return text[:200]
			}
			return text
		}
	}
	return ""
}

// rotateArchiveVersions deletes oldest archive files when count exceeds maxPromptArchiveVersions.
func (r *CCTraitRegistry) rotateArchiveVersions() {
	entries, err := os.ReadDir(r.archiveDir)
	if err != nil {
		return
	}

	type vf struct {
		path    string
		version string
	}
	var files []vf
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "prompts-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		ver := strings.TrimSuffix(strings.TrimPrefix(name, "prompts-"), ".json")
		files = append(files, vf{path: filepath.Join(r.archiveDir, name), version: ver})
	}

	if len(files) <= maxPromptArchiveVersions {
		return
	}

	// Sort newest first by semver
	sort.Slice(files, func(i, j int) bool {
		return CompareVersions(files[i].version, files[j].version) > 0
	})

	for _, f := range files[maxPromptArchiveVersions:] {
		if err := os.Remove(f.path); err != nil {
			slog.Warn("cc_trait_registry.archive_rotate_remove_failed", "path", f.path, "error", err)
		}
	}
}

func (r *CCTraitRegistry) loadFromFile() (*CCTraitSnapshot, error) {
	data, err := os.ReadFile(r.fallbackFile)
	if err != nil {
		return nil, err
	}
	var snap CCTraitSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &snap, nil
}

func (r *CCTraitRegistry) saveToFile(snap *CCTraitSnapshot) error {
	dir := filepath.Dir(r.fallbackFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.fallbackFile, data, 0600)
}

// buildBetaFlagSet converts a beta flags slice into a lookup set.
// Returns nil when flags is empty so callers can use len(set) > 0 guards.
func buildBetaFlagSet(flags []string) map[string]bool {
	if len(flags) == 0 {
		return nil
	}
	set := make(map[string]bool, len(flags))
	for _, f := range flags {
		set[f] = true
	}
	return set
}

// deduplicateStrings returns a new slice with duplicates removed, preserving order.
func deduplicateStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
