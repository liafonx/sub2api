// Package tlsfingerprint provides TLS fingerprint simulation for HTTP clients.
package tlsfingerprint

import (
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

// DefaultProfileName is the name of the built-in Claude CLI profile.
const DefaultProfileName = "claude_cli_v2"

// ProfileAuto is the sentinel value meaning "select profile automatically via round-robin".
const ProfileAuto = "auto"

// Registry manages TLS fingerprint profiles.
// It holds a collection of profiles that can be used for TLS fingerprint simulation.
// Profiles are selected based on account ID using modulo operation.
type Registry struct {
	mu           sync.RWMutex
	profiles     map[string]*Profile
	profileNames []string // Sorted list of profile names for deterministic selection
}

// NewRegistry creates a new TLS fingerprint profile registry.
// It initializes with the built-in default profile.
func NewRegistry() *Registry {
	r := &Registry{
		profiles:     make(map[string]*Profile),
		profileNames: make([]string, 0),
	}

	// Register the built-in default profile
	r.registerBuiltinProfile()

	return r
}

// NewRegistryFromConfig creates a new registry and loads profiles from config.
// If the config has custom profiles defined, they will be merged with the built-in default.
func NewRegistryFromConfig(cfg *config.TLSFingerprintConfig) *Registry {
	r := NewRegistry()

	if cfg == nil || !cfg.Enabled {
		slog.Debug("tls_registry_disabled", "reason", "disabled or no config")
		return r
	}

	// Load custom profiles from config
	for name, profileCfg := range cfg.Profiles {
		profile := &Profile{
			Name:         profileCfg.Name,
			EnableGREASE: profileCfg.EnableGREASE,
			CipherSuites: profileCfg.CipherSuites,
			Curves:       profileCfg.Curves,
			PointFormats: profileCfg.PointFormats,
		}

		// If the profile has empty values, they will use defaults in dialer
		r.RegisterProfile(name, profile)
		slog.Debug("tls_registry_loaded_profile", "key", name, "name", profileCfg.Name)
	}

	slog.Debug("tls_registry_initialized", "profile_count", len(r.profileNames), "profiles", r.profileNames)
	return r
}

// registerBuiltinProfile adds the default Claude CLI profile to the registry.
func (r *Registry) registerBuiltinProfile() {
	defaultProfile := &Profile{
		Name:         "Claude CLI 2.x (Node.js 20.x + OpenSSL 3.x)",
		EnableGREASE: false, // Node.js does not use GREASE
		// Empty slices will cause dialer to use built-in defaults
		CipherSuites: nil,
		Curves:       nil,
		PointFormats: nil,
	}
	r.RegisterProfile(DefaultProfileName, defaultProfile)
}

// RegisterProfile adds or updates a profile in the registry.
func (r *Registry) RegisterProfile(name string, profile *Profile) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if this is a new profile
	_, exists := r.profiles[name]
	r.profiles[name] = profile

	if !exists {
		r.profileNames = append(r.profileNames, name)
		// Keep names sorted for deterministic selection
		sort.Strings(r.profileNames)
	}
}

// GetProfile returns a profile by name.
// Returns nil if the profile does not exist.
func (r *Registry) GetProfile(name string) *Profile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.profiles[name]
}

// GetDefaultProfile returns the built-in default profile.
func (r *Registry) GetDefaultProfile() *Profile {
	return r.GetProfile(DefaultProfileName)
}

// GetProfileByAccountID returns a profile for the given account ID.
// Delegates to GetProfileForAccount with no preferred profile (round-robin).
func (r *Registry) GetProfileByAccountID(accountID int64) *Profile {
	_, p := r.GetProfileForAccount(accountID, "")
	return p
}

// GetProfileForAccount returns the resolved registry key and profile for the given account.
// If preferredProfile is non-empty and not "auto", that key is used if found.
// Otherwise falls back to round-robin selection by accountID.
// Returning the registry key (not Profile.Name) ensures cache key uniqueness.
func (r *Registry) GetProfileForAccount(accountID int64, preferredProfile string) (string, *Profile) {
	if preferredProfile != "" && preferredProfile != ProfileAuto {
		if p := r.GetProfile(preferredProfile); p != nil {
			return preferredProfile, p
		}
		slog.Warn("tls_fingerprint_profile_not_found",
			"account_id", accountID,
			"requested_profile", preferredProfile,
			"fallback", "auto_round_robin",
		)
	}

	// Resolve by accountID and return the registry key alongside the profile.
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.profileNames) == 0 {
		return "", nil
	}
	idx := accountID
	if idx < 0 {
		idx = -idx
	}
	selectedIndex := int(idx % int64(len(r.profileNames)))
	selectedName := r.profileNames[selectedIndex]
	return selectedName, r.profiles[selectedName]
}

// ProfileCount returns the number of registered profiles.
func (r *Registry) ProfileCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.profiles)
}

// ProfileNames returns a sorted list of all registered profile names.
func (r *Registry) ProfileNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to prevent modification
	names := make([]string, len(r.profileNames))
	copy(names, r.profileNames)
	return names
}

// Global registry instance for convenience
var globalRegistry *Registry
var globalRegistryOnce sync.Once

// GlobalRegistry returns the global TLS fingerprint registry.
// The registry is lazily initialized with the default profile.
func GlobalRegistry() *Registry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewRegistry()
	})
	return globalRegistry
}

// InitGlobalRegistry initializes the global registry with configuration.
// This should be called during application startup.
// It is safe to call multiple times; subsequent calls will update the registry.
func InitGlobalRegistry(cfg *config.TLSFingerprintConfig) *Registry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewRegistryFromConfig(cfg)
	})
	return globalRegistry
}

// ProfileIdentity holds platform identity fields extracted from a TLS profile key.
// These fields map directly to X-Stainless-* request headers used by the Anthropic SDK.
type ProfileIdentity struct {
	OS             string // SDK-normalized: "MacOS", "Linux", "Windows"
	Arch           string // "arm64", "x64"
	Runtime        string // "node"
	RuntimeVersion string // "v24.3.0"
	Lang           string // "js"
}

// legacyProfileIdentities maps non-convention profile keys to known identities.
// This keeps backwards compatibility with accounts using "claude_cli_v2".
var legacyProfileIdentities = map[string]ProfileIdentity{
	"claude_cli_v2": {
		OS:             "MacOS",
		Arch:           "arm64",
		Runtime:        "node",
		RuntimeVersion: "v24.3.0",
		Lang:           "js",
	},
}

// ParseProfileIdentity extracts platform identity from a profile key.
// Key format: {platform}_{arch}_{runtime}_v{major}_{minor}_{patch}
// e.g., "darwin_arm64_node_v24_3_0" → OS=MacOS, Arch=arm64, Runtime=node, RuntimeVersion=v24.3.0, Lang=js
// Falls back to legacyProfileIdentities for non-convention keys like "claude_cli_v2".
func ParseProfileIdentity(profileKey string) (ProfileIdentity, bool) {
	if identity, ok := legacyProfileIdentities[profileKey]; ok {
		return identity, true
	}

	parts := strings.Split(profileKey, "_")
	if len(parts) < 3 {
		return ProfileIdentity{}, false
	}

	// Validate runtime field exists at parts[2] and is a known runtime
	runtime := parts[2]
	if runtime != "node" && runtime != "bun" && runtime != "deno" {
		return ProfileIdentity{}, false
	}

	identity := ProfileIdentity{
		OS:      normalizePlatformName(parts[0]),
		Arch:    parts[1],
		Runtime: runtime,
		Lang:    "js",
	}

	// Extract version: v{major}_{minor}_{patch} → v{major}.{minor}.{patch}
	if len(parts) >= 6 && strings.HasPrefix(parts[3], "v") {
		identity.RuntimeVersion = parts[3] + "." + parts[4] + "." + parts[5]
	}

	return identity, true
}

// normalizePlatformName converts raw platform names to SDK-normalized values.
// Matches Anthropic SDK detect-platform.ts:169-191.
func normalizePlatformName(platform string) string {
	switch strings.ToLower(platform) {
	case "darwin":
		return "MacOS"
	case "linux":
		return "Linux"
	case "win32", "windows":
		return "Windows"
	case "freebsd":
		return "FreeBSD"
	default:
		return "Other:" + platform
	}
}

// profileIdentityCache caches ParseProfileIdentity results keyed by profile key.
// Only ~1-3 distinct keys exist at runtime, so unbounded growth is not a concern.
var profileIdentityCache sync.Map

// CachedParseProfileIdentity returns a cached result of ParseProfileIdentity for the given key.
func CachedParseProfileIdentity(profileKey string) (ProfileIdentity, bool) {
	if v, ok := profileIdentityCache.Load(profileKey); ok {
		entry := v.(profileIdentityCacheEntry)
		return entry.identity, entry.ok
	}
	identity, ok := ParseProfileIdentity(profileKey)
	profileIdentityCache.Store(profileKey, profileIdentityCacheEntry{identity: identity, ok: ok})
	return identity, ok
}

type profileIdentityCacheEntry struct {
	identity ProfileIdentity
	ok       bool
}
