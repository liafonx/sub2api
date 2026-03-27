package tlsfingerprint

import (
	"strings"
	"sync"
)

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

	if len(parts) >= 6 && strings.HasPrefix(parts[3], "v") {
		identity.RuntimeVersion = parts[3] + "." + parts[4] + "." + parts[5]
	}

	return identity, true
}

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
