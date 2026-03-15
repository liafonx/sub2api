//go:build unit

package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestScheduledRateConfig_AuthCacheRoundTrip verifies that a ScheduledRateConfig
// with multiple rules survives the full auth cache round-trip:
//
//	snapshotFromAPIKey → JSON marshal → JSON unmarshal → snapshotToAPIKey
//
// All rule fields (Days, TimeStart, TimeEnd, TimeMode, DateStart, DateEnd,
// RateMultiplier) and the top-level Enabled flag must be preserved exactly.
func TestScheduledRateConfig_AuthCacheRoundTrip(t *testing.T) {
	svc := &APIKeyService{}

	cfg := &ScheduledRateConfig{
		Enabled: true,
		Rules: []ScheduledRateRule{
			{
				RateMultiplier: 2.5,
				TimeStart:      "10:00",
				TimeEnd:        "18:00",
				TimeMode:       "include",
				Days:           []int{1, 2, 3, 4, 5},
				DateStart:      "2026-03-01",
				DateEnd:        "2026-03-31",
			},
			{
				RateMultiplier: 0.5,
				TimeStart:      "22:00",
				TimeEnd:        "06:00",
				TimeMode:       "exclude",
				Days:           []int{0, 6},
			},
			{
				RateMultiplier: 1.0,
				// no time/day/date restrictions — matches everything
			},
		},
	}

	groupID := int64(42)
	original := &APIKey{
		ID:      1,
		UserID:  2,
		GroupID: &groupID,
		Status:  StatusActive,
		User: &User{
			ID:          2,
			Status:      StatusActive,
			Role:        RoleUser,
			Balance:     100,
			Concurrency: 5,
		},
		Group: &Group{
			ID:                  groupID,
			Name:                "test-group",
			Platform:            PlatformAnthropic,
			Status:              StatusActive,
			SubscriptionType:    SubscriptionTypeStandard,
			RateMultiplier:      1.0,
			ScheduledRateConfig: cfg,
		},
	}

	// Step 1: snapshot from APIKey.
	snapshot := svc.snapshotFromAPIKey(original)
	require.NotNil(t, snapshot)
	require.NotNil(t, snapshot.Group)
	require.NotNil(t, snapshot.Group.ScheduledRateConfig)

	// Step 2: serialize snapshot to JSON (simulates L2 cache write).
	b, err := json.Marshal(snapshot)
	require.NoError(t, err)

	// Step 3: deserialize JSON into a fresh snapshot (simulates L2 cache read).
	var snapshot2 APIKeyAuthSnapshot
	require.NoError(t, json.Unmarshal(b, &snapshot2))

	// Step 4: reconstruct APIKey from deserialized snapshot.
	reconstructed := svc.snapshotToAPIKey("test-key", &snapshot2)
	require.NotNil(t, reconstructed)
	require.NotNil(t, reconstructed.Group)

	got := reconstructed.Group.ScheduledRateConfig
	require.NotNil(t, got)

	// Top-level flag.
	require.Equal(t, cfg.Enabled, got.Enabled)

	// Rule count.
	require.Len(t, got.Rules, len(cfg.Rules))

	// Rule 0: full fields.
	r0 := got.Rules[0]
	require.Equal(t, 2.5, r0.RateMultiplier)
	require.Equal(t, "10:00", r0.TimeStart)
	require.Equal(t, "18:00", r0.TimeEnd)
	require.Equal(t, "include", r0.TimeMode)
	require.Equal(t, []int{1, 2, 3, 4, 5}, r0.Days)
	require.Equal(t, "2026-03-01", r0.DateStart)
	require.Equal(t, "2026-03-31", r0.DateEnd)

	// Rule 1: overnight + exclude mode + weekend days, no date range.
	r1 := got.Rules[1]
	require.Equal(t, 0.5, r1.RateMultiplier)
	require.Equal(t, "22:00", r1.TimeStart)
	require.Equal(t, "06:00", r1.TimeEnd)
	require.Equal(t, "exclude", r1.TimeMode)
	require.Equal(t, []int{0, 6}, r1.Days)
	require.Empty(t, r1.DateStart)
	require.Empty(t, r1.DateEnd)

	// Rule 2: catch-all, all zero-value optional fields.
	r2 := got.Rules[2]
	require.Equal(t, 1.0, r2.RateMultiplier)
	require.Empty(t, r2.TimeStart)
	require.Empty(t, r2.TimeEnd)
	require.Empty(t, r2.TimeMode)
	require.Empty(t, r2.Days)
	require.Empty(t, r2.DateStart)
	require.Empty(t, r2.DateEnd)
}

// TestScheduledRateConfig_AuthCacheRoundTrip_NilConfig verifies that a nil
// ScheduledRateConfig round-trips as nil (no phantom config injected).
func TestScheduledRateConfig_AuthCacheRoundTrip_NilConfig(t *testing.T) {
	svc := &APIKeyService{}

	groupID := int64(7)
	original := &APIKey{
		ID:      3,
		UserID:  4,
		GroupID: &groupID,
		Status:  StatusActive,
		User: &User{
			ID:          4,
			Status:      StatusActive,
			Role:        RoleUser,
			Balance:     50,
			Concurrency: 1,
		},
		Group: &Group{
			ID:                  groupID,
			Name:                "no-schedule",
			Platform:            PlatformAnthropic,
			Status:              StatusActive,
			SubscriptionType:    SubscriptionTypeStandard,
			RateMultiplier:      1.0,
			ScheduledRateConfig: nil,
		},
	}

	snapshot := svc.snapshotFromAPIKey(original)
	require.NotNil(t, snapshot)
	require.NotNil(t, snapshot.Group)
	require.Nil(t, snapshot.Group.ScheduledRateConfig)

	b, err := json.Marshal(snapshot)
	require.NoError(t, err)

	var snapshot2 APIKeyAuthSnapshot
	require.NoError(t, json.Unmarshal(b, &snapshot2))

	reconstructed := svc.snapshotToAPIKey("test-key", &snapshot2)
	require.NotNil(t, reconstructed)
	require.NotNil(t, reconstructed.Group)
	require.Nil(t, reconstructed.Group.ScheduledRateConfig)
}
