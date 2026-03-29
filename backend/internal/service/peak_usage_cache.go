package service

import (
	"context"
	"time"
)

// Entity type constants for peak usage tracking.
const (
	EntityTypeAccount = "account"
	EntityTypeUser    = "user"
)

// Peak field name constants — used by UpdatePeakIfGreater callers.
const (
	PeakFieldConcurrency = "concurrency"
	PeakFieldSessions    = "sessions"
	PeakFieldRPM         = "rpm"
)

// PeakUsageCache tracks all-time peak resource usage for accounts and users.
// Redis data structure: Hash per entity
// Keys: peak:account:{id}, peak:user:{id}
// Fields: concurrency, sessions, rpm, reset_at
type PeakUsageCache interface {
	// UpdatePeakIfGreater atomically updates a peak field if newValue > current stored value.
	// entityType: "account" or "user"
	// field: "concurrency", "sessions", or "rpm"
	UpdatePeakIfGreater(ctx context.Context, entityType string, entityID int64, field string, newValue int) error

	// GetAllPeaks returns peak values for multiple entities of the same type.
	// Returns map[entityID]*PeakValues. Missing entities have nil value.
	GetAllPeaks(ctx context.Context, entityType string, entityIDs []int64) (map[int64]*PeakValues, error)

	// ResetPeaks zeroes all peak fields for the given entities and sets reset_at to now.
	ResetPeaks(ctx context.Context, entityType string, entityIDs []int64) error
}

// PeakValues holds peak metric values for one entity.
type PeakValues struct {
	Concurrency int       `json:"concurrency"`
	Sessions    int       `json:"sessions"`
	RPM         int       `json:"rpm"`
	ResetAt     time.Time `json:"reset_at"`
}

// updatePeakIfGreaterAsync fires a goroutine to atomically update a peak field
// if count exceeds the current stored value. Best-effort, non-blocking.
func updatePeakIfGreaterAsync(cache PeakUsageCache, entityType string, entityID int64, field string, count int) {
	if cache == nil || count <= 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = cache.UpdatePeakIfGreater(ctx, entityType, entityID, field, count)
	}()
}
