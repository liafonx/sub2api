package service

import (
	"context"
	"time"
)

// UserAffinityCache manages per-user daily account affinity in Redis.
// Affinity binds a user to a specific account for the current day (until the configured reset hour).
// This is Anthropic-only and guarded by group.UserAccountAffinityEnabled.
type UserAffinityCache interface {
	// GetAffinity returns the account ID the user is affinitied to, or 0 if none.
	GetAffinity(ctx context.Context, groupID, userID int64) (int64, error)
	// SetAffinity binds user to account with TTL until next reset hour.
	SetAffinity(ctx context.Context, groupID, userID, accountID int64, ttl time.Duration) error
	// DeleteAffinity removes a user's affinity (when account hits Red zone or is unschedulable).
	DeleteAffinity(ctx context.Context, groupID, userID int64) error
	// GetAffinityUserCounts returns the number of users affinitied to each account in the group.
	GetAffinityUserCounts(ctx context.Context, groupID int64, accountIDs []int64) (map[int64]int64, error)
	// IncrAffinityCount increments the affinitied-user count for an account.
	IncrAffinityCount(ctx context.Context, groupID, accountID int64, ttl time.Duration) error
	// DecrAffinityCount decrements the affinitied-user count for an account (floor 0).
	DecrAffinityCount(ctx context.Context, groupID, accountID int64) error
}

// TimeUntilNextResetHour returns the duration from now until the next occurrence of
// resetHour:00:00 UTC. If now is exactly at resetHour:00:00, returns 24h.
func TimeUntilNextResetHour(now time.Time, resetHour int) time.Duration {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), resetHour, 0, 0, 0, time.UTC)
	if !now.Before(next) {
		// Already past today's reset hour — advance to tomorrow.
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}
