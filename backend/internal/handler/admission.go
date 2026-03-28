package handler

import (
	"sync"
	"sync/atomic"
	"time"
)

// LocalOverloadTracker provides instant in-process overload detection across
// concurrent goroutines. When any request receives a 529 from an account,
// the tracker immediately marks it overloaded so other in-flight goroutines
// skip it without sending another request upstream.
//
// This complements the Redis-based overload marking in ratelimit_service.go,
// which has propagation delay across concurrent requests.
type LocalOverloadTracker struct {
	// map[int64]*atomic.Int64 — accountID → overloadUntilUnixMs
	entries sync.Map
}

// NewLocalOverloadTracker creates a new tracker instance.
func NewLocalOverloadTracker() *LocalOverloadTracker {
	return &LocalOverloadTracker{}
}

// MarkOverloaded marks an account as overloaded for the given duration.
func (t *LocalOverloadTracker) MarkOverloaded(accountID int64, cooldown time.Duration) {
	untilMs := time.Now().Add(cooldown).UnixMilli()
	entry := t.getOrCreate(accountID)
	// Only advance the deadline, never shorten it
	for {
		current := entry.Load()
		if untilMs <= current {
			return
		}
		if entry.CompareAndSwap(current, untilMs) {
			return
		}
	}
}

// IsOverloaded returns true if the account is currently locally overloaded.
func (t *LocalOverloadTracker) IsOverloaded(accountID int64) bool {
	val, ok := t.entries.Load(accountID)
	if !ok {
		return false
	}
	entry := val.(*atomic.Int64)
	return time.Now().UnixMilli() < entry.Load()
}

func (t *LocalOverloadTracker) getOrCreate(accountID int64) *atomic.Int64 {
	val, ok := t.entries.Load(accountID)
	if ok {
		return val.(*atomic.Int64)
	}
	entry := &atomic.Int64{}
	actual, _ := t.entries.LoadOrStore(accountID, entry)
	return actual.(*atomic.Int64)
}
