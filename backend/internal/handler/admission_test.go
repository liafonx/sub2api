package handler

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocalOverloadTracker_NotOverloadedByDefault(t *testing.T) {
	tracker := NewLocalOverloadTracker()
	require.False(t, tracker.IsOverloaded(1))
	require.False(t, tracker.IsOverloaded(999))
}

func TestLocalOverloadTracker_MarkAndCheck(t *testing.T) {
	tracker := NewLocalOverloadTracker()

	tracker.MarkOverloaded(1, 100*time.Millisecond)
	require.True(t, tracker.IsOverloaded(1))
	require.False(t, tracker.IsOverloaded(2))

	time.Sleep(150 * time.Millisecond)
	require.False(t, tracker.IsOverloaded(1))
}

func TestLocalOverloadTracker_NeverShortensDeadline(t *testing.T) {
	tracker := NewLocalOverloadTracker()

	tracker.MarkOverloaded(1, 200*time.Millisecond)
	tracker.MarkOverloaded(1, 50*time.Millisecond) // shorter — should be ignored
	require.True(t, tracker.IsOverloaded(1))

	time.Sleep(100 * time.Millisecond)
	require.True(t, tracker.IsOverloaded(1)) // still within original 200ms
}

func TestLocalOverloadTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewLocalOverloadTracker()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			tracker.MarkOverloaded(id%5, 50*time.Millisecond)
			tracker.IsOverloaded(id % 5)
		}(int64(i))
	}
	wg.Wait()
}

func TestLocalOverloadTracker_IndependentAccounts(t *testing.T) {
	tracker := NewLocalOverloadTracker()

	tracker.MarkOverloaded(1, 100*time.Millisecond)
	tracker.MarkOverloaded(2, 100*time.Millisecond)

	require.True(t, tracker.IsOverloaded(1))
	require.True(t, tracker.IsOverloaded(2))
	require.False(t, tracker.IsOverloaded(3))
}
