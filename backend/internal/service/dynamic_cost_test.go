package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================================
// Phase 1: Account accessors
// ============================================================

func TestIsDynamicCostEnabled(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string]any
		want  bool
	}{
		{"nil extra", nil, false},
		{"missing key", map[string]any{}, false},
		{"false", map[string]any{"dynamic_cost_enabled": false}, false},
		{"true", map[string]any{"dynamic_cost_enabled": true}, true},
		{"non-bool", map[string]any{"dynamic_cost_enabled": "true"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Account{Extra: tc.extra}
			require.Equal(t, tc.want, a.IsDynamicCostEnabled())
		})
	}
}

func TestGetWindowCost7dLimit(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string]any
		want  float64
	}{
		{"nil extra", nil, 0},
		{"missing key", map[string]any{}, 0},
		{"set", map[string]any{"window_cost_7d_limit": 200.0}, 200.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Account{Extra: tc.extra}
			require.Equal(t, tc.want, a.GetWindowCost7dLimit())
		})
	}
}

func TestGet7dWindowStartTime(t *testing.T) {
	t.Run("missing key", func(t *testing.T) {
		a := &Account{Extra: map[string]any{}}
		_, ok := a.Get7dWindowStartTime()
		require.False(t, ok)
	})
	t.Run("valid timestamp", func(t *testing.T) {
		resetTs := float64(time.Now().Add(7 * 24 * time.Hour).Unix())
		a := &Account{Extra: map[string]any{"passive_usage_7d_reset": resetTs}}
		start, ok := a.Get7dWindowStartTime()
		require.True(t, ok)
		// start should be ~now (resetTs - 7d)
		require.WithinDuration(t, time.Now(), start, 5*time.Second)
	})
	t.Run("nil extra", func(t *testing.T) {
		a := &Account{}
		_, ok := a.Get7dWindowStartTime()
		require.False(t, ok)
	})
}

func TestHasWindowCostControl(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string]any
		want  bool
	}{
		{"no control", map[string]any{}, false},
		{"manual 5h only", map[string]any{"window_cost_limit": 50.0}, true},
		{"dynamic only", map[string]any{"dynamic_cost_enabled": true}, true},
		{"7d only", map[string]any{"window_cost_7d_limit": 200.0}, true},
		{"all three", map[string]any{"window_cost_limit": 50.0, "dynamic_cost_enabled": true, "window_cost_7d_limit": 200.0}, true},
		{"nil extra", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Account{Extra: tc.extra}
			require.Equal(t, tc.want, a.HasWindowCostControl())
		})
	}
}

func TestGetCappedStickyReserve(t *testing.T) {
	tests := []struct {
		name    string
		limit   float64
		reserve float64
		wantCap float64
	}{
		{"reserve under cap", 100.0, 10.0, 10.0},
		{"reserve at cap", 100.0, 20.0, 20.0},
		{"reserve over cap", 100.0, 30.0, 20.0},
		{"zero limit", 0.0, 10.0, 0.0},
		{"small limit", 5.0, 10.0, 1.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GetCappedStickyReserve(tc.limit, tc.reserve)
			require.InDelta(t, tc.wantCap, got, 0.001)
		})
	}
}

// ============================================================
// Phase 4: GetEffectiveWindowCostLimit
// ============================================================

func TestGetEffectiveWindowCostLimit(t *testing.T) {
	cache := &sessionLimitCacheHotpathStub{}
	svc := &GatewayService{sessionLimitCache: cache}

	tests := []struct {
		name       string
		extra      map[string]any
		costInCtx  float64
		windowType WindowType
		want       float64
	}{
		{
			name:       "not dynamic, manual limit",
			extra:      map[string]any{"window_cost_limit": 50.0},
			windowType: Window5h,
			want:       50.0,
		},
		{
			name:       "dynamic, high utilization, derives from cost/util",
			extra:      map[string]any{"dynamic_cost_enabled": true, "session_window_utilization": 0.50, "window_cost_limit": 50.0},
			costInCtx:  25.0,
			windowType: Window5h,
			want:       50.0, // 25 / 0.5 = 50
		},
		{
			name:       "dynamic, low utilization (1-4%), capped by fallback",
			extra:      map[string]any{"dynamic_cost_enabled": true, "session_window_utilization": 0.02, "window_cost_limit": 50.0},
			costInCtx:  1.0,
			windowType: Window5h,
			want:       50.0, // min(1/0.02=50, fallback=50) = 50
		},
		{
			name:       "dynamic, very low utilization (<1%), uses fallback",
			extra:      map[string]any{"dynamic_cost_enabled": true, "session_window_utilization": 0.005, "window_cost_limit": 50.0},
			costInCtx:  0.25,
			windowType: Window5h,
			want:       50.0, // fallback
		},
		{
			name:       "dynamic, zero utilization, derived stored limit exists",
			extra:      map[string]any{"dynamic_cost_enabled": true, "derived_5h_limit": 48.0, "session_window_utilization": 0.0},
			costInCtx:  0.0,
			windowType: Window5h,
			want:       48.0, // derived limit as fallback
		},
		{
			name:       "dynamic, zero utilization, no fallback (fail-open)",
			extra:      map[string]any{"dynamic_cost_enabled": true, "session_window_utilization": 0.0},
			costInCtx:  0.0,
			windowType: Window5h,
			want:       0.0, // fail-open
		},
		{
			name:       "7d window, manual limit only",
			extra:      map[string]any{"window_cost_7d_limit": 200.0},
			windowType: Window7d,
			want:       200.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			account := &Account{
				ID:       1,
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    tc.extra,
			}
			// Always provide prefetch context to avoid nil usageLogRepo dereference
			ctx := context.WithValue(context.Background(), windowCostPrefetchContextKey, map[int64]*windowCostSnapshot{
				1: {Cost5h: tc.costInCtx},
			})
			got := svc.GetEffectiveWindowCostLimit(ctx, account, tc.windowType)
			require.InDelta(t, tc.want, got, 0.01)
		})
	}
}

// ============================================================
// Phase 4: checkWindowZone
// ============================================================

func TestCheckWindowZone(t *testing.T) {
	cache := &sessionLimitCacheHotpathStub{}
	svc := &GatewayService{sessionLimitCache: cache}

	tests := []struct {
		name       string
		extra      map[string]any
		cost       float64
		windowType WindowType
		want       WindowCostSchedulability
	}{
		{
			name:       "green zone",
			extra:      map[string]any{"window_cost_limit": 50.0},
			cost:       30.0,
			windowType: Window5h,
			want:       WindowCostSchedulable,
		},
		{
			name:       "yellow zone (sticky only)",
			extra:      map[string]any{"window_cost_limit": 50.0},
			cost:       55.0,
			windowType: Window5h,
			want:       WindowCostStickyOnly,
		},
		{
			name:       "red zone",
			extra:      map[string]any{"window_cost_limit": 50.0},
			cost:       65.0,
			windowType: Window5h,
			want:       WindowCostNotSchedulable,
		},
		{
			name:       "no limit (fail-open)",
			extra:      map[string]any{},
			cost:       100.0,
			windowType: Window5h,
			want:       WindowCostSchedulable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			account := &Account{
				ID:       1,
				Platform: PlatformAnthropic,
				Type:     AccountTypeOAuth,
				Extra:    tc.extra,
			}
			ctx := context.WithValue(context.Background(), windowCostPrefetchContextKey, map[int64]*windowCostSnapshot{
				1: {Cost5h: tc.cost},
			})
			got := svc.checkWindowZone(ctx, account, tc.windowType)
			require.Equal(t, tc.want, got)
		})
	}
}

// ============================================================
// Manual-limit regression: unchanged when dynamic_cost_enabled is false
// ============================================================

func TestManualLimitAccountsUnchanged(t *testing.T) {
	cache := &sessionLimitCacheHotpathStub{}
	svc := &GatewayService{sessionLimitCache: cache}

	account := &Account{
		ID:       1,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{"window_cost_limit": 50.0},
	}

	// Even with high cost, GetEffectiveWindowCostLimit should return manual limit
	ctx := context.WithValue(context.Background(), windowCostPrefetchContextKey, map[int64]*windowCostSnapshot{
		1: {Cost5h: 40.0},
	})
	limit := svc.GetEffectiveWindowCostLimit(ctx, account, Window5h)
	require.Equal(t, 50.0, limit)

	// Dynamic-only accessors should return defaults
	require.False(t, account.IsDynamicCostEnabled())
	require.Equal(t, 0.0, account.GetDerived5hLimit())
	require.Equal(t, 0.0, account.GetDerived7dLimit())
}
