//go:build unit

package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mon is Monday 2026-03-16 00:00:00 UTC — a known Monday.
var mon = time.Date(2026, time.March, 16, 0, 0, 0, 0, time.UTC)

// dateOf returns a UTC time at HH:MM on the given date (year, month, day).
func dateOf(year int, month time.Month, day, hour, minute int) time.Time {
	return time.Date(year, month, day, hour, minute, 0, 0, time.UTC)
}

// atTime returns Monday 2026-03-16 at HH:MM UTC.
func atTime(hour, minute int) time.Time {
	return time.Date(2026, time.March, 16, hour, minute, 0, 0, time.UTC)
}

// groupWith returns a Group with RateMultiplier=1.0 and the given ScheduledRateConfig.
func groupWith(cfg *ScheduledRateConfig) *Group {
	return &Group{RateMultiplier: 1.0, ScheduledRateConfig: cfg}
}

func TestGetEffectiveRateMultiplier(t *testing.T) {
	t.Parallel()

	const defaultRate = 1.0
	const scheduledRate = 2.5

	tests := []struct {
		name string
		g    *Group
		now  time.Time
		want float64
	}{
		// -----------------------------------------------------------------------
		// Basic scenarios
		// -----------------------------------------------------------------------
		{
			name: "nil config returns default rate",
			g:    groupWith(nil),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "config disabled returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: false,
				Rules:   []ScheduledRateRule{{RateMultiplier: scheduledRate}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "config with empty rules returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules:   []ScheduledRateRule{},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "single rule no time/day/date restrictions returns scheduled rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules:   []ScheduledRateRule{{RateMultiplier: scheduledRate}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},

		// -----------------------------------------------------------------------
		// Date range (inclusive end)
		// -----------------------------------------------------------------------
		{
			name: "before date_start: no match returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "2026-03-17",
				}},
			}),
			// now = 2026-03-16, start = 2026-03-17
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "within date range: match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "2026-03-15",
					DateEnd:        "2026-03-20",
				}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "after date_end: no match returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "2026-03-10",
					DateEnd:        "2026-03-15",
				}},
			}),
			// now = 2026-03-16, end = 2026-03-15
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "exactly on date_end: match (inclusive)",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "2026-03-10",
					DateEnd:        "2026-03-16",
				}},
			}),
			// now = 2026-03-16 = date_end → match
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "date_start only: match after start",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "2026-03-16",
				}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "date_start only: no match before start",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "2026-03-17",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "date_end only: match before end",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateEnd:        "2026-03-16",
				}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "date_end only: no match after end",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateEnd:        "2026-03-15",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "single-day range date_start == date_end: match on that day",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "2026-03-16",
					DateEnd:        "2026-03-16",
				}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},

		// -----------------------------------------------------------------------
		// Day-of-week
		// -----------------------------------------------------------------------
		{
			name: "weekday-only rule [1..5]: match on Monday",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					Days:           []int{1, 2, 3, 4, 5},
				}},
			}),
			// 2026-03-16 is Monday (weekday=1)
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "weekday-only rule [1..5]: no match on Saturday",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					Days:           []int{1, 2, 3, 4, 5},
				}},
			}),
			// 2026-03-21 is Saturday (weekday=6)
			now:  time.Date(2026, time.March, 21, 14, 30, 0, 0, time.UTC),
			want: defaultRate,
		},
		{
			name: "weekend-only rule [0,6]: match on Sunday",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					Days:           []int{0, 6},
				}},
			}),
			// 2026-03-22 is Sunday (weekday=0)
			now:  time.Date(2026, time.March, 22, 14, 30, 0, 0, time.UTC),
			want: scheduledRate,
		},
		{
			name: "weekend-only rule [0,6]: no match on Wednesday",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					Days:           []int{0, 6},
				}},
			}),
			// 2026-03-18 is Wednesday (weekday=3)
			now:  time.Date(2026, time.March, 18, 14, 30, 0, 0, time.UTC),
			want: defaultRate,
		},
		{
			name: "empty days list matches every day",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					Days:           []int{},
				}},
			}),
			// Sunday — empty days should still match
			now:  time.Date(2026, time.March, 22, 14, 30, 0, 0, time.UTC),
			want: scheduledRate,
		},

		// -----------------------------------------------------------------------
		// Time window include mode (time_end exclusive)
		// -----------------------------------------------------------------------
		{
			name: "include mode: before window start — no match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
				}},
			}),
			now:  atTime(9, 59),
			want: defaultRate,
		},
		{
			name: "include mode: exactly at window start — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
				}},
			}),
			now:  atTime(10, 0),
			want: scheduledRate,
		},
		{
			name: "include mode: inside window — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
				}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "include mode: exactly at window end — NO match (exclusive)",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
				}},
			}),
			now:  atTime(18, 0),
			want: defaultRate,
		},
		{
			name: "include mode: after window — no match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
				}},
			}),
			now:  atTime(18, 1),
			want: defaultRate,
		},

		// -----------------------------------------------------------------------
		// Time window exclude mode
		// -----------------------------------------------------------------------
		{
			name: "exclude mode: before window — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
					TimeMode:       "exclude",
				}},
			}),
			now:  atTime(9, 0),
			want: scheduledRate,
		},
		{
			name: "exclude mode: inside window — no match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
					TimeMode:       "exclude",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "exclude mode: after window — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
					TimeMode:       "exclude",
				}},
			}),
			now:  atTime(20, 0),
			want: scheduledRate,
		},

		// -----------------------------------------------------------------------
		// Overnight time window (start > end)
		// -----------------------------------------------------------------------
		{
			name: "overnight 22:00-06:00: at 23:00 — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "22:00",
					TimeEnd:        "06:00",
				}},
			}),
			now:  atTime(23, 0),
			want: scheduledRate,
		},
		{
			name: "overnight 22:00-06:00: at 03:00 — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "22:00",
					TimeEnd:        "06:00",
				}},
			}),
			now:  atTime(3, 0),
			want: scheduledRate,
		},
		{
			name: "overnight 22:00-06:00: at 14:00 — no match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "22:00",
					TimeEnd:        "06:00",
				}},
			}),
			now:  atTime(14, 0),
			want: defaultRate,
		},
		{
			name: "overnight 23:59-00:01: 00:00 is in window (match)",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "23:59",
					TimeEnd:        "00:01",
				}},
			}),
			now:  atTime(0, 0),
			want: scheduledRate,
		},
		{
			name: "overnight 23:59-00:01: 00:01 is at exclusive end — no match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "23:59",
					TimeEnd:        "00:01",
				}},
			}),
			now:  atTime(0, 1),
			want: defaultRate,
		},

		// -----------------------------------------------------------------------
		// Equal time_start / time_end — all day
		// -----------------------------------------------------------------------
		{
			name: "time_start == time_end == 00:00: all day (match)",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "00:00",
					TimeEnd:        "00:00",
				}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "time_start == time_end == 14:00: all day (match)",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "14:00",
					TimeEnd:        "14:00",
				}},
			}),
			now:  atTime(3, 0),
			want: scheduledRate,
		},

		// -----------------------------------------------------------------------
		// Multiple rules — first-match wins
		// -----------------------------------------------------------------------
		{
			name: "weekday rule before weekend rule: Monday uses weekday rule",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					{RateMultiplier: 2.0, Days: []int{1, 2, 3, 4, 5}}, // weekdays
					{RateMultiplier: 3.0, Days: []int{0, 6}},          // weekends
				},
			}),
			// 2026-03-16 is Monday
			now:  atTime(14, 30),
			want: 2.0,
		},
		{
			name: "weekday rule before weekend rule: Sunday uses weekend rule",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					{RateMultiplier: 2.0, Days: []int{1, 2, 3, 4, 5}}, // weekdays
					{RateMultiplier: 3.0, Days: []int{0, 6}},          // weekends
				},
			}),
			// 2026-03-22 is Sunday
			now:  time.Date(2026, time.March, 22, 14, 30, 0, 0, time.UTC),
			want: 3.0,
		},
		{
			name: "two overlapping rules: first one wins",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					{RateMultiplier: 2.0, TimeStart: "10:00", TimeEnd: "18:00"},
					{RateMultiplier: 5.0, TimeStart: "12:00", TimeEnd: "16:00"},
				},
			}),
			now:  atTime(13, 0),
			want: 2.0,
		},

		// -----------------------------------------------------------------------
		// DST simulation (no actual DST transitions — just fixed UTC times)
		// -----------------------------------------------------------------------
		{
			name: "DST spring-forward sim: now at 03:00, rule covers 02:00-04:00 — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "02:00",
					TimeEnd:        "04:00",
				}},
			}),
			now:  atTime(3, 0),
			want: scheduledRate,
		},
		{
			name: "DST fall-back sim: now at 01:30, rule covers 01:00-02:00 — match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "01:00",
					TimeEnd:        "02:00",
				}},
			}),
			now:  atTime(1, 30),
			want: scheduledRate,
		},
		{
			name: "DST gap sim: now at 03:00, rule covers 02:00-02:59 — no match",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "02:00",
					TimeEnd:        "02:59",
				}},
			}),
			now:  atTime(3, 0),
			want: defaultRate,
		},

		// -----------------------------------------------------------------------
		// Malformed data — fail-open (rule skipped)
		// -----------------------------------------------------------------------
		{
			name: "invalid time_start format: rule skipped, returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "not-a-time",
					TimeEnd:        "18:00",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "invalid time_end format: rule skipped, returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "invalid",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "invalid date_start format: rule skipped, returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateStart:      "not-a-date",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "invalid date_end format: rule skipped, returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					DateEnd:        "2026/03/16",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "out-of-range day value in rule: rule skipped, returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					Days:           []int{1, 7}, // 7 is out of range
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "negative day value in rule: rule skipped, returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					Days:           []int{-1, 1},
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},
		{
			name: "invalid time_mode: rule skipped, returns default rate",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
					TimeMode:       "unknown",
				}},
			}),
			now:  atTime(14, 30),
			want: defaultRate,
		},

		// -----------------------------------------------------------------------
		// Edge cases
		// -----------------------------------------------------------------------
		{
			name: "rule with rate_multiplier=0: valid, returns 0",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: 0,
				}},
			}),
			now:  atTime(14, 30),
			want: 0,
		},
		{
			name: "malformed rule followed by valid rule: first skipped, second matches",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					{RateMultiplier: 99.0, TimeStart: "bad", TimeEnd: "18:00"},
					{RateMultiplier: scheduledRate},
				},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "rule limit capped at MaxScheduledRateRules",
			// Build 11 rules (> MaxScheduledRateRules=10), last rule has a different rate.
			// Rules 1-10 are no-match (wrong day), rule 11 would match but is never evaluated.
			g: func() *Group {
				rules := make([]ScheduledRateRule, 11)
				for i := 0; i < 10; i++ {
					rules[i] = ScheduledRateRule{
						RateMultiplier: scheduledRate,
						Days:           []int{6}, // Saturday — won't match on Monday
					}
				}
				rules[10] = ScheduledRateRule{RateMultiplier: 99.0} // beyond limit, should not match
				return groupWith(&ScheduledRateConfig{Enabled: true, Rules: rules})
			}(),
			// now = Monday, rules 0-9 require Saturday, rule 10 (beyond limit) matches all
			now:  atTime(14, 30),
			want: defaultRate, // rule 11 never evaluated
		},
		{
			name: "explicit include time_mode treated same as default",
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "10:00",
					TimeEnd:        "18:00",
					TimeMode:       "include",
				}},
			}),
			now:  atTime(14, 30),
			want: scheduledRate,
		},
		{
			name: "Monday with only time_start set (no time_end) - time filter inactive",
			// When only TimeStart is set but not TimeEnd, the time block is skipped entirely
			// because the condition requires both to be non-empty.
			g: groupWith(&ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{{
					RateMultiplier: scheduledRate,
					TimeStart:      "22:00",
					// TimeEnd is empty — time filter inactive
				}},
			}),
			now:  atTime(14, 30), // well outside 22:00, but time filter is inactive
			want: scheduledRate,
		},
	}

	_ = mon // used in comments above for orientation
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.g.GetEffectiveRateMultiplier(tc.now)
			require.Equal(t, tc.want, got)
		})
	}
}
