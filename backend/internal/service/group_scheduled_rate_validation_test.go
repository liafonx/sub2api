//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateScheduledRateConfig(t *testing.T) {
	ptr := func(s string) *string { return &s }
	_ = ptr

	makeRule := func(overrides ...func(*ScheduledRateRule)) ScheduledRateRule {
		r := ScheduledRateRule{RateMultiplier: 1.0}
		for _, fn := range overrides {
			fn(&r)
		}
		return r
	}

	tests := []struct {
		name    string
		config  *ScheduledRateConfig
		wantErr bool
	}{
		{
			name: "valid config with enabled=true and one rule",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules:   []ScheduledRateRule{makeRule()},
			},
			wantErr: false,
		},
		{
			name: "enabled=true with empty rules",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules:   []ScheduledRateRule{},
			},
			wantErr: true,
		},
		{
			name: "too many rules (>10)",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: func() []ScheduledRateRule {
					rules := make([]ScheduledRateRule, 11)
					for i := range rules {
						rules[i] = makeRule()
					}
					return rules
				}(),
			},
			wantErr: true,
		},
		{
			name: "invalid time format 25:00",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.TimeStart = "25:00"
						r.TimeEnd = "26:00"
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid time format ab:cd",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.TimeStart = "ab:cd"
						r.TimeEnd = "10:00"
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid date format 2026-13-01",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.DateStart = "2026-13-01"
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "negative rate_multiplier",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.RateMultiplier = -0.5
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "out-of-range day value 7",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.Days = []int{1, 7}
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "date_start after date_end",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.DateStart = "2026-12-01"
						r.DateEnd = "2026-01-01"
					}),
				},
			},
			wantErr: true,
		},
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config with empty rules is valid",
			config: &ScheduledRateConfig{
				Enabled: false,
				Rules:   []ScheduledRateRule{},
			},
			wantErr: false,
		},
		{
			name: "rate_multiplier=0 is valid (free tier)",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.RateMultiplier = 0
					}),
				},
			},
			wantErr: false,
		},
		{
			name: "empty days array is valid (every day)",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.Days = []int{}
					}),
				},
			},
			wantErr: false,
		},
		{
			name: "both time_start and time_end empty is valid",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.TimeStart = ""
						r.TimeEnd = ""
					}),
				},
			},
			wantErr: false,
		},
		{
			name: "time_start set but time_end empty is error",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.TimeStart = "09:00"
						r.TimeEnd = ""
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "time_end set but time_start empty is error",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: []ScheduledRateRule{
					makeRule(func(r *ScheduledRateRule) {
						r.TimeStart = ""
						r.TimeEnd = "18:00"
					}),
				},
			},
			wantErr: true,
		},
		{
			name: "exactly 10 rules is valid (boundary)",
			config: &ScheduledRateConfig{
				Enabled: true,
				Rules: func() []ScheduledRateRule {
					rules := make([]ScheduledRateRule, 10)
					for i := range rules {
						rules[i] = makeRule()
					}
					return rules
				}(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScheduledRateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
