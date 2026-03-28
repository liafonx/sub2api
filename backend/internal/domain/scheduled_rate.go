package domain

// ScheduledRateConfig holds time-based rate multiplier rules for a group.
type ScheduledRateConfig struct {
	Enabled bool                `json:"enabled"`
	Rules   []ScheduledRateRule `json:"rules"`
}

// ScheduledRateRule defines a single time-based rate multiplier rule.
// All filters are optional; omitted filters match everything.
// First matching rule wins; evaluation stops at maxScheduledRateRules.
type ScheduledRateRule struct {
	RateMultiplier float64 `json:"rate_multiplier"`
	TimeStart      string  `json:"time_start,omitempty"` // "HH:MM"
	TimeEnd        string  `json:"time_end,omitempty"`   // "HH:MM" (exclusive for include mode)
	TimeMode       string  `json:"time_mode,omitempty"`  // "include" (default) or "exclude"
	Days           []int   `json:"days,omitempty"`       // 0=Sunday..6=Saturday; empty=all
	DateStart      string  `json:"date_start,omitempty"` // "YYYY-MM-DD" (inclusive)
	DateEnd        string  `json:"date_end,omitempty"`   // "YYYY-MM-DD" (inclusive)
}
