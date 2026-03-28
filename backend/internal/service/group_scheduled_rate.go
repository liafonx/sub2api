package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/domain"
)

// maxScheduledRateRules caps the number of rules evaluated to prevent abuse.
const maxScheduledRateRules = 10

// Type aliases so existing code in this package continues to compile.
type ScheduledRateConfig = domain.ScheduledRateConfig
type ScheduledRateRule = domain.ScheduledRateRule

// GetEffectiveRateMultiplier returns the rate multiplier for the group at
// the given time. If no scheduled rule matches, it returns g.RateMultiplier.
func (g *Group) GetEffectiveRateMultiplier(now time.Time) float64 {
	if g.ScheduledRateConfig == nil || !g.ScheduledRateConfig.Enabled || len(g.ScheduledRateConfig.Rules) == 0 {
		return g.RateMultiplier
	}

	limit := len(g.ScheduledRateConfig.Rules)
	if limit > maxScheduledRateRules {
		limit = maxScheduledRateRules
	}

	nowDate := now.Format("2006-01-02")
	for i := 0; i < limit; i++ {
		rule := &g.ScheduledRateConfig.Rules[i]
		if ruleMatches(rule, nowDate, now) {
			return rule.RateMultiplier
		}
	}
	return g.RateMultiplier
}

func ruleMatches(r *ScheduledRateRule, nowDate string, now time.Time) bool {
	// Date range check (inclusive on both ends).
	// ISO 8601 date strings are lexicographically orderable — no time.Parse needed.
	if r.DateStart != "" && nowDate < r.DateStart {
		return false
	}
	if r.DateEnd != "" && nowDate > r.DateEnd {
		return false
	}

	// Day-of-week check.
	// If any day value is out of range (not 0-6), skip the entire rule.
	if len(r.Days) > 0 {
		wd := int(now.Weekday()) // 0=Sunday
		found := false
		for _, d := range r.Days {
			if d < 0 || d > 6 {
				return false // invalid day: skip rule
			}
			if d == wd {
				found = true
			}
		}
		if !found {
			return false
		}
	}

	// Time window check. Both TimeStart and TimeEnd must be set.
	if r.TimeStart != "" && r.TimeEnd != "" {
		tsMin := parseHHMM(r.TimeStart)
		teMin := parseHHMM(r.TimeEnd)
		if tsMin < 0 || teMin < 0 {
			return false
		}
		nowMin := now.Hour()*60 + now.Minute()

		inWindow := timeInWindow(nowMin, tsMin, teMin)

		mode := strings.ToLower(r.TimeMode)
		switch mode {
		case "", "include":
			if !inWindow {
				return false
			}
		case "exclude":
			if inWindow {
				return false
			}
		default:
			return false // unknown mode: skip rule
		}
	}

	return true
}

// timeInWindow checks if nowMin is in [start, end) with overnight wrap support.
// When start == end, the window covers all day (returns true).
func timeInWindow(nowMin, startMin, endMin int) bool {
	if startMin == endMin {
		return true // whole day
	}
	if startMin < endMin {
		// Normal window: [start, end)
		return nowMin >= startMin && nowMin < endMin
	}
	// Overnight window: [start, 24:00) or [00:00, end)
	return nowMin >= startMin || nowMin < endMin
}

func parseHHMM(s string) int {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return -1
	}
	h, m := 0, 0
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return -1
		}
		h = h*10 + int(c-'0')
	}
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return -1
		}
		m = m*10 + int(c-'0')
	}
	if h > 23 || m > 59 {
		return -1
	}
	return h*60 + m
}

// ValidateScheduledRateConfig validates a ScheduledRateConfig.
func ValidateScheduledRateConfig(cfg *ScheduledRateConfig) error {
	if cfg == nil {
		return nil
	}
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.Rules) == 0 {
		return fmt.Errorf("enabled config must have at least one rule")
	}
	if len(cfg.Rules) > maxScheduledRateRules {
		return fmt.Errorf("too many rules: %d (max %d)", len(cfg.Rules), maxScheduledRateRules)
	}
	for i, r := range cfg.Rules {
		if r.RateMultiplier < 0 {
			return fmt.Errorf("rule[%d]: rate_multiplier must be >= 0", i)
		}
		if r.TimeStart != "" && parseHHMM(r.TimeStart) < 0 {
			return fmt.Errorf("rule[%d]: invalid time_start %q", i, r.TimeStart)
		}
		if r.TimeEnd != "" && parseHHMM(r.TimeEnd) < 0 {
			return fmt.Errorf("rule[%d]: invalid time_end %q", i, r.TimeEnd)
		}
		if (r.TimeStart != "") != (r.TimeEnd != "") {
			return fmt.Errorf("rule[%d]: time_start and time_end must both be set or both empty", i)
		}
		if r.DateStart != "" {
			if _, err := time.Parse("2006-01-02", r.DateStart); err != nil {
				return fmt.Errorf("rule[%d]: invalid date_start %q", i, r.DateStart)
			}
		}
		if r.DateEnd != "" {
			if _, err := time.Parse("2006-01-02", r.DateEnd); err != nil {
				return fmt.Errorf("rule[%d]: invalid date_end %q", i, r.DateEnd)
			}
		}
		if r.DateStart != "" && r.DateEnd != "" {
			ds, _ := time.Parse("2006-01-02", r.DateStart)
			de, _ := time.Parse("2006-01-02", r.DateEnd)
			if ds.After(de) {
				return fmt.Errorf("rule[%d]: date_start %q is after date_end %q", i, r.DateStart, r.DateEnd)
			}
		}
		mode := strings.ToLower(r.TimeMode)
		if r.TimeMode != "" && mode != "include" && mode != "exclude" {
			return fmt.Errorf("rule[%d]: invalid time_mode %q", i, r.TimeMode)
		}
		for _, d := range r.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("rule[%d]: invalid day %d (must be 0-6)", i, d)
			}
		}
	}
	return nil
}
