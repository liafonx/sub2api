package service

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Group struct {
	ID             int64
	Name           string
	Description    string
	Platform       string
	RateMultiplier float64
	IsExclusive    bool
	Status         string
	Hydrated       bool // indicates the group was loaded from a trusted repository source

	SubscriptionType    string
	DailyLimitUSD       *float64
	WeeklyLimitUSD      *float64
	MonthlyLimitUSD     *float64
	DefaultValidityDays int

	// 图片生成计费配置（antigravity 和 gemini 平台使用）
	ImagePrice1K *float64
	ImagePrice2K *float64
	ImagePrice4K *float64

	// Sora 按次计费配置（阶段 1）
	SoraImagePrice360          *float64
	SoraImagePrice540          *float64
	SoraVideoPricePerRequest   *float64
	SoraVideoPricePerRequestHD *float64

	// Sora 存储配额
	SoraStorageQuotaBytes int64

	// Claude Code 客户端限制
	ClaudeCodeOnly  bool
	FallbackGroupID *int64
	// 无效请求兜底分组（仅 anthropic 平台使用）
	FallbackGroupIDOnInvalidRequest *int64

	// 模型路由配置
	// key: 模型匹配模式（支持 * 通配符，如 "claude-opus-*"）
	// value: 优先账号 ID 列表
	ModelRouting        map[string][]int64
	ModelRoutingEnabled bool

	// MCP XML 协议注入开关（仅 antigravity 平台使用）
	MCPXMLInject bool

	// 支持的模型系列（仅 antigravity 平台使用）
	// 可选值: claude, gemini_text, gemini_image
	SupportedModelScopes []string

	// 分组排序
	SortOrder int

	// OpenAI Messages 调度配置（仅 openai 平台使用）
	AllowMessagesDispatch bool
	DefaultMappedModel    string

	CreatedAt time.Time
	UpdatedAt time.Time

	AccountGroups []AccountGroup
	AccountCount  int64

	// 计费费率时间表配置
	ScheduledRateConfig *ScheduledRateConfig
}

func (g *Group) IsActive() bool {
	return g.Status == StatusActive
}

func (g *Group) IsSubscriptionType() bool {
	return g.SubscriptionType == SubscriptionTypeSubscription
}

func (g *Group) IsFreeSubscription() bool {
	return g.IsSubscriptionType() && g.RateMultiplier == 0
}

func (g *Group) HasDailyLimit() bool {
	return g.DailyLimitUSD != nil && *g.DailyLimitUSD > 0
}

func (g *Group) HasWeeklyLimit() bool {
	return g.WeeklyLimitUSD != nil && *g.WeeklyLimitUSD > 0
}

func (g *Group) HasMonthlyLimit() bool {
	return g.MonthlyLimitUSD != nil && *g.MonthlyLimitUSD > 0
}

// GetImagePrice 根据 image_size 返回对应的图片生成价格
// 如果分组未配置价格，返回 nil（调用方应使用默认值）
func (g *Group) GetImagePrice(imageSize string) *float64 {
	switch imageSize {
	case "1K":
		return g.ImagePrice1K
	case "2K":
		return g.ImagePrice2K
	case "4K":
		return g.ImagePrice4K
	default:
		// 未知尺寸默认按 2K 计费
		return g.ImagePrice2K
	}
}

// GetSoraImagePrice 根据 Sora 图片尺寸返回价格（360/540）
func (g *Group) GetSoraImagePrice(imageSize string) *float64 {
	switch imageSize {
	case "360":
		return g.SoraImagePrice360
	case "540":
		return g.SoraImagePrice540
	default:
		return g.SoraImagePrice360
	}
}

// IsGroupContextValid reports whether a group from context has the fields required for routing decisions.
func IsGroupContextValid(group *Group) bool {
	if group == nil {
		return false
	}
	if group.ID <= 0 {
		return false
	}
	if !group.Hydrated {
		return false
	}
	if group.Platform == "" || group.Status == "" {
		return false
	}
	return true
}

// GetRoutingAccountIDs 根据请求模型获取路由账号 ID 列表
// 返回匹配的优先账号 ID 列表，如果没有匹配规则则返回 nil
func (g *Group) GetRoutingAccountIDs(requestedModel string) []int64 {
	if !g.ModelRoutingEnabled || len(g.ModelRouting) == 0 || requestedModel == "" {
		return nil
	}

	// 1. 精确匹配优先
	if accountIDs, ok := g.ModelRouting[requestedModel]; ok && len(accountIDs) > 0 {
		return accountIDs
	}

	// 2. 通配符匹配（前缀匹配）
	for pattern, accountIDs := range g.ModelRouting {
		if matchModelPattern(pattern, requestedModel) && len(accountIDs) > 0 {
			return accountIDs
		}
	}

	return nil
}

// matchModelPattern 检查模型是否匹配模式
// 支持 * 通配符，如 "claude-opus-*" 匹配 "claude-opus-4-20250514"
func matchModelPattern(pattern, model string) bool {
	if pattern == model {
		return true
	}

	// 处理 * 通配符（仅支持末尾通配符）
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(model, prefix)
	}

	return false
}

// MaxScheduledRateRules is the maximum number of rules allowed in a ScheduledRateConfig.
const MaxScheduledRateRules = 10

// Time mode constants for ScheduledRateRule.TimeMode.
const (
	TimeModeInclude = "include"
	TimeModeExclude = "exclude"
)

// ScheduledRateRule defines a single time-based rate multiplier rule.
type ScheduledRateRule struct {
	RateMultiplier float64 `json:"rate_multiplier"`
	TimeStart      string  `json:"time_start,omitempty"` // "HH:MM", empty = all day
	TimeEnd        string  `json:"time_end,omitempty"`   // "HH:MM", exclusive
	TimeMode       string  `json:"time_mode,omitempty"`  // "include" (default) or "exclude"
	Days           []int   `json:"days,omitempty"`       // 0=Sun..6=Sat, empty = every day
	DateStart      string  `json:"date_start,omitempty"` // "2006-01-02", empty = no start limit
	DateEnd        string  `json:"date_end,omitempty"`   // "2006-01-02", empty = no end limit, inclusive
}

// ScheduledRateConfig holds the time-based rate multiplier configuration for a group.
type ScheduledRateConfig struct {
	Enabled bool                `json:"enabled"`
	Rules   []ScheduledRateRule `json:"rules"`
}

// GetEffectiveRateMultiplier returns the rate multiplier effective at the given time.
// now must already be in the server timezone (callers pass timezone.Now()).
// Returns g.RateMultiplier when no scheduled rule matches.
func (g *Group) GetEffectiveRateMultiplier(now time.Time) float64 {
	cfg := g.ScheduledRateConfig
	if cfg == nil || !cfg.Enabled || len(cfg.Rules) == 0 {
		return g.RateMultiplier
	}

	loc := now.Location()
	nowDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	currentMinutes := now.Hour()*60 + now.Minute()

	limit := len(cfg.Rules)
	if limit > MaxScheduledRateRules {
		limit = MaxScheduledRateRules
	}

	for i := 0; i < limit; i++ {
		rule := cfg.Rules[i]

		// --- Date check ---
		if rule.DateStart != "" {
			ds, err := time.ParseInLocation("2006-01-02", rule.DateStart, loc)
			if err != nil {
				continue
			}
			if nowDate.Before(ds) {
				continue
			}
		}
		if rule.DateEnd != "" {
			de, err := time.ParseInLocation("2006-01-02", rule.DateEnd, loc)
			if err != nil {
				continue
			}
			// date_end is inclusive: nowDate must be <= de
			if nowDate.After(de) {
				continue
			}
		}

		// --- Day check ---
		if len(rule.Days) > 0 {
			weekday := int(now.Weekday())
			matched := false
			valid := true
			for _, d := range rule.Days {
				if d < 0 || d > 6 {
					valid = false
					break
				}
				if d == weekday {
					matched = true
				}
			}
			if !valid {
				continue
			}
			if !matched {
				continue
			}
		}

		// --- Time check ---
		if rule.TimeStart != "" && rule.TimeEnd != "" && rule.TimeStart != rule.TimeEnd {
			startMinutes, err := parseHHMM(rule.TimeStart)
			if err != nil {
				continue
			}
			endMinutes, err := parseHHMM(rule.TimeEnd)
			if err != nil {
				continue
			}

			var inWindow bool
			if startMinutes > endMinutes {
				// overnight window e.g. 22:00 - 06:00
				inWindow = currentMinutes >= startMinutes || currentMinutes < endMinutes
			} else {
				inWindow = currentMinutes >= startMinutes && currentMinutes < endMinutes
			}

			switch rule.TimeMode {
			case "", TimeModeInclude:
				if !inWindow {
					continue
				}
			case TimeModeExclude:
				if inWindow {
					continue
				}
			default:
				continue
			}
		}

		// All checks passed — first matching rule wins.
		return rule.RateMultiplier
	}

	return g.RateMultiplier
}

// parseHHMM parses a "HH:MM" string into total minutes since midnight.
// Returns an error if the format is invalid or values are out of range.
func parseHHMM(s string) (int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid HH:MM: %q", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid hour in %q: %w", s, err)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid minute in %q: %w", s, err)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("time out of range in %q (hour 0-23, minute 0-59)", s)
	}
	return h*60 + m, nil
}

// ValidateScheduledRateConfig validates a ScheduledRateConfig.
// Returns nil if config is nil (absent config is valid).
func ValidateScheduledRateConfig(config *ScheduledRateConfig) error {
	if config == nil {
		return nil
	}
	if config.Enabled && len(config.Rules) == 0 {
		return fmt.Errorf("enabled config must have at least one rule")
	}
	if len(config.Rules) > MaxScheduledRateRules {
		return fmt.Errorf("scheduled rate config has too many rules (max %d)", MaxScheduledRateRules)
	}

	for i, rule := range config.Rules {
		n := i + 1 // 1-based index for error messages

		if rule.RateMultiplier < 0 {
			return fmt.Errorf("rule %d: rate_multiplier must be >= 0", n)
		}

		if err := validateOptionalHHMM(rule.TimeStart, fmt.Sprintf("rule %d: time_start", n)); err != nil {
			return err
		}
		if err := validateOptionalHHMM(rule.TimeEnd, fmt.Sprintf("rule %d: time_end", n)); err != nil {
			return err
		}
		if (rule.TimeStart == "") != (rule.TimeEnd == "") {
			return fmt.Errorf("rule %d: time_start and time_end must both be set or both be empty", n)
		}

		switch rule.TimeMode {
		case "", TimeModeInclude, TimeModeExclude:
			// valid
		default:
			return fmt.Errorf("rule %d: time_mode must be \"\", %q, or %q", n, TimeModeInclude, TimeModeExclude)
		}

		for _, d := range rule.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("rule %d: day value %d is out of range (0-6)", n, d)
			}
		}

		if rule.DateStart != "" {
			if _, err := time.Parse("2006-01-02", rule.DateStart); err != nil {
				return fmt.Errorf("rule %d: invalid date_start %q: %w", n, rule.DateStart, err)
			}
		}
		if rule.DateEnd != "" {
			if _, err := time.Parse("2006-01-02", rule.DateEnd); err != nil {
				return fmt.Errorf("rule %d: invalid date_end %q: %w", n, rule.DateEnd, err)
			}
		}
		if rule.DateStart != "" && rule.DateEnd != "" {
			ds, _ := time.Parse("2006-01-02", rule.DateStart)
			de, _ := time.Parse("2006-01-02", rule.DateEnd)
			if ds.After(de) {
				return fmt.Errorf("rule %d: date_start must be <= date_end", n)
			}
		}
	}

	return nil
}

// validateOptionalHHMM validates a "HH:MM" string if non-empty.
func validateOptionalHHMM(s, label string) error {
	if s == "" {
		return nil
	}
	if _, err := parseHHMM(s); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}
