package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
)

// QuotaZone represents the result zone of a per-user quota check.
type QuotaZone = string

const (
	QuotaZoneDisabled       QuotaZone = "disabled"
	QuotaZoneNoEpoch        QuotaZone = "no_epoch"
	QuotaZoneRedisError     QuotaZone = "redis_error"
	QuotaZoneGreen          QuotaZone = "green"
	QuotaZoneYellowSticky   QuotaZone = "yellow_sticky"
	QuotaZoneYellowNonStick QuotaZone = "yellow_non_sticky"
	QuotaZoneRed            QuotaZone = "red"
)

// QuotaDisplayMeta holds display data for a single account's user quota state.
type QuotaDisplayMeta struct {
	PerUserLimit float64
	ActiveCount  int64
}

// UserQuotaChecker is the interface for per-user dynamic quota enforcement.
// All operations fail-open: returns allowed=true on Redis errors or when disabled.
type UserQuotaChecker interface {
	CheckUserQuota(ctx context.Context, account *Account, userID int64, isSticky bool) (allowed bool, reason string)
	RegisterActivity(ctx context.Context, account *Account, userID int64)
	IncrementUserCost(ctx context.Context, accountID int64, userID int64, standardCost float64)
	// CheckUserRPM checks per-user RPM limit for an account. Returns allowed=true when disabled or within limit.
	CheckUserRPM(ctx context.Context, account *Account, userID int64, isSticky bool) (allowed bool, reason string)
	// IncrementUserAccountRPM increments the per-user-per-account RPM counter after a successful request.
	IncrementUserAccountRPM(ctx context.Context, accountID int64, userID int64)
	// GetDisplayMetaBatch reads per_user_limit and active_count for multiple accounts.
	GetDisplayMetaBatch(ctx context.Context, accountIDs []int64) (map[int64]QuotaDisplayMeta, error)
	// GetUserQuotaStatus returns the per-user limit, user's current cost, and active user count for an account.
	// Returns hasData=false when meta is not initialized (no active users).
	GetUserQuotaStatus(ctx context.Context, accountID int64, userID int64) (perUserLimit float64, userCost float64, activeCount int64, hasData bool, err error)
	// NotifyAccountUpdated refreshes the cached account and recalculates quotas
	// if the account has active users. Call after admin updates account settings.
	NotifyAccountUpdated(ctx context.Context, account *Account)
}

// UserQuotaCache defines the Redis operations for the user quota plugin.
type UserQuotaCache interface {
	// ZAddActivity adds/updates user activity (score=nowMs) using ZADD GT.
	// Returns true if the member was newly added to the set.
	ZAddActivity(ctx context.Context, accountID int64, userID int64, nowMs int64) (isNew bool, err error)
	// ZRemIdleUsers removes members with score < cutoffMs, returns removed userIDs.
	ZRemIdleUsers(ctx context.Context, accountID int64, cutoffMs int64) ([]int64, error)
	// ZCardActive returns count of active users.
	ZCardActive(ctx context.Context, accountID int64) (int64, error)
	// BumpEpochAndSetMeta atomically increments epoch and writes all quota metadata.
	// Returns the new epoch value.
	BumpEpochAndSetMeta(ctx context.Context, accountID int64, perUserLimit float64, perUserStickyReserve float64, activeCount int64) (int64, error)
	// HGetMeta reads quota metadata. epoch=0 means not initialized.
	HGetMeta(ctx context.Context, accountID int64) (epoch int64, perUserLimit float64, perUserStickyReserve float64, err error)
	// GetQuotaCheckData fetches quota metadata, user cost, and active count in a single Lua script (1 RTT).
	// Returns epoch=0 if meta is not initialized.
	GetQuotaCheckData(ctx context.Context, accountID int64, userID int64) (epoch int64, perUserLimit float64, perUserStickyReserve float64, userCost float64, activeCount int64, err error)
	// AtomicIncrCost atomically reads the current epoch from meta and increments the user's cost.
	// Returns epoch=0 if meta is not initialized (cost is not recorded).
	AtomicIncrCost(ctx context.Context, accountID int64, userID int64, delta float64) (epoch int64, newTotal float64, err error)
	// GetUserCost reads cost for a user in the given epoch. Returns 0 if not set.
	GetUserCost(ctx context.Context, accountID int64, epoch int64, userID int64) (float64, error)
	// DelMeta removes the meta hash (when no active users remain).
	DelMeta(ctx context.Context, accountID int64) error
	// GetDisplayMetaBatch reads per_user_limit and active_count for multiple accounts (Redis pipeline).
	// Returns map[accountID] → QuotaDisplayMeta. Missing/empty meta is omitted.
	GetDisplayMetaBatch(ctx context.Context, accountIDs []int64) (map[int64]QuotaDisplayMeta, error)
}

// accountQuotaState holds in-memory state for a single account being tracked by the quota service.
type accountQuotaState struct {
	account           *Account
	lastWindowStartMs int64 // UnixMilli of the 5h billing window start at last recalculation; 0 = not yet recorded
}

// userQuotaService implements UserQuotaChecker.
type userQuotaService struct {
	cache             UserQuotaCache
	rpmCache          RPMCache
	windowCostGetter  func(ctx context.Context, account *Account) float64
	windowLimitGetter func(ctx context.Context, account *Account) float64

	mu             sync.RWMutex
	activeAccounts map[int64]*accountQuotaState
}

// NewUserQuotaService creates a new userQuotaService.
// windowCostGetter returns the current window cost for an account (reuses existing cache logic).
func NewUserQuotaService(cache UserQuotaCache, windowCostGetter func(ctx context.Context, account *Account) float64, rpmCache RPMCache) UserQuotaChecker {
	return &userQuotaService{
		cache:            cache,
		rpmCache:         rpmCache,
		windowCostGetter: windowCostGetter,
		activeAccounts:   make(map[int64]*accountQuotaState),
	}
}

// SetWindowLimitGetter sets the callback to resolve effective window cost limit.
// Must be called after construction (before traffic).
func SetWindowLimitGetter(svc UserQuotaChecker, getter func(ctx context.Context, account *Account) float64) {
	if impl, ok := svc.(*userQuotaService); ok {
		impl.windowLimitGetter = getter
	}
}

// ensureAccountTracked upserts the account in activeAccounts and detects window changes.
// Pass windowStartMs=0 to skip window-change detection (RPM-only mode).
// Returns true if a billing window change was detected.
func (s *userQuotaService) ensureAccountTracked(account *Account, windowStartMs int64) (windowChanged bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.activeAccounts[account.ID]
	if !exists {
		s.activeAccounts[account.ID] = &accountQuotaState{
			account:           account,
			lastWindowStartMs: windowStartMs,
		}
		return false
	}
	state.account = account
	if windowStartMs > 0 && state.lastWindowStartMs > 0 && state.lastWindowStartMs != windowStartMs {
		return true
	}
	return false
}

// StartUserQuotaCleanupTicker starts a background goroutine that evicts idle users
// and redistributes quota. Call this once during application startup.
func StartUserQuotaCleanupTicker(ctx context.Context, svc UserQuotaChecker, interval time.Duration) {
	impl, ok := svc.(*userQuotaService)
	if !ok {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				impl.runCleanup(ctx)
			}
		}
	}()
}

func (s *userQuotaService) runCleanup(ctx context.Context) {
	s.mu.RLock()
	states := make([]*accountQuotaState, 0, len(s.activeAccounts))
	for _, state := range s.activeAccounts {
		states = append(states, state)
	}
	s.mu.RUnlock()

	totalRemoved := 0

	for _, state := range states {
		account := state.account
		cutoffMs := time.Now().UnixMilli() - account.GetUserQuotaIdleTimeout().Milliseconds()
		removed, err := s.cache.ZRemIdleUsers(ctx, account.ID, cutoffMs)
		if err != nil {
			logger.L().Error("user_quota.redis_error",
				zap.String("operation", "ZRemIdleUsers"),
				zap.Int64("account_id", account.ID),
				zap.Error(err),
			)
			continue
		}
		for _, uid := range removed {
			logger.L().Info("user_quota.user_released",
				zap.Int64("account_id", account.ID),
				zap.Int64("user_id", uid),
				zap.String("reason", "idle"),
			)
			totalRemoved++
		}

		quotaEnabled := account.IsUserQuotaEnabled()

		if quotaEnabled {
			// Cost quota accounts: recalculate on eviction or window change.
			currentWindowStartMs := account.GetCurrentWindowStartTime().UnixMilli()
			windowChanged := state.lastWindowStartMs > 0 && currentWindowStartMs != state.lastWindowStartMs

			if len(removed) > 0 || windowChanged {
				if windowChanged {
					logger.L().Info("user_quota.window_reset_detected",
						zap.Int64("account_id", account.ID),
						zap.String("trigger", "cleanup_tick"),
					)
				}
				s.recalculateQuotas(ctx, account, true, windowChanged)
			}
		} else {
			// RPM-only accounts: prune from activeAccounts when all users evicted.
			if len(removed) > 0 {
				activeCount, cardErr := s.cache.ZCardActive(ctx, account.ID)
				if cardErr == nil && activeCount == 0 {
					s.mu.Lock()
					delete(s.activeAccounts, account.ID)
					s.mu.Unlock()
				}
			}
		}
	}

	logger.L().Debug("user_quota.cleanup_tick",
		zap.Int("accounts_checked", len(states)),
		zap.Int("users_removed", totalRemoved),
	)
}

// CheckUserQuota returns whether the user may proceed on this account.
func (s *userQuotaService) CheckUserQuota(ctx context.Context, account *Account, userID int64, isSticky bool) (bool, string) {
	if !account.IsUserQuotaEnabled() {
		return true, QuotaZoneDisabled
	}

	epoch, perUserLimit, perUserStickyReserve, userCost, _, err := s.cache.GetQuotaCheckData(ctx, account.ID, userID)
	if err != nil {
		logger.L().Error("user_quota.redis_error",
			zap.String("operation", "GetQuotaCheckData"),
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return true, QuotaZoneRedisError
	}
	if epoch == 0 {
		return true, QuotaZoneNoEpoch
	}

	if userCost < perUserLimit {
		logger.L().Debug("user_quota.check_allowed",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Float64("user_cost", userCost),
			zap.Float64("per_user_limit", perUserLimit),
			zap.String("zone", QuotaZoneGreen),
		)
		return true, QuotaZoneGreen
	}

	if userCost < perUserLimit+perUserStickyReserve {
		if isSticky {
			logger.L().Debug("user_quota.check_allowed",
				zap.Int64("account_id", account.ID),
				zap.Int64("user_id", userID),
				zap.Float64("user_cost", userCost),
				zap.Float64("per_user_limit", perUserLimit),
				zap.String("zone", QuotaZoneYellowSticky),
			)
			return true, QuotaZoneYellowSticky
		}
		logger.L().Warn("user_quota.check_blocked",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Float64("user_cost", userCost),
			zap.Float64("per_user_limit", perUserLimit),
			zap.String("zone", QuotaZoneYellowNonStick),
		)
		return false, QuotaZoneYellowNonStick
	}

	logger.L().Warn("user_quota.check_blocked",
		zap.Int64("account_id", account.ID),
		zap.Int64("user_id", userID),
		zap.Float64("user_cost", userCost),
		zap.Float64("per_user_limit", perUserLimit),
		zap.String("zone", QuotaZoneRed),
	)
	return false, QuotaZoneRed
}

// RegisterActivity marks the user as active. Triggers recalculation on first appearance
// or when the upstream 5h billing window has reset since the last recalculation.
func (s *userQuotaService) RegisterActivity(ctx context.Context, account *Account, userID int64) {
	quotaEnabled := account.IsUserQuotaEnabled()
	rpmEnabled := account.IsUserRPMEnabled()
	if !quotaEnabled && !rpmEnabled {
		return
	}

	nowMs := time.Now().UnixMilli()
	isNew, err := s.cache.ZAddActivity(ctx, account.ID, userID, nowMs)
	if err != nil {
		logger.L().Error("user_quota.redis_error",
			zap.String("operation", "ZAddActivity"),
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return
	}

	// Window tracking and recalculation only needed for cost quota, not RPM-only.
	if !quotaEnabled {
		// RPM-only: just track in activeAccounts for cleanup, skip window logic.
		s.ensureAccountTracked(account, 0)
		if isNew {
			activeCount, _ := s.cache.ZCardActive(ctx, account.ID)
			logger.L().Info("user_quota.user_joined",
				zap.Int64("account_id", account.ID),
				zap.Int64("user_id", userID),
				zap.Int64("active_users", activeCount),
				zap.String("mode", "rpm_only"),
			)
		}
		return
	}

	currentWindowStartMs := account.GetCurrentWindowStartTime().UnixMilli()
	windowChanged := s.ensureAccountTracked(account, currentWindowStartMs)

	if isNew || windowChanged {
		if windowChanged {
			logger.L().Info("user_quota.window_reset_detected",
				zap.Int64("account_id", account.ID),
				zap.String("trigger", "register_activity"),
			)
		}
		newEpoch, activeCount := s.recalculateQuotas(ctx, account, false, windowChanged)
		if isNew && activeCount > 0 {
			logger.L().Info("user_quota.user_joined",
				zap.Int64("account_id", account.ID),
				zap.Int64("user_id", userID),
				zap.Int64("active_users", activeCount),
				zap.Int64("epoch", newEpoch),
			)
		}
	}
}

// IncrementUserCost atomically reads the current epoch and adds standardCost to the user's cost counter.
func (s *userQuotaService) IncrementUserCost(ctx context.Context, accountID int64, userID int64, standardCost float64) {
	if standardCost <= 0 {
		return
	}
	epoch, newTotal, err := s.cache.AtomicIncrCost(ctx, accountID, userID, standardCost)
	if err != nil {
		logger.L().Error("user_quota.redis_error",
			zap.String("operation", "AtomicIncrCost"),
			zap.Int64("account_id", accountID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return
	}
	if epoch == 0 {
		return
	}
	logger.L().Debug("user_quota.cost_incremented",
		zap.Int64("account_id", accountID),
		zap.Int64("user_id", userID),
		zap.Int64("epoch", epoch),
		zap.Float64("increment_cost", standardCost),
		zap.Float64("new_total", newTotal),
	)
}

// GetDisplayMetaBatch delegates to cache for batch per_user_limit + active_count reads.
func (s *userQuotaService) GetDisplayMetaBatch(ctx context.Context, accountIDs []int64) (map[int64]QuotaDisplayMeta, error) {
	return s.cache.GetDisplayMetaBatch(ctx, accountIDs)
}

// GetUserQuotaStatus returns perUserLimit, userCost, activeCount, and whether meta exists for the account+user.
func (s *userQuotaService) GetUserQuotaStatus(ctx context.Context, accountID int64, userID int64) (perUserLimit float64, userCost float64, activeCount int64, hasData bool, err error) {
	var epoch int64
	epoch, perUserLimit, _, userCost, activeCount, err = s.cache.GetQuotaCheckData(ctx, accountID, userID)
	if err != nil {
		return 0, 0, 0, false, err
	}
	if epoch == 0 {
		return 0, 0, 0, false, nil
	}
	return perUserLimit, userCost, activeCount, true, nil
}

// NotifyAccountUpdated refreshes the cached account pointer and triggers quota
// recalculation if the account has active users. Call after admin updates account settings.
func (s *userQuotaService) NotifyAccountUpdated(ctx context.Context, account *Account) {
	if !account.IsUserQuotaEnabled() {
		return
	}

	s.mu.Lock()
	state, exists := s.activeAccounts[account.ID]
	if !exists {
		s.mu.Unlock()
		return
	}
	state.account = account
	s.mu.Unlock()

	s.recalculateQuotas(ctx, account, false)
	logger.L().Info("user_quota.account_updated",
		zap.Int64("account_id", account.ID),
	)
}

// recalculateQuotas recomputes per-user quota limits.
// When windowReset is true, the 5h window just changed and the cached cost is stale —
// the cost is forced to 0 (new window has no spending yet).
// Returns (newEpoch, activeCount). Returns (0, 0) on error or when no active users remain.
func (s *userQuotaService) recalculateQuotas(ctx context.Context, account *Account, skipEviction bool, windowReset ...bool) (newEpoch, activeCount int64) {
	if !skipEviction {
		cutoffMs := time.Now().UnixMilli() - account.GetUserQuotaIdleTimeout().Milliseconds()
		if _, err := s.cache.ZRemIdleUsers(ctx, account.ID, cutoffMs); err != nil {
			logger.L().Error("user_quota.redis_error",
				zap.String("operation", "ZRemIdleUsers"),
				zap.Int64("account_id", account.ID),
				zap.Error(err),
			)
			return 0, 0
		}
	}

	var err error
	activeCount, err = s.cache.ZCardActive(ctx, account.ID)
	if err != nil {
		logger.L().Error("user_quota.redis_error",
			zap.String("operation", "ZCardActive"),
			zap.Int64("account_id", account.ID),
			zap.Error(err),
		)
		return 0, 0
	}
	if activeCount == 0 {
		s.mu.Lock()
		delete(s.activeAccounts, account.ID)
		s.mu.Unlock()
		_ = s.cache.DelMeta(ctx, account.ID)
		return 0, 0
	}

	// On window reset, cost is 0 — the new window has no spending yet.
	// Calling the getter would return stale cached cost from the previous window.
	var currentWindowCost float64
	isWindowReset := len(windowReset) > 0 && windowReset[0]
	if !isWindowReset {
		currentWindowCost = s.windowCostGetter(ctx, account)
	}
	var limit float64
	if s.windowLimitGetter != nil {
		limit = s.windowLimitGetter(ctx, account)
	} else {
		limit = account.GetWindowCostLimit()
	}
	if limit <= 0 {
		// Fail-open: no effective limit could be resolved (dynamic bootstrap after
		// window reset, stale in-memory account snapshot, etc.). Writing perUserLimit=0
		// would block all users. Leave the last valid epoch intact instead.
		logger.L().Warn("user_quota.limit_unknown_failopen",
			zap.Int64("account_id", account.ID),
			zap.Int64("active_users", activeCount),
		)
		return 0, activeCount
	}
	remaining := limit - currentWindowCost
	if remaining < 0 {
		remaining = 0
	}

	// Deduct sticky reserve from normal budget before splitting.
	// perUserLimit covers the green zone only; perUserStickyReserve is the
	// additional yellow-zone buffer. Without the deduction, the sum of all
	// users' max spend (N × (perUserLimit + perUserStickyReserve)) would
	// exceed remaining by the full sticky reserve amount.
	cappedReserve := GetCappedStickyReserve(limit, account.GetWindowCostStickyReserve())
	if cappedReserve > remaining {
		cappedReserve = remaining // window nearly exhausted: shrink sticky buffer to fit
	}
	normalRemaining := remaining - cappedReserve
	perUserLimit := normalRemaining / float64(activeCount)
	perUserStickyReserve := cappedReserve / float64(activeCount)

	newEpoch, err = s.cache.BumpEpochAndSetMeta(ctx, account.ID, perUserLimit, perUserStickyReserve, activeCount)
	if err != nil {
		logger.L().Error("user_quota.redis_error",
			zap.String("operation", "BumpEpochAndSetMeta"),
			zap.Int64("account_id", account.ID),
			zap.Error(err),
		)
		return 0, 0
	}

	// Record the current window start so future calls can detect a window reset.
	currentWindowStartMs := account.GetCurrentWindowStartTime().UnixMilli()
	s.mu.Lock()
	if state, ok := s.activeAccounts[account.ID]; ok {
		state.lastWindowStartMs = currentWindowStartMs
	}
	s.mu.Unlock()

	logger.L().Info("user_quota.recalculation",
		zap.Int64("account_id", account.ID),
		zap.Int64("epoch", newEpoch),
		zap.Int64("active_users", activeCount),
		zap.Float64("remaining", remaining),
		zap.Float64("per_user_limit", perUserLimit),
		zap.Float64("per_user_sticky_reserve", perUserStickyReserve),
	)
	return newEpoch, activeCount
}

// CheckUserRPM checks per-user RPM limit for an account.
// Returns allowed=true when the feature is disabled, Redis errors occur (fail-open),
// or the user is within their per-user RPM allocation.
func (s *userQuotaService) CheckUserRPM(ctx context.Context, account *Account, userID int64, isSticky bool) (bool, string) {
	if !account.IsUserRPMEnabled() {
		return true, "disabled"
	}
	baseRPM := account.GetBaseRPM()
	if baseRPM <= 0 {
		return true, "no_base_rpm"
	}

	activeCount, err := s.cache.ZCardActive(ctx, account.ID)
	if err != nil {
		logger.L().Error("user_rpm.redis_error",
			zap.String("operation", "ZCardActive"),
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return true, "redis_error"
	}
	if activeCount <= 0 {
		logger.L().Warn("user_rpm.active_count_zero_failopen",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
		)
		return true, "active_count_zero"
	}

	userRPM, err := s.rpmCache.GetUserAccountRPM(ctx, account.ID, userID)
	if err != nil {
		logger.L().Error("user_rpm.redis_error",
			zap.String("operation", "GetUserAccountRPM"),
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return true, "redis_error"
	}

	perUserBase := baseRPM / int(activeCount)
	if perUserBase < 1 {
		perUserBase = 1
	}

	stickyBuffer := account.GetRPMStickyBuffer()
	perUserBuffer := 0
	if stickyBuffer > 0 {
		perUserBuffer = (stickyBuffer + int(activeCount) - 1) / int(activeCount) // ceil division
	}

	zone := CheckRPMZone(userRPM, perUserBase, perUserBuffer, account.GetRPMStrategy())
	switch zone {
	case WindowCostSchedulable:
		return true, "green"
	case WindowCostStickyOnly:
		if isSticky {
			return true, "yellow_sticky"
		}
		logger.L().Warn("user_rpm.check_blocked",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Int("user_rpm", userRPM),
			zap.Int("per_user_base", perUserBase),
			zap.String("zone", "yellow_non_sticky"),
		)
		return false, "yellow_non_sticky"
	case WindowCostNotSchedulable:
		logger.L().Warn("user_rpm.check_blocked",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Int("user_rpm", userRPM),
			zap.Int("per_user_base", perUserBase),
			zap.String("zone", "red"),
		)
		return false, "red"
	}
	return true, "unknown"
}

// IncrementUserAccountRPM increments the per-user-per-account RPM counter.
func (s *userQuotaService) IncrementUserAccountRPM(ctx context.Context, accountID int64, userID int64) {
	if s.rpmCache == nil {
		return
	}
	if _, err := s.rpmCache.IncrementUserAccountRPM(ctx, accountID, userID); err != nil {
		logger.L().Error("user_rpm.increment_failed",
			zap.Int64("account_id", accountID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
	}
}
