package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
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
	cache            UserQuotaCache
	windowCostGetter func(ctx context.Context, account *Account) float64

	mu             sync.RWMutex
	activeAccounts map[int64]*accountQuotaState
}

// NewUserQuotaService creates a new userQuotaService.
// windowCostGetter returns the current window cost for an account (reuses existing cache logic).
func NewUserQuotaService(cache UserQuotaCache, windowCostGetter func(ctx context.Context, account *Account) float64) UserQuotaChecker {
	return &userQuotaService{
		cache:            cache,
		windowCostGetter: windowCostGetter,
		activeAccounts:   make(map[int64]*accountQuotaState),
	}
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

		currentWindowStartMs := account.GetCurrentWindowStartTime().UnixMilli()
		windowChanged := state.lastWindowStartMs > 0 && currentWindowStartMs != state.lastWindowStartMs

		if len(removed) > 0 || windowChanged {
			if windowChanged {
				logger.L().Info("user_quota.window_reset_detected",
					zap.Int64("account_id", account.ID),
					zap.String("trigger", "cleanup_tick"),
				)
			}
			s.recalculateQuotas(ctx, account, true)
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
		return true, "disabled"
	}

	epoch, perUserLimit, perUserStickyReserve, userCost, _, err := s.cache.GetQuotaCheckData(ctx, account.ID, userID)
	if err != nil {
		logger.L().Error("user_quota.redis_error",
			zap.String("operation", "GetQuotaCheckData"),
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return true, "redis_error"
	}
	if epoch == 0 {
		return true, "no_epoch"
	}

	if userCost < perUserLimit {
		logger.L().Debug("user_quota.check_allowed",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Float64("user_cost", userCost),
			zap.Float64("per_user_limit", perUserLimit),
			zap.String("zone", "green"),
		)
		return true, "green"
	}

	if userCost < perUserLimit+perUserStickyReserve {
		if isSticky {
			logger.L().Debug("user_quota.check_allowed",
				zap.Int64("account_id", account.ID),
				zap.Int64("user_id", userID),
				zap.Float64("user_cost", userCost),
				zap.Float64("per_user_limit", perUserLimit),
				zap.String("zone", "yellow_sticky"),
			)
			return true, "yellow_sticky"
		}
		logger.L().Warn("user_quota.check_blocked",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Float64("user_cost", userCost),
			zap.Float64("per_user_limit", perUserLimit),
			zap.String("zone", "yellow_non_sticky"),
		)
		return false, "yellow_non_sticky"
	}

	logger.L().Warn("user_quota.check_blocked",
		zap.Int64("account_id", account.ID),
		zap.Int64("user_id", userID),
		zap.Float64("user_cost", userCost),
		zap.Float64("per_user_limit", perUserLimit),
		zap.String("zone", "red"),
	)
	return false, "red"
}

// RegisterActivity marks the user as active. Triggers recalculation on first appearance
// or when the upstream 5h billing window has reset since the last recalculation.
func (s *userQuotaService) RegisterActivity(ctx context.Context, account *Account, userID int64) {
	if !account.IsUserQuotaEnabled() {
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

	currentWindowStartMs := account.GetCurrentWindowStartTime().UnixMilli()

	s.mu.Lock()
	state, exists := s.activeAccounts[account.ID]
	windowChanged := false
	if !exists {
		state = &accountQuotaState{
			account:           account,
			lastWindowStartMs: currentWindowStartMs,
		}
		s.activeAccounts[account.ID] = state
	} else {
		state.account = account
		if state.lastWindowStartMs > 0 && state.lastWindowStartMs != currentWindowStartMs {
			windowChanged = true
		}
	}
	s.mu.Unlock()

	if isNew || windowChanged {
		if windowChanged {
			logger.L().Info("user_quota.window_reset_detected",
				zap.Int64("account_id", account.ID),
				zap.String("trigger", "register_activity"),
			)
		}
		newEpoch, activeCount := s.recalculateQuotas(ctx, account, false)
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
	logger.L().Info("user_quota.cost_incremented",
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
	s.mu.RLock()
	_, exists := s.activeAccounts[account.ID]
	s.mu.RUnlock()
	if !exists {
		return
	}
	s.mu.Lock()
	if state, ok := s.activeAccounts[account.ID]; ok {
		state.account = account
	}
	s.mu.Unlock()
	s.recalculateQuotas(ctx, account, false)
	logger.L().Info("user_quota.account_updated",
		zap.Int64("account_id", account.ID),
	)
}

// recalculateQuotas bumps epoch and redistributes remaining budget equally among active users.
// Returns (newEpoch, activeCount). Returns (0, 0) on error or when no active users remain.
func (s *userQuotaService) recalculateQuotas(ctx context.Context, account *Account, skipEviction bool) (newEpoch, activeCount int64) {
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

	currentWindowCost := s.windowCostGetter(ctx, account)
	limit := account.GetWindowCostLimit()
	remaining := limit - currentWindowCost
	if remaining < 0 {
		remaining = 0
	}

	perUserLimit := remaining / float64(activeCount)
	perUserStickyReserve := account.GetWindowCostStickyReserve() / float64(activeCount)

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
