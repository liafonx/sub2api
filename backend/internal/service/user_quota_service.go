package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// UserQuotaChecker is the interface for per-user dynamic quota enforcement.
// All operations fail-open: returns allowed=true on Redis errors or when disabled.
type UserQuotaChecker interface {
	CheckUserQuota(ctx context.Context, account *Account, userID int64, isSticky bool) (allowed bool, reason string)
	RegisterActivity(ctx context.Context, account *Account, userID int64)
	IncrementUserCost(ctx context.Context, accountID int64, userID int64, standardCost float64)
}

// UserQuotaCache defines the Redis operations for the user quota plugin.
type UserQuotaCache interface {
	// ZAddActivity adds/updates user activity (score=nowMs). Returns true if user was new.
	ZAddActivity(ctx context.Context, accountID int64, userID int64, nowMs int64) (isNew bool, err error)
	// ZRemIdleUsers removes members with score < cutoffMs, returns removed userIDs.
	ZRemIdleUsers(ctx context.Context, accountID int64, cutoffMs int64) ([]int64, error)
	// ZCardActive returns count of active users.
	ZCardActive(ctx context.Context, accountID int64) (int64, error)
	// HIncrByEpoch atomically increments epoch, returns new value.
	HIncrByEpoch(ctx context.Context, accountID int64) (int64, error)
	// HSetMeta writes quota metadata (must be called after HIncrByEpoch with the new epoch).
	HSetMeta(ctx context.Context, accountID int64, epoch int64, perUserLimit float64, perUserStickyReserve float64, activeCount int64) error
	// HGetMeta reads quota metadata. epoch=0 means not initialized.
	HGetMeta(ctx context.Context, accountID int64) (epoch int64, perUserLimit float64, perUserStickyReserve float64, err error)
	// GetQuotaCheckData fetches quota metadata and user cost in a single Lua script (1 RTT).
	// Returns epoch=0 if meta is not initialized.
	GetQuotaCheckData(ctx context.Context, accountID int64, userID int64) (epoch int64, perUserLimit float64, perUserStickyReserve float64, userCost float64, err error)
	// IncrByFloatCost atomically adds delta to user cost, returns new total.
	IncrByFloatCost(ctx context.Context, accountID int64, epoch int64, userID int64, delta float64) (float64, error)
	// GetUserCost reads cost for a user in the given epoch. Returns 0 if not set.
	GetUserCost(ctx context.Context, accountID int64, epoch int64, userID int64) (float64, error)
	// DelMeta removes the meta hash (when no active users remain).
	DelMeta(ctx context.Context, accountID int64) error
}

// userQuotaService implements UserQuotaChecker.
type userQuotaService struct {
	cache            UserQuotaCache
	windowCostGetter func(ctx context.Context, account *Account) float64

	mu             sync.RWMutex
	activeAccounts map[int64]*Account
}

// NewUserQuotaService creates a new userQuotaService.
// windowCostGetter returns the current window cost for an account (reuses existing cache logic).
func NewUserQuotaService(cache UserQuotaCache, windowCostGetter func(ctx context.Context, account *Account) float64) UserQuotaChecker {
	return &userQuotaService{
		cache:            cache,
		windowCostGetter: windowCostGetter,
		activeAccounts:   make(map[int64]*Account),
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
	accounts := make([]*Account, 0, len(s.activeAccounts))
	for _, acc := range s.activeAccounts {
		accounts = append(accounts, acc)
	}
	s.mu.RUnlock()

	totalRemoved := 0

	for _, account := range accounts {
		cutoffMs := time.Now().UnixMilli() - account.GetUserQuotaIdleTimeout().Milliseconds()
		removed, err := s.cache.ZRemIdleUsers(ctx, account.ID, cutoffMs)
		if err != nil {
			zap.L().Error("user_quota.redis_error",
				zap.String("operation", "ZRemIdleUsers"),
				zap.Int64("account_id", account.ID),
				zap.Error(err),
			)
			continue
		}
		for _, uid := range removed {
			zap.L().Info("user_quota.user_released",
				zap.Int64("account_id", account.ID),
				zap.Int64("user_id", uid),
				zap.String("reason", "idle"),
			)
			totalRemoved++
		}

		count, err := s.cache.ZCardActive(ctx, account.ID)
		if err != nil {
			continue
		}
		if count == 0 {
			s.mu.Lock()
			delete(s.activeAccounts, account.ID)
			s.mu.Unlock()
			_ = s.cache.DelMeta(ctx, account.ID)
			continue
		}
		if len(removed) > 0 {
			s.recalculateQuotas(ctx, account, true)
		}
	}

	zap.L().Debug("user_quota.cleanup_tick",
		zap.Int("accounts_checked", len(accounts)),
		zap.Int("users_removed", totalRemoved),
	)
}

// CheckUserQuota returns whether the user may proceed on this account.
func (s *userQuotaService) CheckUserQuota(ctx context.Context, account *Account, userID int64, isSticky bool) (bool, string) {
	if !account.IsUserQuotaEnabled() {
		return true, "disabled"
	}

	epoch, perUserLimit, perUserStickyReserve, userCost, err := s.cache.GetQuotaCheckData(ctx, account.ID, userID)
	if err != nil {
		zap.L().Error("user_quota.redis_error",
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
		zap.L().Debug("user_quota.check_allowed",
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
			zap.L().Debug("user_quota.check_allowed",
				zap.Int64("account_id", account.ID),
				zap.Int64("user_id", userID),
				zap.Float64("user_cost", userCost),
				zap.Float64("per_user_limit", perUserLimit),
				zap.String("zone", "yellow_sticky"),
			)
			return true, "yellow_sticky"
		}
		zap.L().Warn("user_quota.check_blocked",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Float64("user_cost", userCost),
			zap.Float64("per_user_limit", perUserLimit),
			zap.String("zone", "yellow_non_sticky"),
		)
		return false, "yellow_non_sticky"
	}

	zap.L().Warn("user_quota.check_blocked",
		zap.Int64("account_id", account.ID),
		zap.Int64("user_id", userID),
		zap.Float64("user_cost", userCost),
		zap.Float64("per_user_limit", perUserLimit),
		zap.String("zone", "red"),
	)
	return false, "red"
}

// RegisterActivity marks the user as active. Triggers recalculation on first appearance.
func (s *userQuotaService) RegisterActivity(ctx context.Context, account *Account, userID int64) {
	if !account.IsUserQuotaEnabled() {
		return
	}

	nowMs := time.Now().UnixMilli()
	isNew, err := s.cache.ZAddActivity(ctx, account.ID, userID, nowMs)
	if err != nil {
		zap.L().Error("user_quota.redis_error",
			zap.String("operation", "ZAddActivity"),
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return
	}

	s.mu.RLock()
	existing := s.activeAccounts[account.ID]
	s.mu.RUnlock()
	if existing != account {
		s.mu.Lock()
		s.activeAccounts[account.ID] = account
		s.mu.Unlock()
	}

	if isNew {
		count, _ := s.cache.ZCardActive(ctx, account.ID)
		zap.L().Info("user_quota.user_joined",
			zap.Int64("account_id", account.ID),
			zap.Int64("user_id", userID),
			zap.Int64("new_active_count", count),
		)
		s.recalculateQuotas(ctx, account, false)
	}
}

// IncrementUserCost adds standardCost to the user's per-epoch counter.
func (s *userQuotaService) IncrementUserCost(ctx context.Context, accountID int64, userID int64, standardCost float64) {
	if standardCost <= 0 {
		return
	}
	epoch, _, _, err := s.cache.HGetMeta(ctx, accountID)
	if err != nil || epoch == 0 {
		return
	}
	newTotal, err := s.cache.IncrByFloatCost(ctx, accountID, epoch, userID, standardCost)
	if err != nil {
		zap.L().Error("user_quota.redis_error",
			zap.String("operation", "IncrByFloatCost"),
			zap.Int64("account_id", accountID),
			zap.Int64("user_id", userID),
			zap.Error(err),
		)
		return
	}
	zap.L().Debug("user_quota.cost_incremented",
		zap.Int64("account_id", accountID),
		zap.Int64("user_id", userID),
		zap.Int64("epoch", epoch),
		zap.Float64("increment_cost", standardCost),
		zap.Float64("new_total", newTotal),
	)
}

// recalculateQuotas bumps epoch and redistributes remaining budget equally.
func (s *userQuotaService) recalculateQuotas(ctx context.Context, account *Account, skipEviction bool) {
	cutoffMs := time.Now().UnixMilli() - account.GetUserQuotaIdleTimeout().Milliseconds()
	if !skipEviction {
		if _, err := s.cache.ZRemIdleUsers(ctx, account.ID, cutoffMs); err != nil {
			zap.L().Error("user_quota.redis_error",
				zap.String("operation", "ZRemIdleUsers"),
				zap.Int64("account_id", account.ID),
				zap.Error(err),
			)
			return
		}
	}

	activeCount, err := s.cache.ZCardActive(ctx, account.ID)
	if err != nil {
		zap.L().Error("user_quota.redis_error",
			zap.String("operation", "ZCardActive"),
			zap.Int64("account_id", account.ID),
			zap.Error(err),
		)
		return
	}
	if activeCount == 0 {
		s.mu.Lock()
		delete(s.activeAccounts, account.ID)
		s.mu.Unlock()
		_ = s.cache.DelMeta(ctx, account.ID)
		return
	}

	currentWindowCost := s.windowCostGetter(ctx, account)
	limit := account.GetWindowCostLimit()
	remaining := limit - currentWindowCost
	if remaining < 0 {
		remaining = 0
	}

	perUserLimit := remaining / float64(activeCount)
	perUserStickyReserve := account.GetWindowCostStickyReserve() / float64(activeCount)

	newEpoch, err := s.cache.HIncrByEpoch(ctx, account.ID)
	if err != nil {
		zap.L().Error("user_quota.redis_error",
			zap.String("operation", "HIncrByEpoch"),
			zap.Int64("account_id", account.ID),
			zap.Error(err),
		)
		return
	}
	if err := s.cache.HSetMeta(ctx, account.ID, newEpoch, perUserLimit, perUserStickyReserve, activeCount); err != nil {
		zap.L().Error("user_quota.redis_error",
			zap.String("operation", "HSetMeta"),
			zap.Int64("account_id", account.ID),
			zap.Error(err),
		)
		return
	}

	zap.L().Info("user_quota.recalculation",
		zap.Int64("account_id", account.ID),
		zap.Int64("epoch", newEpoch),
		zap.Int64("active_users", activeCount),
		zap.Float64("remaining", remaining),
		zap.Float64("per_user_limit", perUserLimit),
		zap.Float64("per_user_sticky_reserve", perUserStickyReserve),
	)
}
