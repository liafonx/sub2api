package service

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

type mockUserQuotaCache struct {
	mu sync.Mutex

	// ZAddActivity state
	activeUsers map[int64]map[int64]int64 // accountID -> {userID -> scoreMs}
	addErr      error

	// ZRemIdleUsers
	remErr error

	// ZCardActive
	cardErr error

	// HIncrByEpoch
	epochCounters map[int64]int64 // accountID -> epoch
	incrEpochErr  error

	// HSetMeta / HGetMeta
	meta       map[int64]quotaMetaData // accountID -> meta
	setMetaErr error
	getMetaErr error

	// GetQuotaCheckData
	getQuotaCheckDataErr error
	// override: when set, GetQuotaCheckData returns these values directly
	quotaCheckOverride *quotaCheckResult

	// IncrByFloatCost / GetUserCost
	costs       map[string]float64 // "accountID:epoch:userID" -> cost
	incrCostErr error
	getCostErr  error

	// DelMeta
	deletedMeta map[int64]bool
	delMetaErr  error

	// call tracking
	calls []string
}

type quotaMetaData struct {
	epoch                int64
	perUserLimit         float64
	perUserStickyReserve float64
	activeCount          int64
}

type quotaCheckResult struct {
	epoch                int64
	perUserLimit         float64
	perUserStickyReserve float64
	userCost             float64
}

func newTestAccount(id int64, extra map[string]any) *Account {
	return &Account{
		ID:       id,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    extra,
	}
}

func newMock() *mockUserQuotaCache {
	return &mockUserQuotaCache{
		activeUsers:   make(map[int64]map[int64]int64),
		epochCounters: make(map[int64]int64),
		meta:          make(map[int64]quotaMetaData),
		costs:         make(map[string]float64),
		deletedMeta:   make(map[int64]bool),
	}
}

func (m *mockUserQuotaCache) recordCall(name string) {
	m.calls = append(m.calls, name)
}

func (m *mockUserQuotaCache) ZAddActivity(_ context.Context, accountID int64, userID int64, nowMs int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("ZAddActivity")
	users := m.activeUsers[accountID]
	if users == nil {
		users = make(map[int64]int64)
		m.activeUsers[accountID] = users
	}
	_, exists := users[userID]
	users[userID] = nowMs
	return !exists, m.addErr
}

func (m *mockUserQuotaCache) ZRemIdleUsers(_ context.Context, accountID int64, cutoffMs int64) ([]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("ZRemIdleUsers")
	if m.remErr != nil {
		return nil, m.remErr
	}

	users := m.activeUsers[accountID]
	if users == nil {
		return nil, nil
	}

	var removed []int64
	for userID, score := range users {
		if score < cutoffMs {
			delete(users, userID)
			removed = append(removed, userID)
		}
	}
	if len(users) == 0 {
		delete(m.activeUsers, accountID)
	}
	return removed, nil
}

func (m *mockUserQuotaCache) ZCardActive(_ context.Context, accountID int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("ZCardActive")
	if m.cardErr != nil {
		return 0, m.cardErr
	}
	return int64(len(m.activeUsers[accountID])), nil
}

func (m *mockUserQuotaCache) HIncrByEpoch(_ context.Context, accountID int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("HIncrByEpoch")
	if m.incrEpochErr != nil {
		return 0, m.incrEpochErr
	}

	m.epochCounters[accountID]++
	meta := m.meta[accountID]
	meta.epoch = m.epochCounters[accountID]
	m.meta[accountID] = meta
	return m.epochCounters[accountID], nil
}

func (m *mockUserQuotaCache) HSetMeta(_ context.Context, accountID int64, epoch int64, perUserLimit float64, perUserStickyReserve float64, activeCount int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("HSetMeta")
	if m.setMetaErr != nil {
		return m.setMetaErr
	}

	m.meta[accountID] = quotaMetaData{
		epoch:                epoch,
		perUserLimit:         perUserLimit,
		perUserStickyReserve: perUserStickyReserve,
		activeCount:          activeCount,
	}
	return nil
}

func (m *mockUserQuotaCache) HGetMeta(_ context.Context, accountID int64) (int64, float64, float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("HGetMeta")
	if m.getMetaErr != nil {
		return 0, 0, 0, m.getMetaErr
	}

	meta, ok := m.meta[accountID]
	if !ok {
		return 0, 0, 0, nil
	}
	return meta.epoch, meta.perUserLimit, meta.perUserStickyReserve, nil
}

func (m *mockUserQuotaCache) GetQuotaCheckData(ctx context.Context, accountID int64, userID int64) (int64, float64, float64, float64, error) {
	m.mu.Lock()
	m.recordCall("GetQuotaCheckData")
	err := m.getQuotaCheckDataErr
	override := m.quotaCheckOverride
	m.mu.Unlock()

	if err != nil {
		return 0, 0, 0, 0, err
	}
	if override != nil {
		return override.epoch, override.perUserLimit, override.perUserStickyReserve, override.userCost, nil
	}

	epoch, perUserLimit, perUserStickyReserve, err := m.HGetMeta(ctx, accountID)
	if err != nil || epoch == 0 {
		return epoch, perUserLimit, perUserStickyReserve, 0, err
	}
	userCost, err := m.GetUserCost(ctx, accountID, epoch, userID)
	return epoch, perUserLimit, perUserStickyReserve, userCost, err
}

func (m *mockUserQuotaCache) IncrByFloatCost(_ context.Context, accountID int64, epoch int64, userID int64, delta float64) (float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("IncrByFloatCost")
	if m.incrCostErr != nil {
		return 0, m.incrCostErr
	}

	key := costKey(accountID, epoch, userID)
	m.costs[key] += delta
	return m.costs[key], nil
}

func (m *mockUserQuotaCache) GetUserCost(_ context.Context, accountID int64, epoch int64, userID int64) (float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("GetUserCost")
	if m.getCostErr != nil {
		return 0, m.getCostErr
	}
	return m.costs[costKey(accountID, epoch, userID)], nil
}

func (m *mockUserQuotaCache) DelMeta(_ context.Context, accountID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("DelMeta")
	if m.delMetaErr != nil {
		return m.delMetaErr
	}

	m.deletedMeta[accountID] = true
	delete(m.meta, accountID)
	return nil
}

func costKey(accountID int64, epoch int64, userID int64) string {
	return fmt.Sprintf("%d:%d:%d", accountID, epoch, userID)
}

func assertFloatEqual(t *testing.T, got float64, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.001 {
		t.Fatalf("got %.3f want %.3f", got, want)
	}
}

func enabledExtra(limit float64, reserve float64) map[string]any {
	return map[string]any{
		"user_quota_enabled":         true,
		"window_cost_limit":          limit,
		"window_cost_sticky_reserve": reserve,
	}
}

func TestCheckUserQuota_Disabled(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	allowed, reason := svc.CheckUserQuota(ctx, newTestAccount(1, nil), 10, false)
	if !allowed || reason != "disabled" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
	if len(mock.calls) != 0 {
		t.Fatalf("expected no cache calls, got %v", mock.calls)
	}
}

func TestCheckUserQuota_NoEpoch(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, false)
	if !allowed || reason != "no_epoch" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

func TestCheckUserQuota_GreenZone(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.quotaCheckOverride = &quotaCheckResult{
		epoch:                1,
		perUserLimit:         10,
		perUserStickyReserve: 5,
		userCost:             9.5,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, false)
	if !allowed || reason != "green" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

func TestCheckUserQuota_YellowSticky(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.quotaCheckOverride = &quotaCheckResult{
		epoch:                1,
		perUserLimit:         10,
		perUserStickyReserve: 5,
		userCost:             12,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, true)
	if !allowed || reason != "yellow_sticky" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

func TestCheckUserQuota_YellowNonSticky(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.quotaCheckOverride = &quotaCheckResult{
		epoch:                1,
		perUserLimit:         10,
		perUserStickyReserve: 5,
		userCost:             12,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, false)
	if allowed || reason != "yellow_non_sticky" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

func TestCheckUserQuota_RedZone(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.quotaCheckOverride = &quotaCheckResult{
		epoch:                1,
		perUserLimit:         10,
		perUserStickyReserve: 5,
		userCost:             15,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, true)
	if allowed || reason != "red" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

func TestCheckUserQuota_RedisError_FailOpen(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.getQuotaCheckDataErr = errors.New("redis down")
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, false)
	if !allowed || reason != "redis_error" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

func TestCheckUserQuota_BoundaryExactLimit(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.quotaCheckOverride = &quotaCheckResult{
		epoch:                1,
		perUserLimit:         10,
		perUserStickyReserve: 5,
		userCost:             10,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, true)
	if !allowed || reason != "yellow_sticky" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

func TestRegisterActivity_Disabled(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	svc.RegisterActivity(ctx, newTestAccount(1, nil), 10)
	if len(mock.activeUsers) != 0 {
		t.Fatalf("expected no activity write, got %v", mock.activeUsers)
	}
}

func TestRegisterActivity_NewUser(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	svc.RegisterActivity(ctx, account, 10)

	if mock.epochCounters[account.ID] != 1 {
		t.Fatalf("epoch=%d want 1", mock.epochCounters[account.ID])
	}
	meta := mock.meta[account.ID]
	if meta.epoch != 1 {
		t.Fatalf("meta epoch=%d want 1", meta.epoch)
	}
}

func TestRegisterActivity_ExistingUser(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	mock.activeUsers[account.ID] = map[int64]int64{10: 1}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	svc.RegisterActivity(ctx, account, 10)

	if mock.epochCounters[account.ID] != 0 {
		t.Fatalf("epoch=%d want 0", mock.epochCounters[account.ID])
	}
	if mock.activeUsers[account.ID][10] == 1 {
		t.Fatalf("expected activity score update")
	}
}

func TestRegisterActivity_RedisError(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.addErr = errors.New("redis down")
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	account := newTestAccount(1, enabledExtra(50, 10))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	svc.RegisterActivity(ctx, account, 10)

	if mock.epochCounters[account.ID] != 0 {
		t.Fatalf("epoch=%d want 0", mock.epochCounters[account.ID])
	}
}

func TestIncrementUserCost_Normal(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.meta[7] = quotaMetaData{epoch: 5}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	svc.IncrementUserCost(ctx, 7, 9, 2.5)

	assertFloatEqual(t, mock.costs["7:5:9"], 2.5)
}

func TestIncrementUserCost_ZeroCost(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.meta[7] = quotaMetaData{epoch: 5}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	svc.IncrementUserCost(ctx, 7, 9, 0)

	if len(mock.costs) != 0 {
		t.Fatalf("expected empty costs, got %v", mock.costs)
	}
}

func TestIncrementUserCost_NoEpoch(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	svc.IncrementUserCost(ctx, 7, 9, 2.5)

	if len(mock.costs) != 0 {
		t.Fatalf("expected empty costs, got %v", mock.costs)
	}
}

func TestIncrementUserCost_NegativeCost(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.meta[7] = quotaMetaData{epoch: 5}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	svc.IncrementUserCost(ctx, 7, 9, -1)

	if len(mock.costs) != 0 {
		t.Fatalf("expected empty costs, got %v", mock.costs)
	}
}

func TestRecalculate_EqualSplit(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{
		1: now,
		2: now,
		3: now,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 20 })
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	meta := mock.meta[account.ID]
	if meta.epoch != 1 {
		t.Fatalf("epoch=%d want 1", meta.epoch)
	}
	assertFloatEqual(t, meta.perUserLimit, 10)
	assertFloatEqual(t, meta.perUserStickyReserve, 10.0/3.0)
}

func TestRecalculate_ZeroRemaining(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{
		1: now,
		2: now,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 80 })
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	meta := mock.meta[account.ID]
	assertFloatEqual(t, meta.perUserLimit, 0)
}

func TestRecalculate_NoActiveUsers(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = account

	impl.recalculateQuotas(ctx, account, true)

	if !mock.deletedMeta[account.ID] {
		t.Fatalf("expected meta deletion")
	}
	if mock.epochCounters[account.ID] != 0 {
		t.Fatalf("epoch=%d want 0", mock.epochCounters[account.ID])
	}
}

func TestRecalculate_EpochBump(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now}
	mock.epochCounters[account.ID] = 3
	mock.meta[account.ID] = quotaMetaData{epoch: 3}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	if mock.meta[account.ID].epoch != 4 {
		t.Fatalf("epoch=%d want 4", mock.meta[account.ID].epoch)
	}
}

func TestRecalculate_StickyReserveSplit(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{
		1: now,
		2: now,
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	assertFloatEqual(t, mock.meta[account.ID].perUserStickyReserve, 5)
}

func TestCleanup_RemovesIdleUsers(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, map[string]any{
		"window_cost_limit":          50.0,
		"window_cost_sticky_reserve": 10.0,
		"user_quota_idle_timeout":    60,
	})
	now := time.Now()
	mock.activeUsers[account.ID] = map[int64]int64{
		1: now.Add(-2 * time.Minute).UnixMilli(),
		2: now.UnixMilli(),
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = account

	impl.runCleanup(ctx)

	if _, ok := mock.activeUsers[account.ID][1]; ok {
		t.Fatalf("idle user was not removed")
	}
	if _, ok := mock.activeUsers[account.ID][2]; !ok {
		t.Fatalf("active user was removed")
	}
	if mock.epochCounters[account.ID] != 1 {
		t.Fatalf("epoch=%d want 1", mock.epochCounters[account.ID])
	}
}

func TestCleanup_NoIdleUsers(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, map[string]any{
		"window_cost_limit":       50.0,
		"user_quota_idle_timeout": 60,
	})
	mock.activeUsers[account.ID] = map[int64]int64{
		1: time.Now().UnixMilli(),
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = account

	impl.runCleanup(ctx)

	if mock.epochCounters[account.ID] != 0 {
		t.Fatalf("epoch=%d want 0", mock.epochCounters[account.ID])
	}
}

func TestCleanup_AllUsersIdle(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, map[string]any{
		"window_cost_limit":       50.0,
		"user_quota_idle_timeout": 60,
	})
	mock.activeUsers[account.ID] = map[int64]int64{
		1: time.Now().Add(-2 * time.Minute).UnixMilli(),
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = account

	impl.runCleanup(ctx)

	if !mock.deletedMeta[account.ID] {
		t.Fatalf("expected meta deletion")
	}
}

func TestCleanup_RedisError_Continues(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.remErr = errors.New("redis down")
	account1 := newTestAccount(1, map[string]any{"window_cost_limit": 50.0})
	account2 := newTestAccount(2, map[string]any{"window_cost_limit": 50.0})
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account1.ID] = account1
	impl.activeAccounts[account2.ID] = account2

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	impl.runCleanup(ctx)

	if len(mock.epochCounters) != 0 {
		t.Fatalf("expected no epoch bumps, got %v", mock.epochCounters)
	}
}

func TestConcurrentRegisterActivity(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 })

	var wg sync.WaitGroup
	for userID := int64(1); userID <= 10; userID++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			svc.RegisterActivity(ctx, account, id)
		}(userID)
	}
	wg.Wait()

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.activeUsers[account.ID]) != 10 {
		t.Fatalf("users=%d want 10", len(mock.activeUsers[account.ID]))
	}
}
