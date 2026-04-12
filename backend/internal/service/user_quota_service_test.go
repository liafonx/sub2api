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

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

type mockUserQuotaCache struct {
	mu sync.Mutex

	// ZAddActivity state
	activeUsers map[int64]map[int64]int64 // accountID -> {userID -> scoreMs}
	addErr      error

	// ZRemIdleUsers
	remErr error

	// ZCardActive
	cardErr error

	// BumpEpochAndSetMeta
	epochCounters map[int64]int64 // accountID -> epoch
	bumpMetaErr   error

	// HGetMeta
	meta       map[int64]quotaMetaData // accountID -> meta
	getMetaErr error

	// GetQuotaCheckData
	getQuotaCheckDataErr error
	// override: when set, GetQuotaCheckData returns these values directly
	quotaCheckOverride *quotaCheckResult

	// AtomicIncrCost / GetUserCost
	costs             map[string]float64 // "accountID:epoch:userID" -> cost
	atomicIncrCostErr error
	getCostErr        error

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

// mockRPMCache implements RPMCache for testing.
type mockRPMCache struct {
	userAccountRPM map[string]int // "accountID:userID" -> count
	rpmErr         error
}

func (m *mockRPMCache) IncrementRPM(_ context.Context, _ int64) (int, error) { return 0, nil }
func (m *mockRPMCache) GetRPM(_ context.Context, _ int64) (int, error)       { return 0, nil }
func (m *mockRPMCache) GetRPMBatch(_ context.Context, _ []int64) (map[int64]int, error) {
	return nil, nil
}
func (m *mockRPMCache) IncrementUserRPM(_ context.Context, _ int64) (int, error) { return 0, nil }
func (m *mockRPMCache) GetUserRPM(_ context.Context, _ int64) (int, error)       { return 0, nil }
func (m *mockRPMCache) GetUserRPMBatch(_ context.Context, _ []int64) (map[int64]int, error) {
	return nil, nil
}
func (m *mockRPMCache) GetUserAccountRPM(_ context.Context, accountID int64, userID int64) (int, error) {
	if m.rpmErr != nil {
		return 0, m.rpmErr
	}
	if m.userAccountRPM == nil {
		return 0, nil
	}
	key := fmt.Sprintf("%d:%d", accountID, userID)
	return m.userAccountRPM[key], nil
}
func (m *mockRPMCache) IncrementUserAccountRPM(_ context.Context, accountID int64, userID int64) (int, error) {
	if m.rpmErr != nil {
		return 0, m.rpmErr
	}
	if m.userAccountRPM == nil {
		m.userAccountRPM = make(map[string]int)
	}
	key := fmt.Sprintf("%d:%d", accountID, userID)
	m.userAccountRPM[key]++
	return m.userAccountRPM[key], nil
}

func newTestAccount(id int64, extra map[string]any) *Account {
	return &Account{
		ID:       id,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    extra,
	}
}

func newTestAccountWithWindow(id int64, extra map[string]any, windowStart, windowEnd time.Time) *Account {
	return &Account{
		ID:                 id,
		Platform:           PlatformAnthropic,
		Type:               AccountTypeOAuth,
		Extra:              extra,
		SessionWindowStart: &windowStart,
		SessionWindowEnd:   &windowEnd,
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

func (m *mockUserQuotaCache) BumpEpochAndSetMeta(_ context.Context, accountID int64, perUserLimit float64, perUserStickyReserve float64, activeCount int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("BumpEpochAndSetMeta")
	if m.bumpMetaErr != nil {
		return 0, m.bumpMetaErr
	}

	m.epochCounters[accountID]++
	m.meta[accountID] = quotaMetaData{
		epoch:                m.epochCounters[accountID],
		perUserLimit:         perUserLimit,
		perUserStickyReserve: perUserStickyReserve,
		activeCount:          activeCount,
	}
	return m.epochCounters[accountID], nil
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

func (m *mockUserQuotaCache) GetQuotaCheckData(ctx context.Context, accountID int64, userID int64) (int64, float64, float64, float64, int64, error) {
	m.mu.Lock()
	m.recordCall("GetQuotaCheckData")
	err := m.getQuotaCheckDataErr
	override := m.quotaCheckOverride
	m.mu.Unlock()

	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	if override != nil {
		return override.epoch, override.perUserLimit, override.perUserStickyReserve, override.userCost, 0, nil
	}

	epoch, perUserLimit, perUserStickyReserve, err := m.HGetMeta(ctx, accountID)
	if err != nil || epoch == 0 {
		return epoch, perUserLimit, perUserStickyReserve, 0, 0, err
	}
	userCost, err := m.GetUserCost(ctx, accountID, epoch, userID)
	m.mu.Lock()
	activeCount := m.meta[accountID].activeCount
	m.mu.Unlock()
	return epoch, perUserLimit, perUserStickyReserve, userCost, activeCount, err
}

func (m *mockUserQuotaCache) AtomicIncrCost(_ context.Context, accountID int64, userID int64, delta float64) (int64, float64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recordCall("AtomicIncrCost")
	if m.atomicIncrCostErr != nil {
		return 0, 0, m.atomicIncrCostErr
	}

	meta, ok := m.meta[accountID]
	if !ok || meta.epoch == 0 {
		return 0, 0, nil
	}

	key := costKey(accountID, meta.epoch, userID)
	m.costs[key] += delta
	return meta.epoch, m.costs[key], nil
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

func (m *mockUserQuotaCache) GetDisplayMetaBatch(_ context.Context, accountIDs []int64) (map[int64]QuotaDisplayMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make(map[int64]QuotaDisplayMeta, len(accountIDs))
	for _, id := range accountIDs {
		if meta, ok := m.meta[id]; ok {
			result[id] = QuotaDisplayMeta{PerUserLimit: meta.perUserLimit, ActiveCount: meta.activeCount}
		}
	}
	return result, nil
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

// ---------------------------------------------------------------------------
// CheckUserQuota
// ---------------------------------------------------------------------------

func TestCheckUserQuota_Disabled(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	account := newTestAccount(1, enabledExtra(50, 10))

	allowed, reason := svc.CheckUserQuota(ctx, account, 10, true)
	if !allowed || reason != "yellow_sticky" {
		t.Fatalf("allowed=%v reason=%q", allowed, reason)
	}
}

// ---------------------------------------------------------------------------
// RegisterActivity
// ---------------------------------------------------------------------------

func TestRegisterActivity_Disabled(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.RegisterActivity(ctx, newTestAccount(1, nil), 10)
	if len(mock.activeUsers) != 0 {
		t.Fatalf("expected no activity write, got %v", mock.activeUsers)
	}
}

func TestRegisterActivity_NewUser(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	account := newTestAccount(1, enabledExtra(50, 10))

	svc.RegisterActivity(ctx, account, 10)

	if mock.epochCounters[account.ID] <= 0 {
		t.Fatalf("epoch=%d want > 0 (recalculation must produce a positive epoch)", mock.epochCounters[account.ID])
	}
	meta := mock.meta[account.ID]
	if meta.epoch <= 0 {
		t.Fatalf("meta epoch=%d want > 0", meta.epoch)
	}
}

func TestRegisterActivity_ExistingUser(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	mock.activeUsers[account.ID] = map[int64]int64{10: 1}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = &accountQuotaState{account: account, lastWindowStartMs: account.GetCurrentWindowStartTime().UnixMilli()}

	svc.RegisterActivity(ctx, account, 10)

	if mock.epochCounters[account.ID] != 0 {
		t.Fatalf("epoch=%d want 0 (no recalculation for existing user, same window)", mock.epochCounters[account.ID])
	}
	if mock.activeUsers[account.ID][10] == 1 {
		t.Fatalf("expected activity score update")
	}
}

func TestRegisterActivity_RedisError(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.addErr = errors.New("redis down")
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
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

// ---------------------------------------------------------------------------
// IncrementUserCost (AtomicIncrCost)
// ---------------------------------------------------------------------------

func TestIncrementUserCost_Normal(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.meta[7] = quotaMetaData{epoch: 5}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.IncrementUserCost(ctx, 7, 9, 2.5)

	assertFloatEqual(t, mock.costs[costKey(7, 5, 9)], 2.5)
}

func TestIncrementUserCost_ZeroCost(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.meta[7] = quotaMetaData{epoch: 5}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.IncrementUserCost(ctx, 7, 9, 0)

	if len(mock.costs) != 0 {
		t.Fatalf("expected empty costs, got %v", mock.costs)
	}
}

func TestIncrementUserCost_NoEpoch(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.IncrementUserCost(ctx, 7, 9, 2.5)

	if len(mock.costs) != 0 {
		t.Fatalf("expected empty costs, got %v", mock.costs)
	}
}

func TestIncrementUserCost_NegativeCost(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.meta[7] = quotaMetaData{epoch: 5}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.IncrementUserCost(ctx, 7, 9, -1)

	if len(mock.costs) != 0 {
		t.Fatalf("expected empty costs, got %v", mock.costs)
	}
}

// ---------------------------------------------------------------------------
// recalculateQuotas
// ---------------------------------------------------------------------------

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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 20 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	meta := mock.meta[account.ID]
	if meta.epoch <= 0 {
		t.Fatalf("epoch=%d want > 0", meta.epoch)
	}
	// remaining=30-10(reserve)=20, 3 users → perUserLimit=20/3
	assertFloatEqual(t, meta.perUserLimit, 20.0/3.0)
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 80 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	meta := mock.meta[account.ID]
	assertFloatEqual(t, meta.perUserLimit, 0)
}

func TestRecalculate_NoActiveUsers(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = &accountQuotaState{account: account}

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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	if mock.meta[account.ID].epoch <= 3 {
		t.Fatalf("epoch=%d want > 3 (epoch must increase monotonically)", mock.meta[account.ID].epoch)
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	assertFloatEqual(t, mock.meta[account.ID].perUserStickyReserve, 5)
}

// ---------------------------------------------------------------------------
// Cleanup ticker
// ---------------------------------------------------------------------------

func TestCleanup_RemovesIdleUsers(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, map[string]any{
		"window_cost_limit":          50.0,
		"window_cost_sticky_reserve": 10.0,
		"user_quota_enabled":         true,
		"user_quota_idle_timeout":    60,
	})
	now := time.Now()
	mock.activeUsers[account.ID] = map[int64]int64{
		1: now.Add(-2 * time.Minute).UnixMilli(),
		2: now.UnixMilli(),
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = &accountQuotaState{
		account:           account,
		lastWindowStartMs: account.GetCurrentWindowStartTime().UnixMilli(),
	}

	impl.runCleanup(ctx)

	if _, ok := mock.activeUsers[account.ID][1]; ok {
		t.Fatalf("idle user was not removed")
	}
	if _, ok := mock.activeUsers[account.ID][2]; !ok {
		t.Fatalf("active user was removed")
	}
	if mock.epochCounters[account.ID] <= 0 {
		t.Fatalf("epoch=%d want > 0 (recalculation after idle-user removal must produce a positive epoch)", mock.epochCounters[account.ID])
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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = &accountQuotaState{
		account:           account,
		lastWindowStartMs: account.GetCurrentWindowStartTime().UnixMilli(),
	}

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
		"user_quota_enabled":      true,
		"user_quota_idle_timeout": 60,
	})
	mock.activeUsers[account.ID] = map[int64]int64{
		1: time.Now().Add(-2 * time.Minute).UnixMilli(),
	}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = &accountQuotaState{
		account:           account,
		lastWindowStartMs: account.GetCurrentWindowStartTime().UnixMilli(),
	}

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
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account1.ID] = &accountQuotaState{account: account1}
	impl.activeAccounts[account2.ID] = &accountQuotaState{account: account2}

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

// ---------------------------------------------------------------------------
// NotifyAccountUpdated
// ---------------------------------------------------------------------------

func TestNotifyAccountUpdated_ActiveAccount_RecalculatesQuotas(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(100, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now, 2: now}
	mock.epochCounters[account.ID] = 1
	mock.meta[account.ID] = quotaMetaData{epoch: 1, perUserLimit: 50}

	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = &accountQuotaState{account: account}

	updatedAccount := newTestAccount(account.ID, enabledExtra(50, 10))
	svc.NotifyAccountUpdated(ctx, updatedAccount)

	if mock.epochCounters[account.ID] <= 1 {
		t.Fatalf("epoch=%d want > 1 (NotifyAccountUpdated must trigger a recalculation)", mock.epochCounters[account.ID])
	}
	// limit=50, windowCost=0, reserve=10, normalRemaining=40, 2 users → perUserLimit=20
	assertFloatEqual(t, mock.meta[account.ID].perUserLimit, 20)
	if impl.activeAccounts[account.ID].account != updatedAccount {
		t.Fatalf("expected activeAccounts to hold updated account pointer")
	}
}

func TestNotifyAccountUpdated_InactiveAccount_NoOp(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(100, 10))
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.NotifyAccountUpdated(ctx, account)

	if len(mock.calls) != 0 {
		t.Fatalf("expected no cache calls, got %v", mock.calls)
	}
}

func TestNotifyAccountUpdated_QuotaDisabled_NoOp(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, map[string]any{"window_cost_limit": 100.0})
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)
	impl.activeAccounts[account.ID] = &accountQuotaState{account: account}

	svc.NotifyAccountUpdated(ctx, account)

	if len(mock.calls) != 0 {
		t.Fatalf("expected no cache calls, got %v", mock.calls)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentRegisterActivity(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

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

// ---------------------------------------------------------------------------
// New: epoch isolation -- costs do not carry across epochs
// ---------------------------------------------------------------------------

func TestEpochBumpResetsCost(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now}
	mock.epochCounters[account.ID] = 5
	mock.meta[account.ID] = quotaMetaData{epoch: 5, perUserLimit: 30, activeCount: 1}
	// User 1 has $10 cost in epoch 5
	mock.costs[costKey(account.ID, 5, 1)] = 10.0

	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 20 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	// Epoch must have increased past 5
	if mock.meta[account.ID].epoch <= 5 {
		t.Fatalf("epoch=%d want > 5 (epoch must increase monotonically)", mock.meta[account.ID].epoch)
	}
	// Old epoch 5 cost still present
	oldCost, err := mock.GetUserCost(ctx, account.ID, 5, 1)
	if err != nil {
		t.Fatalf("GetUserCost error: %v", err)
	}
	assertFloatEqual(t, oldCost, 10.0)

	// New epoch 6 cost is zero
	newCost, err := mock.GetUserCost(ctx, account.ID, 6, 1)
	if err != nil {
		t.Fatalf("GetUserCost error: %v", err)
	}
	assertFloatEqual(t, newCost, 0.0)

	// GetQuotaCheckData returns userCost=0 (uses epoch 6)
	_, _, _, userCost, _, err := mock.GetQuotaCheckData(ctx, account.ID, 1)
	if err != nil {
		t.Fatalf("GetQuotaCheckData error: %v", err)
	}
	assertFloatEqual(t, userCost, 0.0)
}

func TestCostNotCarriedAcrossEpochs(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now}
	mock.epochCounters[account.ID] = 3
	mock.meta[account.ID] = quotaMetaData{epoch: 3, perUserLimit: 30, activeCount: 1}

	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 20 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	// User 1 accumulates $7 in epoch 3
	svc.IncrementUserCost(ctx, account.ID, 1, 7.0)
	assertFloatEqual(t, mock.costs[costKey(account.ID, 3, 1)], 7.0)

	// Recalculation must produce a new epoch greater than 3
	impl.recalculateQuotas(ctx, account, true)
	if mock.meta[account.ID].epoch <= 3 {
		t.Fatalf("epoch=%d want > 3 (epoch must increase monotonically)", mock.meta[account.ID].epoch)
	}

	// GetQuotaCheckData returns userCost=0 for epoch 4
	_, _, _, userCost, _, err := mock.GetQuotaCheckData(ctx, account.ID, 1)
	if err != nil {
		t.Fatalf("GetQuotaCheckData error: %v", err)
	}
	assertFloatEqual(t, userCost, 0.0)

	// User 1 accumulates $3 in epoch 4
	svc.IncrementUserCost(ctx, account.ID, 1, 3.0)
	assertFloatEqual(t, mock.costs[costKey(account.ID, 4, 1)], 3.0)

	// GetQuotaCheckData returns 3.0, not 7.0+3.0
	_, _, _, userCost2, _, err := mock.GetQuotaCheckData(ctx, account.ID, 1)
	if err != nil {
		t.Fatalf("GetQuotaCheckData error: %v", err)
	}
	assertFloatEqual(t, userCost2, 3.0)
}

// ---------------------------------------------------------------------------
// New: AtomicIncrCost
// ---------------------------------------------------------------------------

func TestAtomicIncrCost_NoEpoch(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.IncrementUserCost(ctx, 7, 9, 2.5)

	if len(mock.costs) != 0 {
		t.Fatalf("expected no costs written when meta absent, got %v", mock.costs)
	}
}

func TestAtomicIncrCost_Normal(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	mock.meta[7] = quotaMetaData{epoch: 5}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})

	svc.IncrementUserCost(ctx, 7, 9, 2.5)
	assertFloatEqual(t, mock.costs[costKey(7, 5, 9)], 2.5)

	svc.IncrementUserCost(ctx, 7, 9, 1.5)
	assertFloatEqual(t, mock.costs[costKey(7, 5, 9)], 4.0)
}

// ---------------------------------------------------------------------------
// New: BumpEpochAndSetMeta
// ---------------------------------------------------------------------------

func TestBumpEpochAndSetMeta(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now, 2: now}
	mock.epochCounters[account.ID] = 3
	mock.meta[account.ID] = quotaMetaData{epoch: 3}

	// windowCost=10, remaining=40, reserve=10, normalRemaining=30, 2 users → perUserLimit=15
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 10 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	if mock.meta[account.ID].epoch <= 3 {
		t.Fatalf("epoch=%d want > 3 (epoch must increase monotonically)", mock.meta[account.ID].epoch)
	}
	assertFloatEqual(t, mock.meta[account.ID].perUserLimit, 15)
	assertFloatEqual(t, mock.meta[account.ID].perUserStickyReserve, 5) // 10/2
	if mock.meta[account.ID].activeCount != 2 {
		t.Fatalf("activeCount=%d want 2", mock.meta[account.ID].activeCount)
	}
}

// ---------------------------------------------------------------------------
// New: window-reset detection
// ---------------------------------------------------------------------------

func TestWindowResetTriggersRecalc_RegisterActivity(t *testing.T) {
	ctx := context.Background()
	mock := newMock()

	now := time.Now()
	windowStart := now.Add(-3 * time.Hour)
	windowEnd := now.Add(2 * time.Hour)
	account := newTestAccountWithWindow(1, enabledExtra(50, 10), windowStart, windowEnd)

	// User 10 already active (not new)
	mock.activeUsers[account.ID] = map[int64]int64{10: now.UnixMilli()}
	mock.epochCounters[account.ID] = 1
	mock.meta[account.ID] = quotaMetaData{epoch: 1, perUserLimit: 30, activeCount: 1}

	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 20 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	// Simulate state from a previous window
	prevWindowStart := windowStart.Add(-5 * time.Hour)
	impl.activeAccounts[account.ID] = &accountQuotaState{
		account:           account,
		lastWindowStartMs: prevWindowStart.UnixMilli(),
	}

	// RegisterActivity for existing user -- should detect window reset and recalculate
	svc.RegisterActivity(ctx, account, 10)

	if mock.epochCounters[account.ID] <= 1 {
		t.Fatalf("epoch=%d want > 1 (window reset must trigger recalculation)", mock.epochCounters[account.ID])
	}
	// On window reset, cost is forced to 0 (new window has no spending).
	// remaining=50, reserve=10, normalRemaining=40, 1 user → perUserLimit=40
	assertFloatEqual(t, mock.meta[account.ID].perUserLimit, 40)

	// lastWindowStartMs must be updated to current window start
	state := impl.activeAccounts[account.ID]
	if state == nil {
		t.Fatalf("state should not be nil after recalculation")
	}
	if state.lastWindowStartMs != windowStart.UnixMilli() {
		t.Fatalf("lastWindowStartMs=%d want %d", state.lastWindowStartMs, windowStart.UnixMilli())
	}
}

func TestWindowResetTriggersRecalc_Cleanup(t *testing.T) {
	ctx := context.Background()
	mock := newMock()

	now := time.Now()
	windowStart := now.Add(-3 * time.Hour)
	windowEnd := now.Add(2 * time.Hour)
	account := newTestAccountWithWindow(1, map[string]any{
		"user_quota_enabled":         true,
		"window_cost_limit":          50.0,
		"window_cost_sticky_reserve": 10.0,
		"user_quota_idle_timeout":    60,
	}, windowStart, windowEnd)

	// User 1 is active and not idle
	mock.activeUsers[account.ID] = map[int64]int64{1: now.UnixMilli()}
	mock.epochCounters[account.ID] = 1
	mock.meta[account.ID] = quotaMetaData{epoch: 1, perUserLimit: 30, activeCount: 1}

	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 20 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	// Simulate state from a previous window
	prevWindowStart := windowStart.Add(-5 * time.Hour)
	impl.activeAccounts[account.ID] = &accountQuotaState{
		account:           account,
		lastWindowStartMs: prevWindowStart.UnixMilli(),
	}

	impl.runCleanup(ctx)

	// Epoch must be bumped even though no idle users were removed
	if mock.epochCounters[account.ID] <= 1 {
		t.Fatalf("epoch=%d want > 1 (window reset must trigger recalculation)", mock.epochCounters[account.ID])
	}
}

// ---------------------------------------------------------------------------
// New: recalculation uses current remaining budget
// ---------------------------------------------------------------------------

func TestRecalculation_UsesCurrentRemaining(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now}

	// windowCost=40, remaining=10, reserve clamped to 10, normalRemaining=0, 1 user → perUserLimit=0
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 40 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	impl.recalculateQuotas(ctx, account, true)

	assertFloatEqual(t, mock.meta[account.ID].perUserLimit, 0)
	assertFloatEqual(t, mock.meta[account.ID].perUserStickyReserve, 10) // 10/1, all remaining budget is sticky
}

// ---------------------------------------------------------------------------
// New: full end-to-end workflow
// ---------------------------------------------------------------------------

func TestFullWorkflow_MultiUserJoinSpendJoin(t *testing.T) {
	ctx := context.Background()
	mock := newMock()

	// windowCost is mutable so the closure captures the variable by reference
	windowCost := 20.0
	account := newTestAccount(1, enabledExtra(50, 10))
	svc := NewUserQuotaService(mock, func(_ context.Context, _ *Account) float64 { return windowCost }, &mockRPMCache{})

	// Step 1: User A (1) joins → first recalculation, remaining=30, reserve=10, normalRemaining=20, perUserLimit=20
	svc.RegisterActivity(ctx, account, 1)
	epochAfterA := mock.epochCounters[account.ID]
	if epochAfterA <= 0 {
		t.Fatalf("after A join: epoch=%d want > 0", epochAfterA)
	}
	assertFloatEqual(t, mock.meta[account.ID].perUserLimit, 20)

	// Step 2: User A spends $5
	svc.IncrementUserCost(ctx, account.ID, 1, 5.0)
	assertFloatEqual(t, mock.costs[costKey(account.ID, epochAfterA, 1)], 5.0)

	// GetQuotaCheckData reflects cost=5 in current epoch
	_, _, _, costA, _, err := mock.GetQuotaCheckData(ctx, account.ID, 1)
	if err != nil {
		t.Fatalf("GetQuotaCheckData error: %v", err)
	}
	assertFloatEqual(t, costA, 5.0)

	// Step 3: Update window cost (A spent $5, total window now $25)
	windowCost = 25.0

	// Step 4: User B (2) joins → recalculate → new epoch, remaining=25, reserve=10, normalRemaining=15, 2 users → perUserLimit=7.5
	svc.RegisterActivity(ctx, account, 2)
	if mock.epochCounters[account.ID] <= epochAfterA {
		t.Fatalf("after B join: epoch=%d want > %d (recalculation must produce a new epoch)", mock.epochCounters[account.ID], epochAfterA)
	}
	assertFloatEqual(t, mock.meta[account.ID].perUserLimit, 7.5)

	// Step 5: User A's cost in new epoch (2) must be 0 -- NOT carried over from epoch 1
	_, _, _, costANew, _, err := mock.GetQuotaCheckData(ctx, account.ID, 1)
	if err != nil {
		t.Fatalf("GetQuotaCheckData error: %v", err)
	}
	assertFloatEqual(t, costANew, 0.0)

	// Step 6: User B's cost in current epoch is also 0
	_, _, _, costBNew, _, err := mock.GetQuotaCheckData(ctx, account.ID, 2)
	if err != nil {
		t.Fatalf("GetQuotaCheckData error: %v", err)
	}
	assertFloatEqual(t, costBNew, 0.0)
}

// ---------------------------------------------------------------------------
// New: DelMeta must not cause epoch reuse
// ---------------------------------------------------------------------------

// TestRecalculate_LimitZero_FailOpen validates that recalculateQuotas does NOT bump the
// epoch (and thus does NOT write perUserLimit=0) when the resolved limit is 0. This is the
// defense-in-depth guard for the dynamic-bootstrap window-reset scenario where
// computeEffectiveWindowCostLimit may return 0 due to stale/missing data.
func TestRecalculate_LimitZero_FailOpen(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(0, 0)) // window_cost_limit=0 → limit=0
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now, 2: now}
	// Seed a prior epoch with a valid perUserLimit so we can verify it's untouched.
	mock.epochCounters[account.ID] = 5
	mock.meta[account.ID] = quotaMetaData{epoch: 5, perUserLimit: 20, activeCount: 2}

	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	epoch, activeCount := impl.recalculateQuotas(ctx, account, true)

	// No epoch bump — existing meta must remain intact.
	if mock.epochCounters[account.ID] != 5 {
		t.Fatalf("epoch bumped to %d, want 5 (limit=0 must not overwrite existing valid meta)", mock.epochCounters[account.ID])
	}
	if epoch != 0 {
		t.Fatalf("returned epoch=%d want 0 (fail-open path must return 0)", epoch)
	}
	if activeCount != 2 {
		t.Fatalf("returned activeCount=%d want 2", activeCount)
	}
	// Existing meta must be preserved.
	if mock.meta[account.ID].perUserLimit != 20 {
		t.Fatalf("perUserLimit=%v want 20 (must not be overwritten)", mock.meta[account.ID].perUserLimit)
	}
}

// TestDelMeta_DoesNotResetEpoch validates the root cause of the stale-cost bug:
// when all users go idle the cleanup cycle deletes the meta hash (DelMeta). On the next
// request, BumpEpochAndSetMeta must produce an epoch that is DIFFERENT from the one that
// existed before the deletion. If the epoch repeated (e.g. always returning 1 after a
// reset), IncrementUserCost would keep writing to the same cost key, accumulating cost
// across billing windows while per_user_limit was recomputed from scratch — causing the
// user to hit the limit far earlier than the account's own remaining budget.
func TestDelMeta_DoesNotResetEpoch(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	account := newTestAccount(1, enabledExtra(50, 10))
	now := time.Now().UnixMilli()
	mock.activeUsers[account.ID] = map[int64]int64{1: now}

	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 10 }, &mockRPMCache{})
	impl := svc.(*userQuotaService)

	// First recalculation produces a positive epoch.
	impl.recalculateQuotas(ctx, account, true)
	epoch1 := mock.meta[account.ID].epoch
	if epoch1 <= 0 {
		t.Fatalf("epoch1=%d must be > 0", epoch1)
	}

	// Simulate all users going idle: the cleanup tick calls DelMeta when activeCount → 0.
	mock.DelMeta(ctx, account.ID)
	if _, exists := mock.meta[account.ID]; exists {
		t.Fatalf("meta should be absent after DelMeta")
	}

	// User returns — add back to active set and trigger a fresh recalculation.
	mock.activeUsers[account.ID] = map[int64]int64{1: time.Now().UnixMilli()}
	impl.recalculateQuotas(ctx, account, true)
	epoch2 := mock.meta[account.ID].epoch

	// The new epoch MUST differ from the old one so that cost keys are not reused.
	if epoch2 == epoch1 {
		t.Fatalf("epoch repeated after DelMeta: epoch1=%d epoch2=%d — this would cause stale cost accumulation", epoch1, epoch2)
	}
	if epoch2 <= 0 {
		t.Fatalf("epoch2=%d must be > 0", epoch2)
	}
}

// ---------------------------------------------------------------------------
// Per-User RPM Tests
// ---------------------------------------------------------------------------

func rpmEnabledExtra(baseRPM int) map[string]any {
	return map[string]any{
		"user_rpm_enabled": true,
		"base_rpm":         float64(baseRPM),
	}
}

func rpmEnabledExtraWithStrategy(baseRPM int, strategy string) map[string]any {
	return map[string]any{
		"user_rpm_enabled": true,
		"base_rpm":         float64(baseRPM),
		"rpm_strategy":     strategy,
	}
}

func rpmEnabledExtraWithBuffer(baseRPM int, buffer int) map[string]any {
	return map[string]any{
		"user_rpm_enabled":  true,
		"base_rpm":          float64(baseRPM),
		"rpm_sticky_buffer": float64(buffer),
	}
}

func TestCheckUserRPM_Disabled(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	// No user_rpm_enabled flag
	account := newTestAccount(1, map[string]any{"base_rpm": float64(10)})
	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if !allowed || reason != "disabled" {
		t.Fatalf("expected allowed=true reason=disabled, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_NoBaseRPM(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, &mockRPMCache{})
	account := newTestAccount(1, map[string]any{"user_rpm_enabled": true})
	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if !allowed || reason != "no_base_rpm" {
		t.Fatalf("expected allowed=true reason=no_base_rpm, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_GreenZone(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	mock.activeUsers[1] = map[int64]int64{10: now, 20: now}             // 2 active users
	rpmMock := &mockRPMCache{userAccountRPM: map[string]int{"1:10": 2}} // user 10 at 2 RPM
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtra(10)) // base=10, 2 users => perUser=5

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if !allowed || reason != "green" {
		t.Fatalf("expected green zone, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_YellowSticky(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	mock.activeUsers[1] = map[int64]int64{10: now, 20: now}
	rpmMock := &mockRPMCache{userAccountRPM: map[string]int{"1:10": 5}} // at per-user base
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtra(10))

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, true)
	if !allowed || reason != "yellow_sticky" {
		t.Fatalf("expected yellow_sticky, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_YellowNonSticky(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	mock.activeUsers[1] = map[int64]int64{10: now, 20: now}
	rpmMock := &mockRPMCache{userAccountRPM: map[string]int{"1:10": 5}}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtra(10))

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if allowed || reason != "yellow_non_sticky" {
		t.Fatalf("expected blocked yellow_non_sticky, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_RedZone(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	mock.activeUsers[1] = map[int64]int64{10: now, 20: now}
	// perUserBase=5, perUserBuffer=ceil(2/2)=1 => red at 5+1=6
	rpmMock := &mockRPMCache{userAccountRPM: map[string]int{"1:10": 7}}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtra(10))

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, true)
	if allowed || reason != "red" {
		t.Fatalf("expected blocked red, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_StickyExemptStrategy(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	mock.activeUsers[1] = map[int64]int64{10: now}
	// Single user, base=10, at 15 RPM — above base but sticky_exempt has no red zone
	rpmMock := &mockRPMCache{userAccountRPM: map[string]int{"1:10": 15}}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtraWithStrategy(10, "sticky_exempt"))

	// Non-sticky should be blocked (yellow zone)
	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if allowed {
		t.Fatalf("expected blocked in yellow zone for non-sticky, got allowed=%v reason=%s", allowed, reason)
	}
	// Sticky should be allowed (no red zone in sticky_exempt)
	allowed, reason = svc.CheckUserRPM(ctx, account, 10, true)
	if !allowed {
		t.Fatalf("expected allowed for sticky in sticky_exempt, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_FailOpen(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	mock.activeUsers[1] = map[int64]int64{10: now}
	rpmMock := &mockRPMCache{rpmErr: errors.New("redis down")}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtra(10))

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if !allowed || reason != "redis_error" {
		t.Fatalf("expected fail-open, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_ActiveCountZero(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	// No active users in sorted set
	rpmMock := &mockRPMCache{}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtra(10))

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if !allowed || reason != "active_count_zero" {
		t.Fatalf("expected fail-open on zero active, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_SingleUser(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	mock.activeUsers[1] = map[int64]int64{10: now} // single user
	rpmMock := &mockRPMCache{userAccountRPM: map[string]int{"1:10": 8}}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtra(10)) // single user gets full 10

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, false)
	if !allowed || reason != "green" {
		t.Fatalf("single user should get full base RPM, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestCheckUserRPM_BufferCeilDivision(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	now := time.Now().UnixMilli()
	// 3 active users, buffer=2 => ceil(2/3) = 1 per user
	mock.activeUsers[1] = map[int64]int64{10: now, 20: now, 30: now}
	// perUserBase = 12/3 = 4, perUserBuffer = ceil(2/3) = 1
	// yellow zone: 4..4 (base <= rpm < base+buffer=5)
	rpmMock := &mockRPMCache{userAccountRPM: map[string]int{"1:10": 4}}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	account := newTestAccount(1, rpmEnabledExtraWithBuffer(12, 2))

	allowed, reason := svc.CheckUserRPM(ctx, account, 10, true)
	if !allowed || reason != "yellow_sticky" {
		t.Fatalf("expected yellow_sticky with ceil buffer, got allowed=%v reason=%s", allowed, reason)
	}

	// At 5 should be red (4 + 1 = 5)
	rpmMock.userAccountRPM["1:10"] = 5
	allowed, reason = svc.CheckUserRPM(ctx, account, 10, true)
	if allowed || reason != "red" {
		t.Fatalf("expected red zone at buffer boundary, got allowed=%v reason=%s", allowed, reason)
	}
}

func TestRegisterActivity_RPMOnlyMode(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	rpmMock := &mockRPMCache{}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	impl := svc.(*userQuotaService)

	// RPM-only: user_rpm_enabled=true but user_quota_enabled is NOT set
	account := newTestAccount(1, rpmEnabledExtra(10))

	svc.RegisterActivity(ctx, account, 10)

	// User should be tracked in activeUsers
	if _, exists := mock.activeUsers[1]; !exists {
		t.Fatal("expected user to be tracked in active set")
	}
	// Account should be in activeAccounts
	impl.mu.RLock()
	_, tracked := impl.activeAccounts[1]
	impl.mu.RUnlock()
	if !tracked {
		t.Fatal("expected account in activeAccounts for RPM-only mode")
	}
	// No epoch should be bumped (RPM-only skips recalculation)
	if len(mock.meta) > 0 {
		t.Fatal("RPM-only should not trigger recalculate/BumpEpochAndSetMeta")
	}
}

func TestRunCleanup_RPMOnlyAccountPruning(t *testing.T) {
	ctx := context.Background()
	mock := newMock()
	rpmMock := &mockRPMCache{}
	svc := NewUserQuotaService(mock, func(context.Context, *Account) float64 { return 0 }, rpmMock)
	impl := svc.(*userQuotaService)

	account := newTestAccount(1, rpmEnabledExtra(10))

	// Register user activity (RPM-only)
	svc.RegisterActivity(ctx, account, 10)

	// Simulate idle: set score to the past
	mock.mu.Lock()
	mock.activeUsers[1][10] = 0 // long past
	mock.mu.Unlock()

	// Run cleanup
	impl.runCleanup(ctx)

	// After cleanup, user should be evicted and account pruned
	impl.mu.RLock()
	_, tracked := impl.activeAccounts[1]
	impl.mu.RUnlock()
	if tracked {
		t.Fatal("RPM-only account should be pruned from activeAccounts after all users evicted")
	}
}

// ---------------------------------------------------------------------------
// CheckRPMZone + IsUserRPMEnabled unit tests
// ---------------------------------------------------------------------------

func TestCheckRPMZone_Green(t *testing.T) {
	zone := CheckRPMZone(5, 10, 3, "tiered")
	if zone != WindowCostSchedulable {
		t.Fatalf("expected Schedulable, got %v", zone)
	}
}

func TestCheckRPMZone_Yellow(t *testing.T) {
	zone := CheckRPMZone(10, 10, 3, "tiered")
	if zone != WindowCostStickyOnly {
		t.Fatalf("expected StickyOnly, got %v", zone)
	}
}

func TestCheckRPMZone_Red(t *testing.T) {
	zone := CheckRPMZone(13, 10, 3, "tiered")
	if zone != WindowCostNotSchedulable {
		t.Fatalf("expected NotSchedulable, got %v", zone)
	}
}

func TestCheckRPMZone_StickyExempt(t *testing.T) {
	// sticky_exempt has no red zone — anything above base is yellow
	zone := CheckRPMZone(100, 10, 3, "sticky_exempt")
	if zone != WindowCostStickyOnly {
		t.Fatalf("expected StickyOnly for sticky_exempt, got %v", zone)
	}
}

func TestCheckRPMZone_ZeroBase(t *testing.T) {
	zone := CheckRPMZone(5, 0, 3, "tiered")
	if zone != WindowCostSchedulable {
		t.Fatalf("expected Schedulable for zero base, got %v", zone)
	}
}

func TestCheckRPMZone_MatchesOriginalBehavior(t *testing.T) {
	// Verify that CheckRPMZone produces the same result as the old inline code
	// for a realistic account scenario
	cases := []struct {
		rpm, base, buffer int
		strategy          string
		expected          WindowCostSchedulability
	}{
		{0, 10, 2, "tiered", WindowCostSchedulable},
		{9, 10, 2, "tiered", WindowCostSchedulable},
		{10, 10, 2, "tiered", WindowCostStickyOnly},
		{11, 10, 2, "tiered", WindowCostStickyOnly},
		{12, 10, 2, "tiered", WindowCostNotSchedulable},
		{10, 10, 2, "sticky_exempt", WindowCostStickyOnly},
		{999, 10, 2, "sticky_exempt", WindowCostStickyOnly},
	}
	for _, tc := range cases {
		got := CheckRPMZone(tc.rpm, tc.base, tc.buffer, tc.strategy)
		if got != tc.expected {
			t.Errorf("CheckRPMZone(%d,%d,%d,%s)=%v want %v", tc.rpm, tc.base, tc.buffer, tc.strategy, got, tc.expected)
		}
	}
}

func TestIsUserRPMEnabled(t *testing.T) {
	cases := []struct {
		name     string
		extra    map[string]any
		platform string
		accType  string
		expected bool
	}{
		{"enabled", map[string]any{"user_rpm_enabled": true}, PlatformAnthropic, AccountTypeOAuth, true},
		{"disabled", map[string]any{"user_rpm_enabled": false}, PlatformAnthropic, AccountTypeOAuth, false},
		{"missing", map[string]any{}, PlatformAnthropic, AccountTypeOAuth, false},
		{"nil extra", nil, PlatformAnthropic, AccountTypeOAuth, false},
		{"wrong platform", map[string]any{"user_rpm_enabled": true}, PlatformOpenAI, AccountTypeOAuth, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Account{Platform: tc.platform, Type: tc.accType, Extra: tc.extra}
			if got := a.IsUserRPMEnabled(); got != tc.expected {
				t.Fatalf("IsUserRPMEnabled()=%v want %v", got, tc.expected)
			}
		})
	}
}
