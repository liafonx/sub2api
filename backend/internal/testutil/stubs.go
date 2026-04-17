//go:build unit

// Package testutil 提供单元测试共享的 Stub、Fixture 和辅助函数。
// 所有文件使用 //go:build unit 标签，确保不会被生产构建包含。
package testutil

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// ============================================================
// StubConcurrencyCache — service.ConcurrencyCache 的空实现
// ============================================================

// 编译期接口断言
var _ service.ConcurrencyCache = StubConcurrencyCache{}

// StubConcurrencyCache 是 ConcurrencyCache 的默认空实现，所有方法返回零值。
type StubConcurrencyCache struct{}

func (c StubConcurrencyCache) AcquireAccountSlot(_ context.Context, _ int64, _ int, _ string) (int, error) {
	return 1, nil
}
func (c StubConcurrencyCache) ReleaseAccountSlot(_ context.Context, _ int64, _ string) error {
	return nil
}
func (c StubConcurrencyCache) GetAccountConcurrency(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubConcurrencyCache) IncrementAccountWaitCount(_ context.Context, _ int64, _ int) (bool, error) {
	return true, nil
}
func (c StubConcurrencyCache) DecrementAccountWaitCount(_ context.Context, _ int64) error {
	return nil
}
func (c StubConcurrencyCache) GetAccountWaitingCount(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubConcurrencyCache) AcquireUserSlot(_ context.Context, _ int64, _ int, _ string) (int, error) {
	return 1, nil
}
func (c StubConcurrencyCache) ReleaseUserSlot(_ context.Context, _ int64, _ string) error {
	return nil
}
func (c StubConcurrencyCache) GetUserConcurrency(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubConcurrencyCache) IncrementWaitCount(_ context.Context, _ int64, _ int) (bool, error) {
	return true, nil
}
func (c StubConcurrencyCache) DecrementWaitCount(_ context.Context, _ int64) error { return nil }
func (c StubConcurrencyCache) GetAccountsLoadBatch(_ context.Context, accounts []service.AccountWithConcurrency) (map[int64]*service.AccountLoadInfo, error) {
	result := make(map[int64]*service.AccountLoadInfo, len(accounts))
	for _, acc := range accounts {
		result[acc.ID] = &service.AccountLoadInfo{AccountID: acc.ID, LoadRate: 0}
	}
	return result, nil
}
func (c StubConcurrencyCache) GetUsersLoadBatch(_ context.Context, users []service.UserWithConcurrency) (map[int64]*service.UserLoadInfo, error) {
	result := make(map[int64]*service.UserLoadInfo, len(users))
	for _, u := range users {
		result[u.ID] = &service.UserLoadInfo{UserID: u.ID, LoadRate: 0}
	}
	return result, nil
}
func (c StubConcurrencyCache) GetAccountConcurrencyBatch(_ context.Context, accountIDs []int64) (map[int64]int, error) {
	result := make(map[int64]int, len(accountIDs))
	for _, id := range accountIDs {
		result[id] = 0
	}
	return result, nil
}
func (c StubConcurrencyCache) CleanupExpiredAccountSlots(_ context.Context, _ int64) error {
	return nil
}
func (c StubConcurrencyCache) CleanupStaleProcessSlots(_ context.Context, _ string) error {
	return nil
}

// ============================================================
// StubGatewayCache — service.GatewayCache 的空实现
// ============================================================

var _ service.GatewayCache = StubGatewayCache{}

type StubGatewayCache struct{}

func (c StubGatewayCache) GetSessionAccountID(_ context.Context, _ int64, _ string) (int64, error) {
	return 0, nil
}
func (c StubGatewayCache) SetSessionAccountID(_ context.Context, _ int64, _ string, _ int64, _ time.Duration) error {
	return nil
}
func (c StubGatewayCache) RefreshSessionTTL(_ context.Context, _ int64, _ string, _ time.Duration) error {
	return nil
}
func (c StubGatewayCache) DeleteSessionAccountID(_ context.Context, _ int64, _ string) error {
	return nil
}

// ============================================================
// StubSessionLimitCache — service.SessionLimitCache 的空实现
// ============================================================

var _ service.SessionLimitCache = StubSessionLimitCache{}

type StubSessionLimitCache struct{}

func (c StubSessionLimitCache) RegisterSession(_ context.Context, _ int64, _ string, _ int, _ time.Duration) (bool, error) {
	return true, nil
}
func (c StubSessionLimitCache) RefreshSession(_ context.Context, _ int64, _ string, _ time.Duration) error {
	return nil
}
func (c StubSessionLimitCache) GetActiveSessionCount(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubSessionLimitCache) GetActiveSessionCountBatch(_ context.Context, _ []int64, _ map[int64]time.Duration) (map[int64]int, error) {
	return nil, nil
}
func (c StubSessionLimitCache) IsSessionActive(_ context.Context, _ int64, _ string) (bool, error) {
	return false, nil
}
func (c StubSessionLimitCache) GetWindowCost(_ context.Context, _ int64) (float64, bool, error) {
	return 0, false, nil
}
func (c StubSessionLimitCache) SetWindowCost(_ context.Context, _ int64, _ float64) error {
	return nil
}
func (c StubSessionLimitCache) GetWindowCostBatch(_ context.Context, _ []int64) (map[int64]float64, error) {
	return nil, nil
}
func (c StubSessionLimitCache) RegisterUserSession(_ context.Context, _ int64, _ string, _ int, _ time.Duration) (bool, error) {
	return true, nil
}
func (c StubSessionLimitCache) GetUserActiveSessionCount(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubSessionLimitCache) GetWindowCost7d(_ context.Context, _ int64) (float64, bool, error) {
	return 0, false, nil
}
func (c StubSessionLimitCache) SetWindowCost7d(_ context.Context, _ int64, _ float64) error {
	return nil
}
func (c StubSessionLimitCache) GetWindowCost7dBatch(_ context.Context, _ []int64) (map[int64]float64, error) {
	return nil, nil
}
func (c StubSessionLimitCache) DeleteWindowCost7d(_ context.Context, _ int64) error {
	return nil
}

// ============================================================
// StubRPMCache — service.RPMCache 的空实现
// ============================================================

var _ service.RPMCache = StubRPMCache{}

type StubRPMCache struct{}

func (c StubRPMCache) IncrementRPM(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubRPMCache) GetRPM(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubRPMCache) GetRPMBatch(_ context.Context, _ []int64) (map[int64]int, error) {
	return nil, nil
}
func (c StubRPMCache) IncrementUserRPM(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubRPMCache) GetUserRPM(_ context.Context, _ int64) (int, error) {
	return 0, nil
}
func (c StubRPMCache) GetUserRPMBatch(_ context.Context, _ []int64) (map[int64]int, error) {
	return nil, nil
}
func (c StubRPMCache) GetUserAccountRPM(_ context.Context, _ int64, _ int64) (int, error) {
	return 0, nil
}
func (c StubRPMCache) IncrementUserAccountRPM(_ context.Context, _ int64, _ int64) (int, error) {
	return 0, nil
}

// ============================================================
// StubPeakUsageCache — service.PeakUsageCache 的空实现
// ============================================================

var _ service.PeakUsageCache = StubPeakUsageCache{}

type StubPeakUsageCache struct{}

func (c StubPeakUsageCache) UpdatePeakIfGreater(_ context.Context, _ string, _ int64, _ string, _ int) error {
	return nil
}
func (c StubPeakUsageCache) GetAllPeaks(_ context.Context, _ string, _ []int64) (map[int64]*service.PeakValues, error) {
	return nil, nil
}
func (c StubPeakUsageCache) ResetPeaks(_ context.Context, _ string, _ []int64) error {
	return nil
}
