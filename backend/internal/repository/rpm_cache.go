package repository

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

// RPM 计数器缓存常量定义
//
// 设计说明：
// 使用 Redis 简单计数器跟踪每个账号每分钟的请求数：
// - Key: rpm:{accountID}:{minuteTimestamp}
// - Value: 当前分钟内的请求计数
// - TTL: 120 秒（覆盖当前分钟 + 一定冗余）
//
// 使用 TxPipeline（MULTI/EXEC）执行 INCR + EXPIRE，保证原子性且兼容 Redis Cluster。
// 通过 rdb.Time() 获取服务端时间，避免多实例时钟不同步。
//
// 设计决策：
//   - TxPipeline vs Pipeline：Pipeline 仅合并发送但不保证原子，TxPipeline 使用 MULTI/EXEC 事务保证原子执行。
//   - rdb.Time() 单独调用：Pipeline/TxPipeline 中无法引用前一命令的结果，因此 TIME 必须单独调用（2 RTT）。
//     Lua 脚本可以做到 1 RTT，但在 Redis Cluster 中动态拼接 key 存在 CROSSSLOT 风险，选择安全性优先。
const (
	// RPM 计数器键前缀
	// 格式: rpm:{accountID}:{minuteTimestamp}
	rpmKeyPrefix = "rpm:"

	// RPM 计数器 TTL（120 秒，覆盖当前分钟窗口 + 冗余）
	rpmKeyTTL = 120 * time.Second
)

// RPMCacheImpl RPM 计数器缓存 Redis 实现
type RPMCacheImpl struct {
	rdb *redis.Client
}

// NewRPMCache 创建 RPM 计数器缓存
func NewRPMCache(rdb *redis.Client) service.RPMCache {
	return &RPMCacheImpl{rdb: rdb}
}

// currentMinuteTS returns the current minute timestamp from Redis server time.
func (c *RPMCacheImpl) currentMinuteTS(ctx context.Context) (int64, error) {
	serverTime, err := c.rdb.Time(ctx).Result()
	if err != nil {
		return 0, fmt.Errorf("redis TIME: %w", err)
	}
	return serverTime.Unix() / 60, nil
}

// getByMinuteKey reads an integer counter for the given key, returning 0 for missing keys.
func (c *RPMCacheImpl) getByMinuteKey(ctx context.Context, key string) (int, error) {
	val, err := c.rdb.Get(ctx, key).Int()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return val, nil
}

// incrWithExpire atomically increments a key and sets TTL using TxPipeline.
func (c *RPMCacheImpl) incrWithExpire(ctx context.Context, key string) (int, error) {
	pipe := c.rdb.TxPipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, rpmKeyTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return int(incrCmd.Val()), nil
}

// IncrementRPM 原子递增并返回当前分钟的计数
// 使用 TxPipeline (MULTI/EXEC) 执行 INCR + EXPIRE，保证原子性且兼容 Redis Cluster
func (c *RPMCacheImpl) IncrementRPM(ctx context.Context, accountID int64) (int, error) {
	minuteTS, err := c.currentMinuteTS(ctx)
	if err != nil {
		return 0, fmt.Errorf("rpm increment: %w", err)
	}
	key := fmt.Sprintf("%s%d:%d", rpmKeyPrefix, accountID, minuteTS)
	count, err := c.incrWithExpire(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("rpm increment: %w", err)
	}
	return count, nil
}

// GetRPM 获取当前分钟的 RPM 计数
func (c *RPMCacheImpl) GetRPM(ctx context.Context, accountID int64) (int, error) {
	minuteTS, err := c.currentMinuteTS(ctx)
	if err != nil {
		return 0, fmt.Errorf("rpm get: %w", err)
	}
	key := fmt.Sprintf("%s%d:%d", rpmKeyPrefix, accountID, minuteTS)
	val, err := c.getByMinuteKey(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("rpm get: %w", err)
	}
	return val, nil
}

// GetRPMBatch 批量获取多个账号的 RPM 计数（使用 Pipeline）
func (c *RPMCacheImpl) GetRPMBatch(ctx context.Context, accountIDs []int64) (map[int64]int, error) {
	if len(accountIDs) == 0 {
		return map[int64]int{}, nil
	}

	minuteTS, err := c.currentMinuteTS(ctx)
	if err != nil {
		return nil, fmt.Errorf("rpm batch get: %w", err)
	}
	minuteSuffix := strconv.FormatInt(minuteTS, 10)

	// 使用 Pipeline 批量 GET
	pipe := c.rdb.Pipeline()
	cmds := make(map[int64]*redis.StringCmd, len(accountIDs))
	for _, id := range accountIDs {
		key := fmt.Sprintf("%s%d:%s", rpmKeyPrefix, id, minuteSuffix)
		cmds[id] = pipe.Get(ctx, key)
	}

	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("rpm batch get: %w", err)
	}

	result := make(map[int64]int, len(accountIDs))
	for id, cmd := range cmds {
		if val, err := cmd.Int(); err == nil {
			result[id] = val
		} else {
			result[id] = 0
		}
	}
	return result, nil
}

// GetUserAccountRPM returns the current minute's per-user-per-account RPM count.
func (c *RPMCacheImpl) GetUserAccountRPM(ctx context.Context, accountID int64, userID int64) (int, error) {
	minuteTS, err := c.currentMinuteTS(ctx)
	if err != nil {
		return 0, fmt.Errorf("user_acct_rpm get: %w", err)
	}
	key := fmt.Sprintf("user_acct_rpm:%d:%d:%d", accountID, userID, minuteTS)
	val, err := c.getByMinuteKey(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("user_acct_rpm get: %w", err)
	}
	return val, nil
}

// IncrementUserAccountRPM atomically increments and returns the current minute's per-user-per-account RPM count.
func (c *RPMCacheImpl) IncrementUserAccountRPM(ctx context.Context, accountID int64, userID int64) (int, error) {
	minuteTS, err := c.currentMinuteTS(ctx)
	if err != nil {
		return 0, fmt.Errorf("user_acct_rpm increment: %w", err)
	}
	key := fmt.Sprintf("user_acct_rpm:%d:%d:%d", accountID, userID, minuteTS)
	count, err := c.incrWithExpire(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("user_acct_rpm increment: %w", err)
	}
	return count, nil
}

// IncrementUserRPM atomically increments and returns the current minute's RPM count for a user.
func (c *RPMCacheImpl) IncrementUserRPM(ctx context.Context, userID int64) (int, error) {
	minuteTS, err := c.currentMinuteTS(ctx)
	if err != nil {
		return 0, fmt.Errorf("user rpm increment: %w", err)
	}
	key := fmt.Sprintf("user_rpm:%d:%d", userID, minuteTS)
	count, err := c.incrWithExpire(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("user rpm increment: %w", err)
	}
	return count, nil
}
