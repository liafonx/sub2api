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

// 编译期接口断言
var _ service.PeakUsageCache = &PeakUsageCacheImpl{}

// Peak 缓存键前缀定义
//
// 设计说明：
// 使用 Redis Hash 存储每个实体的峰值指标：
// - Key: peak:account:{id} 或 peak:user:{id}
// - Fields: concurrency, sessions, rpm, reset_at（Unix 时间戳字符串）
//
// 通过 Lua 脚本实现原子比较并更新，避免并发写入竞争。
const (
	peakAccountKeyPrefix = "peak:account:"
	peakUserKeyPrefix    = "peak:user:"
)

var (
	// peakUpdateIfGreaterScript 原子比较并设置峰值
	// KEYS[1] = peak:{entityType}:{entityID}
	// ARGV[1] = field name
	// ARGV[2] = new value
	// 返回: 旧值（更新前的值）
	peakUpdateIfGreaterScript = redis.NewScript(`
		local key = KEYS[1]
		local field = ARGV[1]
		local newVal = tonumber(ARGV[2])
		local current = tonumber(redis.call('HGET', key, field) or '0')
		if newVal > current then
		  redis.call('HSET', key, field, newVal)
		end
		return current
	`)
)

// PeakUsageCacheImpl Redis 实现的峰值使用量缓存
type PeakUsageCacheImpl struct {
	rdb *redis.Client
}

// NewPeakUsageCache 创建峰值使用量缓存
func NewPeakUsageCache(rdb *redis.Client) service.PeakUsageCache {
	return &PeakUsageCacheImpl{rdb: rdb}
}

// peakKey 根据实体类型和 ID 生成 Redis 键
func peakKey(entityType string, entityID int64) string {
	if entityType == "account" {
		return fmt.Sprintf("%s%d", peakAccountKeyPrefix, entityID)
	}
	return fmt.Sprintf("%s%d", peakUserKeyPrefix, entityID)
}

// UpdatePeakIfGreater 原子更新峰值字段（仅当新值 > 当前值时）
func (c *PeakUsageCacheImpl) UpdatePeakIfGreater(ctx context.Context, entityType string, entityID int64, field string, newValue int) error {
	key := peakKey(entityType, entityID)
	err := peakUpdateIfGreaterScript.Run(ctx, c.rdb, []string{key}, field, newValue).Err()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("peak update if greater: %w", err)
	}
	return nil
}

// GetAllPeaks 批量获取多个实体的峰值数据
// 使用 Pipeline 并行 HGETALL，缺失的实体在结果 map 中不包含（nil 值）
func (c *PeakUsageCacheImpl) GetAllPeaks(ctx context.Context, entityType string, entityIDs []int64) (map[int64]*service.PeakValues, error) {
	if len(entityIDs) == 0 {
		return map[int64]*service.PeakValues{}, nil
	}

	pipe := c.rdb.Pipeline()
	cmds := make(map[int64]*redis.MapStringStringCmd, len(entityIDs))
	for _, id := range entityIDs {
		key := peakKey(entityType, id)
		cmds[id] = pipe.HGetAll(ctx, key)
	}

	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("peak get all: %w", err)
	}

	result := make(map[int64]*service.PeakValues, len(entityIDs))
	for id, cmd := range cmds {
		fields, err := cmd.Result()
		if err != nil || len(fields) == 0 {
			// 键不存在，跳过
			continue
		}
		pv := parsePeakValues(fields)
		result[id] = pv
	}
	return result, nil
}

// ResetPeaks 将指定实体的所有峰值字段归零，并设置 reset_at 为当前服务器时间
func (c *PeakUsageCacheImpl) ResetPeaks(ctx context.Context, entityType string, entityIDs []int64) error {
	if len(entityIDs) == 0 {
		return nil
	}

	serverTime, err := c.rdb.Time(ctx).Result()
	if err != nil {
		return fmt.Errorf("peak reset: redis TIME: %w", err)
	}
	resetAt := strconv.FormatInt(serverTime.Unix(), 10)

	pipe := c.rdb.Pipeline()
	for _, id := range entityIDs {
		key := peakKey(entityType, id)
		pipe.HSet(ctx, key, "concurrency", 0, "sessions", 0, "rpm", 0, "reset_at", resetAt)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("peak reset: %w", err)
	}
	return nil
}

// parsePeakValues 将 Redis Hash 字段解析为 PeakValues
func parsePeakValues(fields map[string]string) *service.PeakValues {
	pv := &service.PeakValues{}
	if v, ok := fields["concurrency"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			pv.Concurrency = n
		}
	}
	if v, ok := fields["sessions"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			pv.Sessions = n
		}
	}
	if v, ok := fields["rpm"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			pv.RPM = n
		}
	}
	if v, ok := fields["reset_at"]; ok {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			pv.ResetAt = time.Unix(ts, 0)
		}
	}
	return pv
}
