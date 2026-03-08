package repository

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

// Redis key patterns:
//   user_quota:active:{accountID}              -> Sorted Set (member=userID, score=lastActivityMs)
//   user_quota:cost:{accountID}:{epoch}:{userID} -> String (float64, INCRBYFLOAT)
//   user_quota:meta:{accountID}                -> Hash (epoch, per_user_limit, per_user_sticky_reserve, active_count)

const (
	userQuotaActivePrefix = "user_quota:active:"
	userQuotaCostPrefix   = "user_quota:cost:"
	userQuotaMetaPrefix   = "user_quota:meta:"
	userQuotaTTL          = 6 * time.Hour
)

type userQuotaCache struct {
	rdb *redis.Client
}

// NewUserQuotaCache creates a Redis-backed UserQuotaCache.
func NewUserQuotaCache(rdb *redis.Client) service.UserQuotaCache {
	return &userQuotaCache{rdb: rdb}
}

func uqActiveKey(accountID int64) string {
	return fmt.Sprintf("%s%d", userQuotaActivePrefix, accountID)
}

func uqCostKey(accountID, epoch, userID int64) string {
	return fmt.Sprintf("%s%d:%d:%d", userQuotaCostPrefix, accountID, epoch, userID)
}

func uqMetaKey(accountID int64) string {
	return fmt.Sprintf("%s%d", userQuotaMetaPrefix, accountID)
}

func (c *userQuotaCache) ZAddActivity(ctx context.Context, accountID int64, userID int64, nowMs int64) (bool, error) {
	key := uqActiveKey(accountID)
	member := strconv.FormatInt(userID, 10)

	_, err := c.rdb.ZScore(ctx, key, member).Result()
	isNew := err == redis.Nil

	if addErr := c.rdb.ZAdd(ctx, key, redis.Z{Score: float64(nowMs), Member: member}).Err(); addErr != nil {
		return false, fmt.Errorf("ZAddActivity: %w", addErr)
	}
	c.rdb.Expire(ctx, key, userQuotaTTL)
	return isNew, nil
}

func (c *userQuotaCache) ZRemIdleUsers(ctx context.Context, accountID int64, cutoffMs int64) ([]int64, error) {
	key := uqActiveKey(accountID)
	maxScore := strconv.FormatInt(cutoffMs, 10)

	members, err := c.rdb.ZRangeByScore(ctx, key, &redis.ZRangeBy{Min: "-inf", Max: maxScore}).Result()
	if err != nil {
		return nil, fmt.Errorf("ZRemIdleUsers range: %w", err)
	}
	if len(members) == 0 {
		return nil, nil
	}
	if err := c.rdb.ZRemRangeByScore(ctx, key, "-inf", maxScore).Err(); err != nil {
		return nil, fmt.Errorf("ZRemIdleUsers remove: %w", err)
	}

	ids := make([]int64, 0, len(members))
	for _, m := range members {
		id, err := strconv.ParseInt(m, 10, 64)
		if err == nil {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (c *userQuotaCache) ZCardActive(ctx context.Context, accountID int64) (int64, error) {
	n, err := c.rdb.ZCard(ctx, uqActiveKey(accountID)).Result()
	if err != nil {
		return 0, fmt.Errorf("ZCardActive: %w", err)
	}
	return n, nil
}

func (c *userQuotaCache) HIncrByEpoch(ctx context.Context, accountID int64) (int64, error) {
	key := uqMetaKey(accountID)
	epoch, err := c.rdb.HIncrBy(ctx, key, "epoch", 1).Result()
	if err != nil {
		return 0, fmt.Errorf("HIncrByEpoch: %w", err)
	}
	c.rdb.Expire(ctx, key, userQuotaTTL)
	return epoch, nil
}

func (c *userQuotaCache) HSetMeta(ctx context.Context, accountID int64, epoch int64, perUserLimit float64, perUserStickyReserve float64, activeCount int64) error {
	key := uqMetaKey(accountID)
	err := c.rdb.HSet(ctx, key, map[string]any{
		"epoch":                   strconv.FormatInt(epoch, 10),
		"per_user_limit":          strconv.FormatFloat(perUserLimit, 'f', -1, 64),
		"per_user_sticky_reserve": strconv.FormatFloat(perUserStickyReserve, 'f', -1, 64),
		"active_count":            strconv.FormatInt(activeCount, 10),
	}).Err()
	if err != nil {
		return fmt.Errorf("HSetMeta: %w", err)
	}
	c.rdb.Expire(ctx, key, userQuotaTTL)
	return nil
}

func (c *userQuotaCache) HGetMeta(ctx context.Context, accountID int64) (int64, float64, float64, error) {
	vals, err := c.rdb.HMGet(ctx, uqMetaKey(accountID), "epoch", "per_user_limit", "per_user_sticky_reserve").Result()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("HGetMeta: %w", err)
	}
	epoch := parseHMGetInt64(vals[0])
	perUserLimit := parseHMGetFloat64(vals[1])
	perUserStickyReserve := parseHMGetFloat64(vals[2])
	return epoch, perUserLimit, perUserStickyReserve, nil
}

func (c *userQuotaCache) GetQuotaCheckData(ctx context.Context, accountID int64, userID int64) (int64, float64, float64, float64, error) {
	const luaScript = `
local vals = redis.call("HMGET", KEYS[1], "epoch", "per_user_limit", "per_user_sticky_reserve")
local epoch = vals[1]
if not epoch or epoch == "" then
	return {false, "0", "0", "0"}
end
local costKey = KEYS[2] .. epoch .. ":" .. ARGV[1]
local cost = redis.call("GET", costKey)
if not cost then
	cost = "0"
end
return {epoch, vals[2] or "0", vals[3] or "0", cost}
	`

	keys := []string{uqMetaKey(accountID), fmt.Sprintf("%s%d:", userQuotaCostPrefix, accountID)}
	args := []any{strconv.FormatInt(userID, 10)}
	result, err := redis.NewScript(luaScript).Run(ctx, c.rdb, keys, args...).Result()
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData script: %w", err)
	}

	vals, ok := result.([]any)
	if !ok || len(vals) != 4 {
		return 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData result: unexpected %T", result)
	}

	epochStr := parseScriptString(vals[0])
	if epochStr == "" || epochStr == "false" {
		return 0, 0, 0, 0, nil
	}
	perUserLimitStr := parseScriptString(vals[1])
	perUserStickyReserveStr := parseScriptString(vals[2])
	costStr := parseScriptString(vals[3])

	epoch, err := strconv.ParseInt(epochStr, 10, 64)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse epoch: %w", err)
	}

	perUserLimit, err := strconv.ParseFloat(perUserLimitStr, 64)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse per_user_limit: %w", err)
	}

	perUserStickyReserve, err := strconv.ParseFloat(perUserStickyReserveStr, 64)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse per_user_sticky_reserve: %w", err)
	}

	userCost, err := strconv.ParseFloat(costStr, 64)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse cost: %w", err)
	}

	return epoch, perUserLimit, perUserStickyReserve, userCost, nil
}

func (c *userQuotaCache) IncrByFloatCost(ctx context.Context, accountID, epoch, userID int64, delta float64) (float64, error) {
	key := uqCostKey(accountID, epoch, userID)
	val, err := c.rdb.IncrByFloat(ctx, key, delta).Result()
	if err != nil {
		return 0, fmt.Errorf("IncrByFloatCost: %w", err)
	}
	c.rdb.Expire(ctx, key, userQuotaTTL)
	return val, nil
}

func (c *userQuotaCache) GetUserCost(ctx context.Context, accountID, epoch, userID int64) (float64, error) {
	val, err := c.rdb.Get(ctx, uqCostKey(accountID, epoch, userID)).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("GetUserCost: %w", err)
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0, fmt.Errorf("GetUserCost parse: %w", err)
	}
	return f, nil
}

func (c *userQuotaCache) DelMeta(ctx context.Context, accountID int64) error {
	return c.rdb.Del(ctx, uqMetaKey(accountID)).Err()
}

// parseHMGetInt64 safely parses an HMGet result value as int64.
func parseHMGetInt64(v any) int64 {
	if v == nil {
		return 0
	}
	s, ok := v.(string)
	if !ok {
		return 0
	}
	i, _ := strconv.ParseInt(s, 10, 64)
	return i
}

// parseHMGetFloat64 safely parses an HMGet result value as float64.
func parseHMGetFloat64(v any) float64 {
	if v == nil {
		return 0
	}
	s, ok := v.(string)
	if !ok {
		return 0
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

func parseScriptString(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return fmt.Sprint(v)
	}
}
