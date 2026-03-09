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

// Redis key patterns:
//
//	user_quota:active:{accountID}              -> Sorted Set (member=userID, score=lastActivityMs)
//	user_quota:cost:{accountID}:{epoch}:{userID} -> String (float64, INCRBYFLOAT)
//	user_quota:meta:{accountID}                -> Hash (epoch, per_user_limit, per_user_sticky_reserve, active_count)
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

// ZAddActivity uses ZADD GT to record user activity in a single round trip.
// ZADD GT only updates an existing member's score when the new score is greater (more recent
// timestamp), preventing accidental clock-skew regressions. New members are always added.
// Returns isNew=true when the member was not previously in the set.
func (c *userQuotaCache) ZAddActivity(ctx context.Context, accountID int64, userID int64, nowMs int64) (bool, error) {
	key := uqActiveKey(accountID)
	member := strconv.FormatInt(userID, 10)

	added, err := c.rdb.ZAddArgs(ctx, key, redis.ZAddArgs{
		GT:      true,
		Members: []redis.Z{{Score: float64(nowMs), Member: member}},
	}).Result()
	if err != nil {
		return false, fmt.Errorf("ZAddActivity: %w", err)
	}
	c.rdb.Expire(ctx, key, userQuotaTTL)
	return added > 0, nil
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

// BumpEpochAndSetMeta atomically increments the epoch and writes all quota metadata in one
// Lua script, eliminating the brief window where a concurrent read could see a stale limit
// with an already-bumped epoch.
func (c *userQuotaCache) BumpEpochAndSetMeta(ctx context.Context, accountID int64, perUserLimit float64, perUserStickyReserve float64, activeCount int64) (int64, error) {
	const luaScript = `
local key = KEYS[1]
local epoch = redis.call("HINCRBY", key, "epoch", 1)
redis.call("HSET", key,
    "per_user_limit",          ARGV[1],
    "per_user_sticky_reserve", ARGV[2],
    "active_count",            ARGV[3])
redis.call("EXPIRE", key, tonumber(ARGV[4]))
return epoch
`
	ttlSecs := int64(userQuotaTTL / time.Second)
	result, err := redis.NewScript(luaScript).Run(ctx, c.rdb,
		[]string{uqMetaKey(accountID)},
		strconv.FormatFloat(perUserLimit, 'f', -1, 64),
		strconv.FormatFloat(perUserStickyReserve, 'f', -1, 64),
		strconv.FormatInt(activeCount, 10),
		strconv.FormatInt(ttlSecs, 10),
	).Result()
	if err != nil {
		return 0, fmt.Errorf("BumpEpochAndSetMeta: %w", err)
	}
	epoch, ok := result.(int64)
	if !ok {
		return 0, fmt.Errorf("BumpEpochAndSetMeta: unexpected result type %T", result)
	}
	return epoch, nil
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

func (c *userQuotaCache) GetQuotaCheckData(ctx context.Context, accountID int64, userID int64) (int64, float64, float64, float64, int64, error) {
	const luaScript = `
local vals = redis.call("HMGET", KEYS[1], "epoch", "per_user_limit", "per_user_sticky_reserve", "active_count")
local epoch = vals[1]
if not epoch or epoch == "" then
	return {false, "0", "0", "0", "0"}
end
local costKey = KEYS[2] .. epoch .. ":" .. ARGV[1]
local cost = redis.call("GET", costKey)
if not cost then
	cost = "0"
end
return {epoch, vals[2] or "0", vals[3] or "0", cost, vals[4] or "0"}
	`

	keys := []string{uqMetaKey(accountID), fmt.Sprintf("%s%d:", userQuotaCostPrefix, accountID)}
	args := []any{strconv.FormatInt(userID, 10)}
	result, err := redis.NewScript(luaScript).Run(ctx, c.rdb, keys, args...).Result()
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData script: %w", err)
	}

	vals, ok := result.([]any)
	if !ok || len(vals) != 5 {
		return 0, 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData result: unexpected %T", result)
	}

	epochStr := parseScriptString(vals[0])
	if epochStr == "" || epochStr == "false" {
		return 0, 0, 0, 0, 0, nil
	}
	perUserLimitStr := parseScriptString(vals[1])
	perUserStickyReserveStr := parseScriptString(vals[2])
	costStr := parseScriptString(vals[3])
	activeCountStr := parseScriptString(vals[4])

	epoch, err := strconv.ParseInt(epochStr, 10, 64)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse epoch: %w", err)
	}

	perUserLimit, err := strconv.ParseFloat(perUserLimitStr, 64)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse per_user_limit: %w", err)
	}

	perUserStickyReserve, err := strconv.ParseFloat(perUserStickyReserveStr, 64)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse per_user_sticky_reserve: %w", err)
	}

	userCost, err := strconv.ParseFloat(costStr, 64)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse cost: %w", err)
	}

	activeCount, err := strconv.ParseInt(activeCountStr, 10, 64)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("GetQuotaCheckData parse active_count: %w", err)
	}

	return epoch, perUserLimit, perUserStickyReserve, userCost, activeCount, nil
}

// AtomicIncrCost atomically reads the current epoch from the meta hash and increments the
// user's cost in a single Lua script, closing the race window where a concurrent epoch bump
// could cause cost to be written to a stale epoch key.
// Returns epoch=0 when meta is not initialised (increment is skipped).
func (c *userQuotaCache) AtomicIncrCost(ctx context.Context, accountID int64, userID int64, delta float64) (int64, float64, error) {
	const luaScript = `
local epoch = redis.call("HGET", KEYS[1], "epoch")
if not epoch or epoch == "" then
	return {0, "0"}
end
local costKey = KEYS[2] .. epoch .. ":" .. ARGV[1]
local newTotal = redis.call("INCRBYFLOAT", costKey, ARGV[2])
redis.call("EXPIRE", costKey, tonumber(ARGV[3]))
return {tonumber(epoch), newTotal}
`
	ttlSecs := int64(userQuotaTTL / time.Second)
	keys := []string{
		uqMetaKey(accountID),
		fmt.Sprintf("%s%d:", userQuotaCostPrefix, accountID),
	}
	args := []any{
		strconv.FormatInt(userID, 10),
		strconv.FormatFloat(delta, 'f', -1, 64),
		strconv.FormatInt(ttlSecs, 10),
	}

	result, err := redis.NewScript(luaScript).Run(ctx, c.rdb, keys, args...).Result()
	if err != nil {
		return 0, 0, fmt.Errorf("AtomicIncrCost: %w", err)
	}

	vals, ok := result.([]any)
	if !ok || len(vals) != 2 {
		return 0, 0, fmt.Errorf("AtomicIncrCost: unexpected result type %T", result)
	}

	epoch, ok := vals[0].(int64)
	if !ok || epoch == 0 {
		return 0, 0, nil
	}

	newTotalStr := parseScriptString(vals[1])
	newTotal, err := strconv.ParseFloat(newTotalStr, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("AtomicIncrCost parse newTotal: %w", err)
	}
	return epoch, newTotal, nil
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

func (c *userQuotaCache) GetDisplayMetaBatch(ctx context.Context, accountIDs []int64) (map[int64]service.QuotaDisplayMeta, error) {
	if len(accountIDs) == 0 {
		return map[int64]service.QuotaDisplayMeta{}, nil
	}

	pipe := c.rdb.Pipeline()
	cmds := make(map[int64]*redis.SliceCmd, len(accountIDs))
	for _, id := range accountIDs {
		cmds[id] = pipe.HMGet(ctx, uqMetaKey(id), "per_user_limit", "active_count")
	}

	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("GetDisplayMetaBatch: %w", err)
	}

	result := make(map[int64]service.QuotaDisplayMeta, len(accountIDs))
	for id, cmd := range cmds {
		vals, err := cmd.Result()
		if err != nil || len(vals) != 2 || vals[0] == nil {
			continue
		}
		perUserLimit := parseHMGetFloat64(vals[0])
		activeCount := parseHMGetInt64(vals[1])
		if perUserLimit == 0 && activeCount == 0 {
			continue
		}
		result[id] = service.QuotaDisplayMeta{PerUserLimit: perUserLimit, ActiveCount: activeCount}
	}
	return result, nil
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
