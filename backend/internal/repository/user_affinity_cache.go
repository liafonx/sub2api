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
//	user_affinity:{groupID}:{userID}           → accountID (STRING, TTL = time until next reset hour)
//	user_affinity_count:{groupID}:{accountID}  → count     (STRING INCR, same TTL)
const (
	userAffinityPrefix      = "user_affinity:"
	userAffinityCountPrefix = "user_affinity_count:"
	userAffinityDefaultTTL  = 24 * time.Hour
)

// incrAffinityCountScript atomically increments the count key and sets its TTL.
// KEYS[1] = key, ARGV[1] = ttl seconds
var incrAffinityCountScript = redis.NewScript(`
local key = KEYS[1]
local ttl = tonumber(ARGV[1])
local val = redis.call("INCR", key)
redis.call("EXPIRE", key, ttl)
return val
`)

// decrAffinityCountScript atomically decrements the count key with floor at 0.
// KEYS[1] = key
var decrAffinityCountScript = redis.NewScript(`
local key = KEYS[1]
local val = redis.call("GET", key)
if not val then return 0 end
local n = tonumber(val)
if n and n > 0 then
    return redis.call("DECR", key)
end
return 0
`)

type userAffinityCache struct {
	rdb *redis.Client
}

// NewUserAffinityCache creates a Redis-backed UserAffinityCache.
func NewUserAffinityCache(rdb *redis.Client) service.UserAffinityCache {
	return &userAffinityCache{rdb: rdb}
}

func affinityKey(groupID, userID int64) string {
	return fmt.Sprintf("%s%d:%d", userAffinityPrefix, groupID, userID)
}

func affinityCountKey(groupID, accountID int64) string {
	return fmt.Sprintf("%s%d:%d", userAffinityCountPrefix, groupID, accountID)
}

func (c *userAffinityCache) GetAffinity(ctx context.Context, groupID, userID int64) (int64, error) {
	val, err := c.rdb.Get(ctx, affinityKey(groupID, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("GetAffinity: %w", err)
	}
	id, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("GetAffinity parse: %w", err)
	}
	return id, nil
}

func (c *userAffinityCache) SetAffinity(ctx context.Context, groupID, userID, accountID int64, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = userAffinityDefaultTTL
	}
	return c.rdb.Set(ctx, affinityKey(groupID, userID), strconv.FormatInt(accountID, 10), ttl).Err()
}

func (c *userAffinityCache) DeleteAffinity(ctx context.Context, groupID, userID int64) error {
	return c.rdb.Del(ctx, affinityKey(groupID, userID)).Err()
}

func (c *userAffinityCache) GetAffinityUserCounts(ctx context.Context, groupID int64, accountIDs []int64) (map[int64]int64, error) {
	if len(accountIDs) == 0 {
		return map[int64]int64{}, nil
	}
	pipe := c.rdb.Pipeline()
	cmds := make(map[int64]*redis.StringCmd, len(accountIDs))
	for _, id := range accountIDs {
		cmds[id] = pipe.Get(ctx, affinityCountKey(groupID, id))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("GetAffinityUserCounts: %w", err)
	}
	result := make(map[int64]int64, len(accountIDs))
	for id, cmd := range cmds {
		val, err := cmd.Result()
		if errors.Is(err, redis.Nil) {
			result[id] = 0
			continue
		}
		if err != nil {
			result[id] = 0
			continue
		}
		n, _ := strconv.ParseInt(val, 10, 64)
		result[id] = n
	}
	return result, nil
}

func (c *userAffinityCache) IncrAffinityCount(ctx context.Context, groupID, accountID int64, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = userAffinityDefaultTTL
	}
	key := affinityCountKey(groupID, accountID)
	ttlSecs := int64(ttl.Seconds())
	if err := incrAffinityCountScript.Run(ctx, c.rdb, []string{key}, ttlSecs).Err(); err != nil {
		return fmt.Errorf("IncrAffinityCount: %w", err)
	}
	return nil
}

func (c *userAffinityCache) DecrAffinityCount(ctx context.Context, groupID, accountID int64) error {
	key := affinityCountKey(groupID, accountID)
	if err := decrAffinityCountScript.Run(ctx, c.rdb, []string{key}).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("DecrAffinityCount: %w", err)
	}
	return nil
}
