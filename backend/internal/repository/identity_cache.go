package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

const (
	fingerprintKeyPrefix   = "fingerprint:"
	fingerprintTTL         = 7 * 24 * time.Hour // 7天，配合每24小时懒续期可保持活跃账号永不过期
	maskedSessionKeyPrefix = "masked_session:"
	maskedSessionTTL       = 15 * time.Minute
	userSessionKeyPrefix   = "user_session:"
	userSessionTTL         = 30 * time.Minute
)

// fingerprintKey generates the Redis key for account fingerprint cache.
func fingerprintKey(accountID int64) string {
	return fmt.Sprintf("%s%d", fingerprintKeyPrefix, accountID)
}

// maskedSessionKey generates the Redis key for masked session ID cache.
func maskedSessionKey(accountID int64) string {
	return fmt.Sprintf("%s%d", maskedSessionKeyPrefix, accountID)
}

// userSessionKey generates the Redis key for per-(account, user) session cache.
// Scoped like user_acct_rpm:<accountID>:<userID>:... so the same upstream account
// gives each sub2api user a distinct, stable mimic session UUID.
func userSessionKey(accountID, userID int64) string {
	return fmt.Sprintf("%s%d:%d", userSessionKeyPrefix, accountID, userID)
}

type identityCache struct {
	rdb *redis.Client
}

func NewIdentityCache(rdb *redis.Client) service.IdentityCache {
	return &identityCache{rdb: rdb}
}

func (c *identityCache) GetFingerprint(ctx context.Context, accountID int64) (*service.Fingerprint, error) {
	key := fingerprintKey(accountID)
	val, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	var fp service.Fingerprint
	if err := json.Unmarshal([]byte(val), &fp); err != nil {
		return nil, err
	}
	return &fp, nil
}

func (c *identityCache) SetFingerprint(ctx context.Context, accountID int64, fp *service.Fingerprint) error {
	key := fingerprintKey(accountID)
	val, err := json.Marshal(fp)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, key, val, fingerprintTTL).Err()
}

func (c *identityCache) GetMaskedSessionID(ctx context.Context, accountID int64) (string, error) {
	key := maskedSessionKey(accountID)
	val, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

func (c *identityCache) SetMaskedSessionID(ctx context.Context, accountID int64, sessionID string) error {
	key := maskedSessionKey(accountID)
	return c.rdb.Set(ctx, key, sessionID, maskedSessionTTL).Err()
}

// GetUserSessionID returns the cached mimic-mode session UUID for a
// (accountID, userID) pair, or empty string when absent / expired.
func (c *identityCache) GetUserSessionID(ctx context.Context, accountID, userID int64) (string, error) {
	key := userSessionKey(accountID, userID)
	val, err := c.rdb.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

// SetUserSessionID writes (or refreshes the TTL of) the per-(account, user)
// mimic-mode session UUID. TTL is rolling — every call resets the idle timer.
func (c *identityCache) SetUserSessionID(ctx context.Context, accountID, userID int64, sessionID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = userSessionTTL
	}
	key := userSessionKey(accountID, userID)
	return c.rdb.Set(ctx, key, sessionID, ttl).Err()
}
