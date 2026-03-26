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
	ccTraitsKey = "cc_version_traits:latest"
	ccTraitsTTL = 90 * 24 * time.Hour // 90 days
)

type ccProbeCache struct {
	rdb *redis.Client
}

// NewCCProbeCache creates a Redis-backed CCProbeCache.
func NewCCProbeCache(rdb *redis.Client) service.CCProbeCache {
	return &ccProbeCache{rdb: rdb}
}

func (c *ccProbeCache) GetCCTraits(ctx context.Context) (*service.CCVersionTraits, error) {
	val, err := c.rdb.Get(ctx, ccTraitsKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("GetCCTraits get: %w", err)
	}
	var traits service.CCVersionTraits
	if err := json.Unmarshal([]byte(val), &traits); err != nil {
		return nil, fmt.Errorf("GetCCTraits unmarshal: %w", err)
	}
	return &traits, nil
}

func (c *ccProbeCache) SetCCTraits(ctx context.Context, traits *service.CCVersionTraits) error {
	data, err := json.Marshal(traits)
	if err != nil {
		return fmt.Errorf("SetCCTraits marshal: %w", err)
	}
	return c.rdb.Set(ctx, ccTraitsKey, data, ccTraitsTTL).Err()
}
