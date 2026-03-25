package repository

import (
	"context"
	"encoding/json"
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
		return nil, err
	}
	var traits service.CCVersionTraits
	if err := json.Unmarshal([]byte(val), &traits); err != nil {
		return nil, err
	}
	return &traits, nil
}

func (c *ccProbeCache) SetCCTraits(ctx context.Context, traits *service.CCVersionTraits) error {
	data, err := json.Marshal(traits)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, ccTraitsKey, data, ccTraitsTTL).Err()
}
