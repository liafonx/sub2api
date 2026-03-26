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
	ccTraitSnapshotKey = "cc_trait_snapshot:latest"
	ccTraitSnapshotTTL = 30 * 24 * time.Hour // 30 days
)

type ccTraitRegistryCache struct {
	rdb *redis.Client
}

// NewCCTraitRegistryCache creates a Redis-backed CCTraitRegistryCache.
func NewCCTraitRegistryCache(rdb *redis.Client) service.CCTraitRegistryCache {
	return &ccTraitRegistryCache{rdb: rdb}
}

func (c *ccTraitRegistryCache) GetSnapshot(ctx context.Context) (*service.CCTraitSnapshot, error) {
	val, err := c.rdb.Get(ctx, ccTraitSnapshotKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("GetSnapshot get: %w", err)
	}
	var snap service.CCTraitSnapshot
	if err := json.Unmarshal([]byte(val), &snap); err != nil {
		return nil, fmt.Errorf("GetSnapshot unmarshal: %w", err)
	}
	return &snap, nil
}

func (c *ccTraitRegistryCache) SetSnapshot(ctx context.Context, snap *service.CCTraitSnapshot) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("SetSnapshot marshal: %w", err)
	}
	return c.rdb.Set(ctx, ccTraitSnapshotKey, data, ccTraitSnapshotTTL).Err()
}
