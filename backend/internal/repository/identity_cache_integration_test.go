//go:build integration

package repository

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type IdentityCacheSuite struct {
	IntegrationRedisSuite
	cache *identityCache
}

func (s *IdentityCacheSuite) SetupTest() {
	s.IntegrationRedisSuite.SetupTest()
	s.cache = NewIdentityCache(s.rdb).(*identityCache)
}

func (s *IdentityCacheSuite) TestGetFingerprint_Missing() {
	_, err := s.cache.GetFingerprint(s.ctx, 1)
	require.True(s.T(), errors.Is(err, redis.Nil), "expected redis.Nil for missing fingerprint")
}

func (s *IdentityCacheSuite) TestSetAndGetFingerprint() {
	fp := &service.Fingerprint{ClientID: "c1", UserAgent: "ua"}
	require.NoError(s.T(), s.cache.SetFingerprint(s.ctx, 1, fp), "SetFingerprint")
	gotFP, err := s.cache.GetFingerprint(s.ctx, 1)
	require.NoError(s.T(), err, "GetFingerprint")
	require.Equal(s.T(), "c1", gotFP.ClientID)
	require.Equal(s.T(), "ua", gotFP.UserAgent)
}

func (s *IdentityCacheSuite) TestFingerprint_TTL() {
	fp := &service.Fingerprint{ClientID: "c1", UserAgent: "ua"}
	require.NoError(s.T(), s.cache.SetFingerprint(s.ctx, 2, fp))

	fpKey := fmt.Sprintf("%s%d", fingerprintKeyPrefix, 2)
	ttl, err := s.rdb.TTL(s.ctx, fpKey).Result()
	require.NoError(s.T(), err, "TTL fpKey")
	s.AssertTTLWithin(ttl, 1*time.Second, fingerprintTTL)
}

func (s *IdentityCacheSuite) TestGetFingerprint_JSONCorruption() {
	fpKey := fmt.Sprintf("%s%d", fingerprintKeyPrefix, 999)
	require.NoError(s.T(), s.rdb.Set(s.ctx, fpKey, "invalid-json-data", 1*time.Minute).Err(), "Set invalid JSON")

	_, err := s.cache.GetFingerprint(s.ctx, 999)
	require.Error(s.T(), err, "expected error for corrupted JSON")
	require.False(s.T(), errors.Is(err, redis.Nil), "expected decoding error, not redis.Nil")
}

func (s *IdentityCacheSuite) TestSetFingerprint_Nil() {
	err := s.cache.SetFingerprint(s.ctx, 100, nil)
	require.NoError(s.T(), err, "SetFingerprint(nil) should succeed")
}

func (s *IdentityCacheSuite) TestUserSessionID_MissingReturnsEmpty() {
	got, err := s.cache.GetUserSessionID(s.ctx, 1, 42)
	require.NoError(s.T(), err, "missing key should yield empty + nil err")
	require.Equal(s.T(), "", got)
}

func (s *IdentityCacheSuite) TestUserSessionID_Roundtrip() {
	sessionID := "11111111-2222-4333-8444-555555555555"
	require.NoError(s.T(), s.cache.SetUserSessionID(s.ctx, 7, 99, sessionID, userSessionTTL))

	got, err := s.cache.GetUserSessionID(s.ctx, 7, 99)
	require.NoError(s.T(), err)
	require.Equal(s.T(), sessionID, got)

	// Different user on same account must not collide.
	other, err := s.cache.GetUserSessionID(s.ctx, 7, 100)
	require.NoError(s.T(), err)
	require.Equal(s.T(), "", other)
}

func (s *IdentityCacheSuite) TestUserSessionID_TTLRefreshOnRepeatSet() {
	sessionID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	key := userSessionKey(3, 4)

	require.NoError(s.T(), s.cache.SetUserSessionID(s.ctx, 3, 4, sessionID, 5*time.Second))
	ttl1, err := s.rdb.TTL(s.ctx, key).Result()
	require.NoError(s.T(), err)
	require.True(s.T(), ttl1 > 0 && ttl1 <= 5*time.Second, "initial TTL should be ≤ 5s, got %v", ttl1)

	// Repeat Set with the default TTL must extend the idle timer beyond the initial 5s.
	require.NoError(s.T(), s.cache.SetUserSessionID(s.ctx, 3, 4, sessionID, userSessionTTL))
	ttl2, err := s.rdb.TTL(s.ctx, key).Result()
	require.NoError(s.T(), err)
	require.True(s.T(), ttl2 > 5*time.Second, "rolling TTL should refresh beyond initial 5s, got %v", ttl2)
	s.AssertTTLWithin(ttl2, 1*time.Second, userSessionTTL)
}

func (s *IdentityCacheSuite) TestUserSessionID_ZeroTTLFallsBackToDefault() {
	require.NoError(s.T(), s.cache.SetUserSessionID(s.ctx, 5, 6, "sid-default", 0))

	ttl, err := s.rdb.TTL(s.ctx, userSessionKey(5, 6)).Result()
	require.NoError(s.T(), err)
	s.AssertTTLWithin(ttl, 1*time.Second, userSessionTTL)
}

func TestIdentityCacheSuite(t *testing.T) {
	suite.Run(t, new(IdentityCacheSuite))
}
