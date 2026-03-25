package service

import (
	"context"
	"log"
	"time"

	"github.com/Wei-Shaw/sub2api/ent"
	entpeakusage "github.com/Wei-Shaw/sub2api/ent/peakusage"
)

// AccountPeakDTO is the response DTO for account peak usage.
type AccountPeakDTO struct {
	EntityID    int64  `json:"entity_id"`
	EntityName  string `json:"entity_name"`
	EntityLabel string `json:"entity_label"` // platform

	PeakConcurrency int `json:"peak_concurrency"`
	PeakSessions    int `json:"peak_sessions"`
	PeakRPM         int `json:"peak_rpm"`

	MaxConcurrency int `json:"max_concurrency,omitempty"`
	MaxSessions    int `json:"max_sessions,omitempty"`
	MaxRPM         int `json:"max_rpm,omitempty"`

	ResetAt *time.Time `json:"reset_at,omitempty"`
}

// UserPeakDTO is the response DTO for user peak usage.
type UserPeakDTO struct {
	EntityID    int64  `json:"entity_id"`
	EntityName  string `json:"entity_name"`
	EntityLabel string `json:"entity_label"` // email

	PeakConcurrency int `json:"peak_concurrency"`
	PeakSessions    int `json:"peak_sessions"`
	PeakRPM         int `json:"peak_rpm"`

	MaxConcurrency int `json:"max_concurrency,omitempty"`
	MaxSessions    int `json:"max_sessions,omitempty"`
	MaxRPM         int `json:"max_rpm,omitempty"`

	ResetAt *time.Time `json:"reset_at,omitempty"`
}

// PeakUsageService manages peak usage persistence and retrieval.
type PeakUsageService struct {
	entClient   *ent.Client
	peakCache   PeakUsageCache
	accountRepo AccountRepository
	userRepo    UserRepository
	timingWheel *TimingWheelService
}

// NewPeakUsageService creates a new PeakUsageService.
func NewPeakUsageService(
	entClient *ent.Client,
	peakCache PeakUsageCache,
	accountRepo AccountRepository,
	userRepo UserRepository,
	timingWheel *TimingWheelService,
) *PeakUsageService {
	return &PeakUsageService{
		entClient:   entClient,
		peakCache:   peakCache,
		accountRepo: accountRepo,
		userRepo:    userRepo,
		timingWheel: timingWheel,
	}
}

// Start schedules periodic Redis-to-DB flush every 5 minutes.
func (s *PeakUsageService) Start() {
	s.timingWheel.ScheduleRecurring("peak_usage:flush", 5*time.Minute, s.FlushPeaksFromRedis)
	log.Printf("[PeakUsageService] Started (flush interval: 5m)")
}

// Stop cancels the flush schedule and performs a final flush before shutdown.
func (s *PeakUsageService) Stop() {
	s.timingWheel.Cancel("peak_usage:flush")
	s.FlushPeaksFromRedis()
	log.Printf("[PeakUsageService] Stopped")
}

// FlushPeaksFromRedis reads current peaks from Redis and upserts them into the DB.
func (s *PeakUsageService) FlushPeaksFromRedis() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	accounts, err := s.accountRepo.ListSchedulable(ctx)
	if err != nil {
		log.Printf("[PeakUsageService] FlushPeaksFromRedis: list accounts failed: %v", err)
	} else if len(accounts) > 0 {
		accountIDs := make([]int64, len(accounts))
		for i, a := range accounts {
			accountIDs[i] = a.ID
		}
		peaks, err := s.peakCache.GetAllPeaks(ctx, "account", accountIDs)
		if err != nil {
			log.Printf("[PeakUsageService] FlushPeaksFromRedis: get account peaks failed: %v", err)
		} else {
			s.upsertPeaks(ctx, "account", peaks)
		}
	}

	userIDs, err := s.userRepo.ListAllIDs(ctx)
	if err != nil {
		log.Printf("[PeakUsageService] FlushPeaksFromRedis: list users failed: %v", err)
	}

	if len(userIDs) > 0 {
		peaks, err := s.peakCache.GetAllPeaks(ctx, "user", userIDs)
		if err != nil {
			log.Printf("[PeakUsageService] FlushPeaksFromRedis: get user peaks failed: %v", err)
		} else {
			s.upsertPeaks(ctx, "user", peaks)
		}
	}
}

// upsertPeaks writes peak values to the DB, updating on conflict.
func (s *PeakUsageService) upsertPeaks(ctx context.Context, entityType string, peaks map[int64]*PeakValues) {
	now := time.Now()
	for id, v := range peaks {
		if v == nil {
			continue
		}
		var resetAt *time.Time
		if !v.ResetAt.IsZero() {
			t := v.ResetAt
			resetAt = &t
		}
		err := s.entClient.PeakUsage.Create().
			SetEntityType(entityType).
			SetEntityID(id).
			SetPeakConcurrency(v.Concurrency).
			SetPeakSessions(v.Sessions).
			SetPeakRpm(v.RPM).
			SetNillableResetAt(resetAt).
			SetUpdatedAt(now).
			OnConflictColumns(entpeakusage.FieldEntityType, entpeakusage.FieldEntityID).
			Update(func(u *ent.PeakUsageUpsert) {
				u.SetPeakConcurrency(v.Concurrency)
				u.SetPeakSessions(v.Sessions)
				u.SetPeakRpm(v.RPM)
				if resetAt == nil {
					u.ClearResetAt()
				} else {
					u.SetResetAt(*resetAt)
				}
				u.SetUpdatedAt(now)
			}).
			Exec(ctx)
		if err != nil {
			log.Printf("[PeakUsageService] upsertPeaks: failed for %s/%d: %v", entityType, id, err)
		}
	}
}

// GetAccountPeaks returns peak usage records for all accounts, enriched with name and platform.
func (s *PeakUsageService) GetAccountPeaks(ctx context.Context) ([]AccountPeakDTO, error) {
	rows, err := s.entClient.PeakUsage.Query().
		Where(entpeakusage.EntityTypeEQ("account")).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []AccountPeakDTO{}, nil
	}

	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.EntityID
	}
	accounts, err := s.accountRepo.GetByIDs(ctx, ids)
	accountMap := make(map[int64]*Account, len(accounts))
	if err == nil {
		for _, a := range accounts {
			accountMap[a.ID] = a
		}
	}

	dtos := make([]AccountPeakDTO, 0, len(rows))
	for _, r := range rows {
		dto := AccountPeakDTO{
			EntityID:        r.EntityID,
			PeakConcurrency: r.PeakConcurrency,
			PeakSessions:    r.PeakSessions,
			PeakRPM:         r.PeakRpm,
			ResetAt:         r.ResetAt,
		}
		if a, ok := accountMap[r.EntityID]; ok {
			dto.EntityName = a.Name
			dto.EntityLabel = a.Platform
			dto.MaxConcurrency = a.Concurrency
		}
		dtos = append(dtos, dto)
	}
	return dtos, nil
}

// GetUserPeaks returns peak usage records for all users, enriched with username and email.
func (s *PeakUsageService) GetUserPeaks(ctx context.Context) ([]UserPeakDTO, error) {
	rows, err := s.entClient.PeakUsage.Query().
		Where(entpeakusage.EntityTypeEQ("user")).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []UserPeakDTO{}, nil
	}

	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.EntityID
	}
	users, _ := s.userRepo.GetByIDs(ctx, ids)
	userMap := make(map[int64]*User, len(users))
	for _, u := range users {
		userMap[u.ID] = u
	}

	dtos := make([]UserPeakDTO, 0, len(rows))
	for _, r := range rows {
		dto := UserPeakDTO{
			EntityID:        r.EntityID,
			PeakConcurrency: r.PeakConcurrency,
			PeakSessions:    r.PeakSessions,
			PeakRPM:         r.PeakRpm,
			ResetAt:         r.ResetAt,
		}
		if u, ok := userMap[r.EntityID]; ok {
			dto.EntityName = u.Username
			dto.EntityLabel = u.Email
		}
		dtos = append(dtos, dto)
	}
	return dtos, nil
}

// ResetAllPeaks zeroes peak values in both Redis and the DB for the given entity type.
func (s *PeakUsageService) ResetAllPeaks(ctx context.Context, entityType string) error {
	rows, err := s.entClient.PeakUsage.Query().
		Where(entpeakusage.EntityTypeEQ(entityType)).
		All(ctx)
	if err != nil {
		return err
	}

	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.EntityID
	}

	if len(ids) > 0 {
		if err := s.peakCache.ResetPeaks(ctx, entityType, ids); err != nil {
			log.Printf("[PeakUsageService] ResetAllPeaks: redis reset failed for %s: %v", entityType, err)
		}
	}

	now := time.Now()
	_, err = s.entClient.PeakUsage.Update().
		Where(entpeakusage.EntityTypeEQ(entityType)).
		SetPeakConcurrency(0).
		SetPeakSessions(0).
		SetPeakRpm(0).
		SetResetAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	return err
}
