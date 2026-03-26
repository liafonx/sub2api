package service

import (
	"context"
	"log"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/Wei-Shaw/sub2api/ent"
	entpeakusage "github.com/Wei-Shaw/sub2api/ent/peakusage"
)

// PeakDTO is the response DTO for entity peak usage (account or user).
type PeakDTO struct {
	EntityID    int64  `json:"entity_id"`
	EntityName  string `json:"entity_name"`
	EntityLabel string `json:"entity_label"` // platform (account) or email (user)

	PeakConcurrency int `json:"peak_concurrency"`
	PeakSessions    int `json:"peak_sessions"`
	PeakRPM         int `json:"peak_rpm"`

	MaxConcurrency int `json:"max_concurrency,omitempty"`
	MaxSessions    int `json:"max_sessions,omitempty"`
	MaxRPM         int `json:"max_rpm,omitempty"`

	ResetAt   *time.Time `json:"reset_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// peakUpdatedAtExpr is the SQL CASE expression used in ON CONFLICT DO UPDATE.
// It advances updated_at only when at least one peak value actually increased,
// preventing flush heartbeats from overwriting a meaningful "last peak change" time.
var peakUpdatedAtExpr = entsql.ExprFunc(func(b *entsql.Builder) {
	b.WriteString(
		"CASE WHEN EXCLUDED.peak_concurrency > peak_usages.peak_concurrency" +
			" OR EXCLUDED.peak_sessions > peak_usages.peak_sessions" +
			" OR EXCLUDED.peak_rpm > peak_usages.peak_rpm" +
			" THEN EXCLUDED.updated_at ELSE peak_usages.updated_at END",
	)
})

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

	// Use all account IDs (including disabled/paused) so peaks are never lost.
	accountIDs, err := s.entClient.Account.Query().IDs(ctx)
	if err != nil {
		log.Printf("[PeakUsageService] FlushPeaksFromRedis: list account IDs failed: %v", err)
	} else if len(accountIDs) > 0 {
		peaks, err := s.peakCache.GetAllPeaks(ctx, EntityTypeAccount, accountIDs)
		if err != nil {
			log.Printf("[PeakUsageService] FlushPeaksFromRedis: get account peaks failed: %v", err)
		} else {
			s.upsertPeaks(ctx, EntityTypeAccount, peaks)
		}
	}

	userIDs, err := s.userRepo.ListAllIDs(ctx)
	if err != nil {
		log.Printf("[PeakUsageService] FlushPeaksFromRedis: list users failed: %v", err)
	}

	if len(userIDs) > 0 {
		peaks, err := s.peakCache.GetAllPeaks(ctx, EntityTypeUser, userIDs)
		if err != nil {
			log.Printf("[PeakUsageService] FlushPeaksFromRedis: get user peaks failed: %v", err)
		} else {
			s.upsertPeaks(ctx, EntityTypeUser, peaks)
		}
	}
}

// upsertPeaks writes peak values to the DB using bulk upsert (at most 2 SQL calls).
// Entries are split by whether reset_at is set, since the conflict update clause differs.
func (s *PeakUsageService) upsertPeaks(ctx context.Context, entityType string, peaks map[int64]*PeakValues) {
	if len(peaks) == 0 {
		return
	}
	now := time.Now()
	conflictCols := []string{entpeakusage.FieldEntityType, entpeakusage.FieldEntityID}

	var withReset, withoutReset []*ent.PeakUsageCreate
	for id, v := range peaks {
		if v == nil {
			continue
		}
		// Skip all-zero entries to avoid overwriting DB peaks after a Redis restart.
		if v.Concurrency == 0 && v.Sessions == 0 && v.RPM == 0 {
			continue
		}
		b := s.entClient.PeakUsage.Create().
			SetEntityType(entityType).
			SetEntityID(id).
			SetPeakConcurrency(v.Concurrency).
			SetPeakSessions(v.Sessions).
			SetPeakRpm(v.RPM).
			SetUpdatedAt(now)
		if !v.ResetAt.IsZero() {
			withReset = append(withReset, b.SetResetAt(v.ResetAt))
		} else {
			withoutReset = append(withoutReset, b)
		}
	}

	if len(withoutReset) > 0 {
		if err := s.entClient.PeakUsage.CreateBulk(withoutReset...).
			OnConflict(
				entsql.ConflictColumns(conflictCols...),
				entsql.ResolveWith(func(u *entsql.UpdateSet) {
					u.SetExcluded(entpeakusage.FieldPeakConcurrency)
					u.SetExcluded(entpeakusage.FieldPeakSessions)
					u.SetExcluded(entpeakusage.FieldPeakRpm)
					u.SetNull(entpeakusage.FieldResetAt)
					u.Set(entpeakusage.FieldUpdatedAt, peakUpdatedAtExpr)
				}),
			).
			Exec(ctx); err != nil {
			log.Printf("[PeakUsageService] upsertPeaks: bulk upsert failed for %s: %v", entityType, err)
		}
	}

	if len(withReset) > 0 {
		if err := s.entClient.PeakUsage.CreateBulk(withReset...).
			OnConflict(
				entsql.ConflictColumns(conflictCols...),
				entsql.ResolveWith(func(u *entsql.UpdateSet) {
					u.SetExcluded(entpeakusage.FieldPeakConcurrency)
					u.SetExcluded(entpeakusage.FieldPeakSessions)
					u.SetExcluded(entpeakusage.FieldPeakRpm)
					u.SetExcluded(entpeakusage.FieldResetAt)
					u.Set(entpeakusage.FieldUpdatedAt, peakUpdatedAtExpr)
				}),
			).
			Exec(ctx); err != nil {
			log.Printf("[PeakUsageService] upsertPeaks: bulk upsert (with-reset) failed for %s: %v", entityType, err)
		}
	}
}

// getPeaks queries DB peak rows and calls enrich to populate entity-specific fields.
func (s *PeakUsageService) getPeaks(ctx context.Context, entityType string, enrich func([]*ent.PeakUsage, []PeakDTO)) ([]PeakDTO, error) {
	rows, err := s.entClient.PeakUsage.Query().
		Where(entpeakusage.EntityTypeEQ(entityType)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []PeakDTO{}, nil
	}
	dtos := make([]PeakDTO, len(rows))
	for i, r := range rows {
		updatedAt := r.UpdatedAt
		dtos[i] = PeakDTO{
			EntityID:        r.EntityID,
			PeakConcurrency: r.PeakConcurrency,
			PeakSessions:    r.PeakSessions,
			PeakRPM:         r.PeakRpm,
			ResetAt:         r.ResetAt,
			UpdatedAt:       &updatedAt,
		}
	}
	enrich(rows, dtos)

	// Filter out orphaned entries (soft-deleted entities) whose name resolved to empty.
	filtered := dtos[:0]
	for _, d := range dtos {
		if d.EntityName != "" {
			filtered = append(filtered, d)
		}
	}
	return filtered, nil
}

// GetAccountPeaks returns peak usage records for all accounts, enriched with name and platform.
func (s *PeakUsageService) GetAccountPeaks(ctx context.Context) ([]PeakDTO, error) {
	return s.getPeaks(ctx, EntityTypeAccount, func(rows []*ent.PeakUsage, dtos []PeakDTO) {
		ids := make([]int64, len(rows))
		for i, r := range rows {
			ids[i] = r.EntityID
		}
		accounts, err := s.accountRepo.GetByIDs(ctx, ids)
		if err != nil {
			log.Printf("[PeakUsageService] GetAccountPeaks: load accounts failed: %v", err)
			return
		}
		accountMap := make(map[int64]*Account, len(accounts))
		for _, a := range accounts {
			accountMap[a.ID] = a
		}
		for i, r := range rows {
			if a, ok := accountMap[r.EntityID]; ok {
				dtos[i].EntityName = a.Name
				dtos[i].EntityLabel = a.Platform
				dtos[i].MaxConcurrency = a.Concurrency
				dtos[i].MaxSessions = a.GetMaxSessions()
				dtos[i].MaxRPM = a.GetBaseRPM()
			}
		}
	})
}

// GetUserPeaks returns peak usage records for all users, enriched with username and email.
func (s *PeakUsageService) GetUserPeaks(ctx context.Context) ([]PeakDTO, error) {
	return s.getPeaks(ctx, EntityTypeUser, func(rows []*ent.PeakUsage, dtos []PeakDTO) {
		ids := make([]int64, len(rows))
		for i, r := range rows {
			ids[i] = r.EntityID
		}
		users, err := s.userRepo.GetByIDs(ctx, ids)
		if err != nil {
			log.Printf("[PeakUsageService] GetUserPeaks: load users failed: %v", err)
			return
		}
		userMap := make(map[int64]*User, len(users))
		for _, u := range users {
			userMap[u.ID] = u
		}
		for i, r := range rows {
			if u, ok := userMap[r.EntityID]; ok {
				dtos[i].EntityName = u.Email
				dtos[i].EntityLabel = u.Email
				dtos[i].MaxConcurrency = u.Concurrency
			}
		}
	})
}

// ResetAllPeaks zeroes peak values in both Redis and the DB for the given entity type.
// entityType must be EntityTypeAccount or EntityTypeUser.
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
