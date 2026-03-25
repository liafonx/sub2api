package admin

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/pkg/sysutil"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// SystemHandler handles system-related operations
type SystemHandler struct {
	updateSvc  *service.UpdateService
	lockSvc    *service.SystemOperationLockService
	ccProbeSvc *service.CCProbeService
}

// NewSystemHandler creates a new SystemHandler
func NewSystemHandler(updateSvc *service.UpdateService, lockSvc *service.SystemOperationLockService, ccProbeSvc *service.CCProbeService) *SystemHandler {
	return &SystemHandler{
		updateSvc:  updateSvc,
		lockSvc:    lockSvc,
		ccProbeSvc: ccProbeSvc,
	}
}

// GetVersion returns the current version
// GET /api/v1/admin/system/version
func (h *SystemHandler) GetVersion(c *gin.Context) {
	info, _ := h.updateSvc.CheckUpdate(c.Request.Context(), false)
	response.Success(c, gin.H{
		"version": info.CurrentVersion,
	})
}

// CheckUpdates checks for available updates
// GET /api/v1/admin/system/check-updates
func (h *SystemHandler) CheckUpdates(c *gin.Context) {
	force := c.Query("force") == "true"
	info, err := h.updateSvc.CheckUpdate(c.Request.Context(), force)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	response.Success(c, info)
}

// PerformUpdate downloads and applies the update
// POST /api/v1/admin/system/update
func (h *SystemHandler) PerformUpdate(c *gin.Context) {
	operationID := buildSystemOperationID(c, "update")
	payload := gin.H{"operation_id": operationID}
	executeAdminIdempotentJSON(c, "admin.system.update", payload, service.DefaultSystemOperationIdempotencyTTL(), func(ctx context.Context) (any, error) {
		lock, release, err := h.acquireSystemLock(ctx, operationID)
		if err != nil {
			return nil, err
		}
		var releaseReason string
		succeeded := false
		defer func() {
			release(releaseReason, succeeded)
		}()

		if err := h.updateSvc.PerformUpdate(ctx); err != nil {
			releaseReason = "SYSTEM_UPDATE_FAILED"
			return nil, err
		}
		succeeded = true

		return gin.H{
			"message":      "Update completed. Please restart the service.",
			"need_restart": true,
			"operation_id": lock.OperationID(),
		}, nil
	})
}

// Rollback restores the previous version
// POST /api/v1/admin/system/rollback
func (h *SystemHandler) Rollback(c *gin.Context) {
	operationID := buildSystemOperationID(c, "rollback")
	payload := gin.H{"operation_id": operationID}
	executeAdminIdempotentJSON(c, "admin.system.rollback", payload, service.DefaultSystemOperationIdempotencyTTL(), func(ctx context.Context) (any, error) {
		lock, release, err := h.acquireSystemLock(ctx, operationID)
		if err != nil {
			return nil, err
		}
		var releaseReason string
		succeeded := false
		defer func() {
			release(releaseReason, succeeded)
		}()

		if err := h.updateSvc.Rollback(); err != nil {
			releaseReason = "SYSTEM_ROLLBACK_FAILED"
			return nil, err
		}
		succeeded = true

		return gin.H{
			"message":      "Rollback completed. Please restart the service.",
			"need_restart": true,
			"operation_id": lock.OperationID(),
		}, nil
	})
}

// RestartService restarts the systemd service
// POST /api/v1/admin/system/restart
func (h *SystemHandler) RestartService(c *gin.Context) {
	operationID := buildSystemOperationID(c, "restart")
	payload := gin.H{"operation_id": operationID}
	executeAdminIdempotentJSON(c, "admin.system.restart", payload, service.DefaultSystemOperationIdempotencyTTL(), func(ctx context.Context) (any, error) {
		lock, release, err := h.acquireSystemLock(ctx, operationID)
		if err != nil {
			return nil, err
		}
		succeeded := false
		defer func() {
			release("", succeeded)
		}()

		// Schedule service restart in background after sending response
		// This ensures the client receives the success response before the service restarts
		go func() {
			// Wait a moment to ensure the response is sent
			time.Sleep(500 * time.Millisecond)
			sysutil.RestartServiceAsync()
		}()
		succeeded = true
		return gin.H{
			"message":      "Service restart initiated",
			"operation_id": lock.OperationID(),
		}, nil
	})
}

// GetTLSProfiles returns the list of registered TLS fingerprint profile names.
// GET /api/v1/admin/system/tls-profiles
func (h *SystemHandler) GetTLSProfiles(c *gin.Context) {
	names := tlsfingerprint.GlobalRegistry().ProfileNames()
	response.Success(c, gin.H{"profiles": names})
}

func (h *SystemHandler) acquireSystemLock(
	ctx context.Context,
	operationID string,
) (*service.SystemOperationLock, func(string, bool), error) {
	if h.lockSvc == nil {
		return nil, nil, service.ErrIdempotencyStoreUnavail
	}
	lock, err := h.lockSvc.Acquire(ctx, operationID)
	if err != nil {
		return nil, nil, err
	}
	release := func(reason string, succeeded bool) {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.lockSvc.Release(releaseCtx, lock, succeeded, reason)
	}
	return lock, release, nil
}

// GetCCProbeStatus returns current probe status.
// GET /api/v1/admin/system/cc-probe
func (h *SystemHandler) GetCCProbeStatus(c *gin.Context) {
	if h.ccProbeSvc == nil {
		response.Success(c, nil)
		return
	}
	traits := h.ccProbeSvc.GetLatestTraits()
	if traits == nil {
		response.Success(c, nil)
		return
	}
	response.Success(c, gin.H{
		"cc_version":  traits.CCVersion,
		"headers":     traits.Headers,
		"captured_at": traits.CapturedAt,
	})
}

// GetCCProbeConfig returns the read-only cc_probe configuration.
// GET /api/v1/admin/system/cc-probe/config
func (h *SystemHandler) GetCCProbeConfig(c *gin.Context) {
	if h.ccProbeSvc == nil {
		response.Success(c, nil)
		return
	}
	response.Success(c, h.ccProbeSvc.PublicConfig())
}

// TriggerCCProbe triggers an on-demand probe.
// POST /api/v1/admin/system/cc-probe/trigger
func (h *SystemHandler) TriggerCCProbe(c *gin.Context) {
	slog.Info("admin.cc_probe.trigger_requested")
	if h.ccProbeSvc == nil {
		response.Error(c, http.StatusBadRequest, "CC probe service not configured")
		return
	}
	if err := h.ccProbeSvc.ProbeInstalledCC(c.Request.Context()); err != nil {
		response.Error(c, http.StatusInternalServerError, "probe failed: "+err.Error())
		return
	}
	traits := h.ccProbeSvc.GetLatestTraits()
	if traits == nil {
		response.Error(c, http.StatusInternalServerError, "probe completed but no traits captured")
		return
	}
	slog.Info("admin.cc_probe.trigger_complete", "cc_version", traits.CCVersion)
	response.Success(c, gin.H{
		"cc_version":  traits.CCVersion,
		"headers":     traits.Headers,
		"captured_at": traits.CapturedAt,
	})
}

func buildSystemOperationID(c *gin.Context, operation string) string {
	key := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if key == "" {
		return "sysop-" + operation + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	actorScope := "admin:0"
	if subject, ok := middleware2.GetAuthSubjectFromContext(c); ok {
		actorScope = "admin:" + strconv.FormatInt(subject.UserID, 10)
	}
	seed := operation + "|" + actorScope + "|" + c.FullPath() + "|" + key
	hash := service.HashIdempotencyKey(seed)
	if len(hash) > 24 {
		hash = hash[:24]
	}
	return "sysop-" + hash
}
