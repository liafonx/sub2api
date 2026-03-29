package admin

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type PeakUsageHandler struct {
	peakUsageService *service.PeakUsageService
}

func NewPeakUsageHandler(svc *service.PeakUsageService) *PeakUsageHandler {
	return &PeakUsageHandler{peakUsageService: svc}
}

// GetAccountPeaks returns all-time peak usage for service accounts.
// GET /api/v1/admin/peak-usage/accounts
func (h *PeakUsageHandler) GetAccountPeaks(c *gin.Context) {
	dtos, err := h.peakUsageService.GetAccountPeaks(c.Request.Context())
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to get account peaks")
		return
	}
	response.Success(c, dtos)
}

// GetUserPeaks returns all-time peak usage for users.
// GET /api/v1/admin/peak-usage/users
func (h *PeakUsageHandler) GetUserPeaks(c *gin.Context) {
	dtos, err := h.peakUsageService.GetUserPeaks(c.Request.Context())
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to get user peaks")
		return
	}
	response.Success(c, dtos)
}

// ResetPeaks zeroes peak values for all entities of the given type.
// POST /api/v1/admin/peak-usage/reset
func (h *PeakUsageHandler) ResetPeaks(c *gin.Context) {
	var req struct {
		EntityType string `json:"entity_type" binding:"required,oneof=account user"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "entity_type must be 'account' or 'user'")
		return
	}
	if err := h.peakUsageService.ResetAllPeaks(c.Request.Context(), req.EntityType); err != nil {
		response.Error(c, http.StatusInternalServerError, "Failed to reset peaks")
		return
	}
	response.Success(c, nil)
}
