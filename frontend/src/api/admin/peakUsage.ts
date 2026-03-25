/**
 * Admin Peak Usage API endpoints
 * Handles peak usage log retrieval and reset for accounts and users
 */

import { apiClient } from "../client";
import type { PeakUsageEntry } from "@/types";

export interface PeakUsageListResponse {
  data: PeakUsageEntry[];
}

export interface ResetPeaksRequest {
  entity_type: "account" | "user";
}

export interface ResetPeaksResponse {
  message: string;
}

/**
 * Get peak usage records for all accounts
 */
async function getAccountPeaks(): Promise<PeakUsageListResponse> {
  const { data } = await apiClient.get<PeakUsageListResponse>(
    "/admin/peak-usage/accounts",
  );
  return data;
}

/**
 * Get peak usage records for all users
 */
async function getUserPeaks(): Promise<PeakUsageListResponse> {
  const { data } = await apiClient.get<PeakUsageListResponse>(
    "/admin/peak-usage/users",
  );
  return data;
}

/**
 * Reset all peak usage records for the given entity type
 * @param entityType - 'account' or 'user'
 */
async function resetPeaks(
  entityType: "account" | "user",
): Promise<ResetPeaksResponse> {
  const { data } = await apiClient.post<ResetPeaksResponse>(
    "/admin/peak-usage/reset",
    {
      entity_type: entityType,
    },
  );
  return data;
}

export const peakUsageAPI = {
  getAccountPeaks,
  getUserPeaks,
  resetPeaks,
};

export default peakUsageAPI;
