/**
 * System API endpoints for admin operations
 */

import { apiClient } from "../client";

export interface ReleaseInfo {
  name: string;
  body: string;
  published_at: string;
  html_url: string;
}

export interface VersionInfo {
  current_version: string;
  latest_version: string;
  has_update: boolean;
  release_info?: ReleaseInfo;
  cached: boolean;
  warning?: string;
  build_type: string; // "source" for manual builds, "release" for CI builds
}

/**
 * Get current version
 */
export async function getVersion(): Promise<{ version: string }> {
  const { data } = await apiClient.get<{ version: string }>(
    "/admin/system/version",
  );
  return data;
}

/**
 * Check for updates
 * @param force - Force refresh from GitHub API
 */
export async function checkUpdates(force = false): Promise<VersionInfo> {
  const { data } = await apiClient.get<VersionInfo>(
    "/admin/system/check-updates",
    {
      params: force ? { force: "true" } : undefined,
    },
  );
  return data;
}

export interface UpdateResult {
  message: string;
  need_restart: boolean;
}

/**
 * Perform system update
 * Downloads and applies the latest version
 */
export async function performUpdate(): Promise<UpdateResult> {
  const { data } = await apiClient.post<UpdateResult>("/admin/system/update");
  return data;
}

/**
 * Rollback to previous version
 */
export async function rollback(): Promise<UpdateResult> {
  const { data } = await apiClient.post<UpdateResult>("/admin/system/rollback");
  return data;
}

/**
 * Restart the service
 */
export async function restartService(): Promise<{ message: string }> {
  const { data } = await apiClient.post<{ message: string }>(
    "/admin/system/restart",
  );
  return data;
}

/**
 * Get available TLS fingerprint profile names
 */
export async function getTLSProfiles(): Promise<string[]> {
  const { data } = await apiClient.get<{ profiles: string[] }>(
    "/admin/system/tls-profiles",
  );
  return data.profiles ?? [];
}

export interface CCProbeTraits {
  cc_version: string;
  headers: Record<string, string>;
  captured_at: string;
}

export interface CCProbeConfig {
  enabled: boolean;
  cc_binary_path: string;
  auto_update_cc: boolean;
  update_command: string;
  probe_model: string;
  check_interval_hours: number;
}

/**
 * Get current CC probe status (latest captured traits, or null if none)
 */
export async function getCCProbeStatus(): Promise<CCProbeTraits | null> {
  const { data } = await apiClient.get<CCProbeTraits | null>(
    "/admin/system/cc-probe",
  );
  return data ?? null;
}

/**
 * Get CC probe configuration (read-only view of config.yaml section)
 */
export async function getCCProbeConfig(): Promise<CCProbeConfig | null> {
  const { data } = await apiClient.get<CCProbeConfig | null>(
    "/admin/system/cc-probe/config",
  );
  return data ?? null;
}

/**
 * Trigger an on-demand CC probe
 */
export async function triggerCCProbe(): Promise<CCProbeTraits> {
  const { data } = await apiClient.post<CCProbeTraits>(
    "/admin/system/cc-probe/trigger",
  );
  return data;
}

export const systemAPI = {
  getVersion,
  checkUpdates,
  performUpdate,
  rollback,
  restartService,
  getTLSProfiles,
  getCCProbeStatus,
  getCCProbeConfig,
  triggerCCProbe,
};

export default systemAPI;
