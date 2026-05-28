/**
 * SentinelFlow Scan API Adapter
 * 
 * This module bridges the new ScanApi utilities with the existing page component.
 * It converts between the page's internal state format and the API contract.
 */

import { ScanApiContext, ScanJobResponse as ApiScanJobResponse } from "@/app/lib/api/scan-api";
import { Ecosystem } from "@/app/types/dashboard";

// Map API types to page component types
export type ScanJobResponse = ApiScanJobResponse;

export interface ScanApiAdapter {
  baseUrl: string;
  authHeaders?: HeadersInit;
  owner: string;
  repoName: string;
}

export function buildScanApiContext(adapter: ScanApiAdapter): ScanApiContext {
  return {
    baseUrl: adapter.baseUrl,
    authHeaders: adapter.authHeaders,
    owner: adapter.owner,
    repoName: adapter.repoName,
  };
}

/**
 * Converts API ScanJobResponse to page component format
 */
export function normalizeApiScanJob(apiJob: ApiScanJobResponse): ScanJobResponse {
  return {
    id: apiJob.id,
    owner: apiJob.owner,
    repo_name: apiJob.repo_name,
    ecosystem: apiJob.ecosystem,
    scan_mode: apiJob.scan_mode,
    status: apiJob.status,
    total_packages: apiJob.total_packages,
    scanned_packages: apiJob.scanned_packages,
    total_dependency_nodes: apiJob.total_dependency_nodes,
    total_unique_packages: apiJob.total_unique_packages,
    progress_percent: apiJob.progress_percent,
    elapsed_seconds: apiJob.elapsed_seconds,
    packages_per_minute: apiJob.packages_per_minute,
    estimated_seconds_remaining: apiJob.estimated_seconds_remaining,
    error_message: apiJob.error_message,
    started_at: apiJob.started_at,
    completed_at: apiJob.completed_at,
    created_at: apiJob.created_at,
    results: apiJob.results,
  };
}

/**
 * Extracts status value from API response
 */
export function normalizeStatusValue(status: unknown): string {
  if (typeof status === "string") {
    const lower = status.toLowerCase().trim();
    if (["pending", "running", "completed", "failed", "cancelled"].includes(lower)) {
      return lower;
    }
  }
  return "unknown";
}

/**
 * Determines if a status is a polling status (not terminal)
 */
export function isPollingStatus(status: string): boolean {
  return ["pending", "running"].includes(status.toLowerCase());
}

/**
 * Maps error details from API error payloads
 */
export function extractErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  const record = payload as Record<string, unknown>;

  if (typeof record.detail === "string") {
    return record.detail;
  }

  if (typeof record.message === "string") {
    return record.message;
  }

  return null;
}

/**
 * Calculates poll error metadata for retry logic
 */
export interface PollErrorMeta {
  kind: "auth" | "not-found" | "other";
  status: number | null;
  message: string;
}

export function resolvePollErrorMeta(error: unknown): PollErrorMeta {
  if (error instanceof Error) {
    const anyError = error as any;
    const status = anyError.status ?? null;

    if (status === 401 || status === 403) {
      return {
        kind: "auth",
        status,
        message: "Your session expired. Please log in again.",
      };
    }

    if (status === 404) {
      return {
        kind: "not-found",
        status,
        message: "Scan job not found. It may have been deleted.",
      };
    }

    if (status && [502, 503, 504].includes(status)) {
      return {
        kind: "other",
        status,
        message: "Backend service temporarily unavailable.",
      };
    }

    return {
      kind: "other",
      status,
      message: error.message || "Failed to poll scan status.",
    };
  }

  return {
    kind: "other",
    status: null,
    message: "Unknown polling error.",
  };
}

/**
 * Normalizes elapsed time from API response
 */
export function normalizeLiveElapsedSeconds(scanDetails: ScanJobResponse): number {
  if (!scanDetails.started_at) {
    return scanDetails.elapsed_seconds || 0;
  }

  try {
    const startTime = new Date(scanDetails.started_at).getTime();
    const nowTime = Date.now();
    const elapsedMs = nowTime - startTime;
    const elapsedSecs = Math.floor(elapsedMs / 1000);
    return Math.max(0, elapsedSecs);
  } catch {
    return scanDetails.elapsed_seconds || 0;
  }
}

/**
 * Parse JSON safely from response
 */
export async function parseJsonSafe(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Build dedup key for scan results
 */
export function buildResultDedupKey(packageName: string, packageVersion: string): string {
  return `${packageName}@${packageVersion}`;
}

/**
 * Terminal state detection
 */
export const SCAN_TERMINAL_DONE = new Set(["completed", "success", "succeeded", "done"]);
export const SCAN_TERMINAL_FAILED = new Set(["failed", "error"]);
export const SCAN_TERMINAL_CANCELLED = new Set(["cancelled", "user_cancelled"]);

export function isScanTerminal(status: string): boolean {
  return (
    SCAN_TERMINAL_DONE.has(status) ||
    SCAN_TERMINAL_CANCELLED.has(status) ||
    SCAN_TERMINAL_FAILED.has(status)
  );
}

/**
 * Get color for scan mode
 */
export function getScanModeColor(scanMode: string): string {
  switch (scanMode) {
    case "full":
      return "blue";
    case "static_enrichment":
      return "purple";
    case "static":
      return "purple";
    case "lightweight":
      return "teal";
    case "dynamic":
      return "orange";
    default:
      return "slate";
  }
}

/**
 * Format scan mode label
 */
export function formatScanModeLabel(scanMode: string): string {
  switch (scanMode) {
    case "full":
      return "Full Scan";
    case "static_enrichment":
      return "Static + Enrichment";
    case "static":
      return "Static Analysis";
    case "lightweight":
      return "Lightweight (CVE + Reputation)";
    case "dynamic":
      return "Dynamic Analysis";
    default:
      return scanMode;
  }
}
