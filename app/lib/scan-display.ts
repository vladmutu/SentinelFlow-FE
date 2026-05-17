import {
  ScanJobResponse,
  ScanResultResponse,
  ScanStatus,
  MalwareStatus,
  RiskStatus,
  ScanMode,
} from "@/app/lib/api/scan-api";

// ============================================================================
// FORMATTING UTILITIES
// ============================================================================

export function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  if (seconds < 3600) {
    const minutes = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${minutes}m ${secs}s`;
  }
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

export function formatPackagesPerMinute(packagesPerMinute?: number): string {
  if (!packagesPerMinute) return "";
  return `~${Math.round(packagesPerMinute)} pkg/min`;
}

export function formatEstimatedTime(seconds?: number): string {
  if (!seconds || seconds < 0) return "";
  return `ETA: ${formatDuration(seconds)}`;
}

export function formatTimestampForDisplay(timestamp: string | null | undefined): string {
  if (!timestamp) return "-";
  try {
    const date = new Date(timestamp);
    return date.toLocaleString();
  } catch {
    return "-";
  }
}

export function formatDownloadCount(count?: number | null): string {
  if (!count) return "0";
  if (count >= 1_000_000) {
    return `${(count / 1_000_000).toFixed(1)}M`;
  }
  if (count >= 1_000) {
    return `${(count / 1_000).toFixed(1)}K`;
  }
  return String(count);
}

export function formatRiskScore(score: number): string {
  return `${Math.round(score * 100)}%`;
}

// ============================================================================
// STATUS BADGES & DISPLAY LOGIC
// ============================================================================

export function getScanStatusBadgeColor(status: ScanStatus): string {
  switch (status) {
    case "completed":
      return "emerald";
    case "running":
    case "pending":
      return "cyan";
    case "failed":
      return "rose";
    case "cancelled":
      return "slate";
    default:
      return "slate";
  }
}

export function getScanModeLabel(mode: ScanMode): string {
  switch (mode) {
    case "full":
      return "Full Scan";
    case "static_only":
      return "Static Only";
    case "static_dynamic":
      return "Static + Dynamic";
    case "dynamic_only":
      return "Dynamic Only";
    default:
      return mode;
  }
}

export function getMalwareStatusDisplay(status: MalwareStatus): {
  label: string;
  color: string;
  icon: string;
} {
  switch (status) {
    case "clean":
      return {
        label: "Clean",
        color: "emerald",
        icon: "✅",
      };
    case "malicious":
      return {
        label: "Malicious",
        color: "rose",
        icon: "⛔",
      };
    case "suspicious":
      return {
        label: "Suspicious",
        color: "amber",
        icon: "⚠️",
      };
    case "error":
      return {
        label: "Scan Error",
        color: "rose",
        icon: "❌",
      };
    case "unknown":
    default:
      return {
        label: "Unknown",
        color: "slate",
        icon: "❓",
      };
  }
}

export function getRiskStatusDisplay(status: RiskStatus): {
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
} {
  switch (status) {
    case "clean":
      return {
        label: "Clean",
        color: "emerald",
        bgColor: "emerald-500/15",
        borderColor: "emerald-400/50",
      };
    case "suspicious":
      return {
        label: "Suspicious",
        color: "amber",
        bgColor: "amber-500/15",
        borderColor: "amber-400/50",
      };
    case "malicious":
      return {
        label: "Malicious",
        color: "rose",
        bgColor: "rose-500/15",
        borderColor: "rose-400/50",
      };
    default:
      return {
        label: "Unknown",
        color: "slate",
        bgColor: "slate-500/15",
        borderColor: "slate-400/50",
      };
  }
}

// ============================================================================
// SCAN DISPLAY DERIVATION
// ============================================================================

export interface ScanDisplay {
  phase: "pending" | "running" | "completed" | "failed" | "cancelled";
  statusLabel: string;
  progressPercent: number;
  progressLabel: string;
  primaryCountLabel: string;
  secondaryCountLabel: string | null;
  etaLabel: string | null;
  speedLabel: string | null;
  elapsedLabel: string;
}

export function deriveScanDisplay(
  scanDetails: ScanJobResponse | null,
  liveProgress: number,
  isRunning: boolean,
  scanError: string | null,
): ScanDisplay {
  if (scanError) {
    return {
      phase: "failed",
      statusLabel: "Scan failed",
      progressPercent: liveProgress,
      progressLabel: "Failed",
      primaryCountLabel: scanError,
      secondaryCountLabel: null,
      etaLabel: null,
      speedLabel: null,
      elapsedLabel: formatDuration(scanDetails?.elapsed_seconds ?? 0),
    };
  }

  if (!scanDetails) {
    return {
      phase: "pending",
      statusLabel: "Waiting to start",
      progressPercent: 0,
      progressLabel: "0%",
      primaryCountLabel: "Pending scan start",
      secondaryCountLabel: null,
      etaLabel: null,
      speedLabel: null,
      elapsedLabel: "0s",
    };
  }

  const phase = scanDetails.status as "pending" | "running" | "completed" | "failed" | "cancelled";
  const progressPercent = Math.max(0, Math.min(100, scanDetails.progress_percent || 0));
  const progressLabel = `${Math.round(progressPercent)}%`;
  const elapsedLabel = formatDuration(scanDetails.elapsed_seconds);

  if (scanDetails.status === "completed") {
    const completedLabel = `${scanDetails.scanned_packages} / ${scanDetails.total_unique_packages} packages scanned`;
    return {
      phase: "completed",
      statusLabel: "Scan completed",
      progressPercent: 100,
      progressLabel: "100%",
      primaryCountLabel: completedLabel,
      secondaryCountLabel: null,
      etaLabel: null,
      speedLabel: null,
      elapsedLabel,
    };
  }

  if (scanDetails.status === "failed") {
    return {
      phase: "failed",
      statusLabel: "Scan failed",
      progressPercent: progressPercent,
      progressLabel,
      primaryCountLabel: scanDetails.error_message || "Scan failed with unknown error",
      secondaryCountLabel: null,
      etaLabel: null,
      speedLabel: null,
      elapsedLabel,
    };
  }

  if (scanDetails.status === "cancelled") {
    return {
      phase: "cancelled",
      statusLabel: "Scan cancelled",
      progressPercent: progressPercent,
      progressLabel,
      primaryCountLabel: `${scanDetails.scanned_packages} / ${scanDetails.total_unique_packages} packages processed before cancellation`,
      secondaryCountLabel: null,
      etaLabel: null,
      speedLabel: null,
      elapsedLabel,
    };
  }

  // Running or pending
  const primaryCountLabel = `${scanDetails.scanned_packages} / ${scanDetails.total_unique_packages} packages scanned`;
  const secondaryCountLabel = scanDetails.total_dependency_nodes
    ? `${scanDetails.total_dependency_nodes} total dependency nodes`
    : null;

  const speedLabel = formatPackagesPerMinute(scanDetails.packages_per_minute);
  const etaLabel = formatEstimatedTime(scanDetails.estimated_seconds_remaining);

  return {
    phase: isRunning ? "running" : "pending",
    statusLabel: isRunning ? "Scanning packages..." : "Waiting to start",
    progressPercent,
    progressLabel,
    primaryCountLabel,
    secondaryCountLabel,
    etaLabel: etaLabel || null,
    speedLabel: speedLabel || null,
    elapsedLabel,
  };
}

// ============================================================================
// RESULT HELPERS
// ============================================================================

export function computeScanProgress(
  scanDetails: ScanJobResponse,
  phase: string,
  fallbackProgress: number,
): number {
  if (scanDetails.progress_percent !== undefined) {
    return Math.max(0, Math.min(100, scanDetails.progress_percent));
  }

  if (phase === "completed") {
    return 100;
  }

  if (scanDetails.total_unique_packages > 0) {
    return Math.round((scanDetails.scanned_packages / scanDetails.total_unique_packages) * 100);
  }

  return fallbackProgress;
}

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

export function normalizeScanPhase(
  status: string,
  isRunning: boolean,
  isCompleted: boolean,
): string {
  if (["completed", "failed", "cancelled"].includes(status)) {
    return status;
  }
  if (isRunning) {
    return "running";
  }
  if (isCompleted) {
    return "completed";
  }
  return "pending";
}

export function normalizeStatusValue(status: unknown): string {
  if (typeof status === "string") {
    const lower = status.toLowerCase().trim();
    if (["pending", "running", "completed", "failed", "cancelled"].includes(lower)) {
      return lower;
    }
  }
  return "unknown";
}

export function isPollingStatus(status: string): boolean {
  return ["pending", "running"].includes(status);
}

// ============================================================================
// SCAN RESULT TERMINAL STATES
// ============================================================================

export const SCAN_TERMINAL_DONE = new Set(["completed", "success"]);
export const SCAN_TERMINAL_CANCELLED = new Set(["cancelled", "user_cancelled"]);
export const SCAN_TERMINAL_FAILED = new Set(["failed", "error"]);

export function isScanTerminal(status: string): boolean {
  return (
    SCAN_TERMINAL_DONE.has(status) ||
    SCAN_TERMINAL_CANCELLED.has(status) ||
    SCAN_TERMINAL_FAILED.has(status)
  );
}

// ============================================================================
// RESULT DEDUPLICATION & NORMALIZATION
// ============================================================================

export interface ScanResultRow {
  id: string;
  name: string;
  version: string;
  status: "clean" | "suspicious" | "malicious" | "error" | "unknown";
  score: number;
  advisories: string[];
  errorMessage: string | null;
}

export function buildResultDedupKey(row: ScanResultRow): string {
  return `${row.name}@${row.version}`;
}

export function normalizeResultMapFromRows(rows: ScanResultRow[]): Record<string, ScanResultRow> {
  const map: Record<string, ScanResultRow> = {};
  for (const row of rows) {
    const key = buildResultDedupKey(row);
    map[key] = row;
  }
  return map;
}

export function normalizeScanResultsPayload(
  payload: unknown,
): { rows: ScanResultRow[]; map: Record<string, ScanResultRow> } {
  const rows: ScanResultRow[] = [];

  if (payload && typeof payload === "object" && "results" in payload) {
    const record = payload as Record<string, unknown>;
    const results = Array.isArray(record.results) ? record.results : [];

    for (const result of results) {
      if (!result || typeof result !== "object") continue;
      const entry = result as Record<string, unknown>;

      const row: ScanResultRow = {
        id: typeof entry.id === "string" ? entry.id : Math.random().toString(),
        name: typeof entry.package_name === "string" ? entry.package_name : "",
        version: typeof entry.package_version === "string" ? entry.package_version : "",
        status: (["clean", "suspicious", "malicious", "error", "unknown"].includes(
          String(entry.risk_overall_status || entry.malware_status),
        )
          ? (entry.risk_overall_status || entry.malware_status)
          : "unknown") as any,
        score: typeof entry.risk_overall_score === "number" ? entry.risk_overall_score : 0,
        advisories: Array.isArray(entry.advisory_references)
          ? entry.advisory_references.filter((item): item is string => typeof item === "string")
          : [],
        errorMessage: typeof entry.error_message === "string" ? entry.error_message : null,
      };

      if (row.name) {
        rows.push(row);
      }
    }
  }

  return {
    rows,
    map: normalizeResultMapFromRows(rows),
  };
}

export interface LatestScanSummary {
  status: string | null;
  processed: number | null;
  total: number | null;
  completedAt: string | null;
}

export function normalizeLatestCompletedScan(payload: unknown): LatestScanSummary {
  if (!payload || typeof payload !== "object") {
    return {
      status: null,
      processed: null,
      total: null,
      completedAt: null,
    };
  }

  const record = payload as Record<string, unknown>;

  return {
    status: typeof record.status === "string" ? record.status : null,
    processed:
      typeof record.scanned_packages === "number" && record.scanned_packages >= 0
        ? record.scanned_packages
        : null,
    total:
      typeof record.total_unique_packages === "number" && record.total_unique_packages >= 0
        ? record.total_unique_packages
        : null,
    completedAt: typeof record.completed_at === "string" ? record.completed_at : null,
  };
}

// ============================================================================
// ERROR HANDLING FOR POLLING
// ============================================================================

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

// ============================================================================
// POLLING CONSTANTS
// ============================================================================

export const SCAN_POLL_INTERVAL_MS = 3000; // 3 seconds
export const SCAN_RETRY_MAX_DELAY_MS = 60000; // 1 minute max backoff
export const POLL_RETRY_SILENT_ATTEMPTS = 2; // Show error after 3 failures
export const POLL_ERROR_VISIBLE_RETRY_DELAY_MS = 5000; // 5 seconds for visible error retry
