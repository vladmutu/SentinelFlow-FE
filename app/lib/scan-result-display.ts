import {
  ScanResultResponse,
  StaticFeatures,
  DynamicFinding,
  ScanHistoryItem,
  ScanMode,
  RiskStatus,
} from "@/app/lib/api/scan-api";

// ============================================================================
// TYPES - Scan Result Display
// ============================================================================

export interface ScanResultDisplayCard {
  id: string;
  packageLabel: string;
  riskStatus: RiskStatus;
  riskScore: number;
  malwareStatus: string;
  advisories: string[];
  errorMessage: string | null;
  hasStaticFeatures: boolean;
  hasDynamicFindings: boolean;
}

export interface StaticFeaturesDisplay {
  entropy: {
    value: number;
    category: "low" | "medium" | "high";
    tooltip: string;
  };
  obfuscationScore: {
    value: number;
    percentage: number;
    risk: "safe" | "warning" | "critical";
    tooltip: string;
  };
  networkCalls: {
    value: number;
    risk: "safe" | "warning" | "critical";
    tooltip: string;
  };
  execCalls: {
    value: number;
    risk: "safe" | "warning" | "critical";
    tooltip: string;
  };
}

export interface DynamicFindingsDisplay {
  networkConnections: string[];
  fileWrites: string[];
  execCalls: string[];
  hasSuspiciousActivity: boolean;
}

// ============================================================================
// DISPLAY BUILDERS
// ============================================================================

export function buildScanResultCard(result: ScanResultResponse): ScanResultDisplayCard {
  return {
    id: result.id,
    packageLabel: `${result.package_name}@${result.package_version}`,
    riskStatus: result.risk_overall_status,
    riskScore: result.risk_overall_score,
    malwareStatus: result.malware_status,
    advisories: result.advisory_references || [],
    errorMessage: result.error_message,
    hasStaticFeatures: result.static_features !== undefined && result.static_features !== null,
    hasDynamicFindings: result.dynamic_findings !== undefined && result.dynamic_findings !== null,
  };
}

export function buildStaticFeaturesDisplay(features: StaticFeatures | null | undefined): StaticFeaturesDisplay | null {
  if (!features) {
    return null;
  }

  const entropy = features.max_entropy ?? 0;
  const obfuscationScore = features.obfuscation_index ?? 0;
  const networkCalls = features.network_imports ?? 0;
  const execCalls = features.exec_count ?? 0;

  return {
    entropy: {
      value: entropy,
      category: entropy > 5.5 ? "high" : entropy > 4.0 ? "medium" : "low",
      tooltip: "Shannon entropy — high values (>5.5) may indicate obfuscation or minification",
    },
    obfuscationScore: {
      value: obfuscationScore,
      percentage: Math.round(obfuscationScore * 100),
      risk: obfuscationScore > 0.5 ? "warning" : "safe",
      tooltip: "0–1 normalised obfuscation score",
    },
    networkCalls: {
      value: networkCalls,
      risk: networkCalls > 0 ? "warning" : "safe",
      tooltip: "Network imports detected during static analysis",
    },
    execCalls: {
      value: execCalls,
      risk: execCalls > 0 ? "warning" : "safe",
      tooltip: "exec() calls detected during static analysis",
    },
  };
}

export function buildDynamicFindingsDisplay(findings: DynamicFinding | null | undefined): DynamicFindingsDisplay | null {
  if (!findings) {
    return null;
  }

  const networkConnections = findings.network_activity?.destinations ?? [];
  const fileWrites = findings.filesystem_changes?.paths ?? [];
  const execCalls = findings.ioc_detail?.process_iocs ?? [];

  const hasSuspiciousActivity =
    networkConnections.length > 0 ||
    fileWrites.length > 0 ||
    execCalls.length > 0 ||
    findings.vm_evasion_observed === true;

  return {
    networkConnections,
    fileWrites,
    execCalls,
    hasSuspiciousActivity,
  };
}

// ============================================================================
// STATIC FEATURES FORMATTING
// ============================================================================

export function formatEntropyValue(entropy: number): {
  label: string;
  color: string;
  icon: string;
} {
  if (entropy > 5.5) {
    return {
      label: "High entropy (possible obfuscation)",
      color: "rose",
      icon: "⚠️",
    };
  }
  if (entropy > 4.0) {
    return {
      label: "Medium entropy",
      color: "amber",
      icon: "⏳",
    };
  }
  return {
    label: "Low entropy (likely readable)",
    color: "emerald",
    icon: "✓",
  };
}

export function formatDynamicCallCount(count: number, callType: string): string {
  if (count === 0) return "No " + callType;
  return `${count} ${callType}${count !== 1 ? "s" : ""}`;
}

export function hasHighStaticRisk(features: StaticFeaturesDisplay): boolean {
  return (
    features.entropy.category === "high" ||
    features.obfuscationScore.risk === "warning" ||
    features.execCalls.risk === "warning"
  );
}

export function hasHighDynamicRisk(findings: DynamicFindingsDisplay): boolean {
  return findings.hasSuspiciousActivity;
}

// ============================================================================
// ADVISORY DISPLAY
// ============================================================================

export interface AdvisoryDisplay {
  id: string;
  type: "CVE" | "GHSA" | "OTHER";
  url?: string;
}

export function parseAdvisoryId(ref: string): AdvisoryDisplay {
  const cveMatcher = /CVE-\d{4}-\d{4,5}/i;
  const ghsaMatcher = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i;

  if (cveMatcher.test(ref)) {
    return {
      id: ref,
      type: "CVE",
      url: `https://nvd.nist.gov/vuln/detail/${ref}`,
    };
  }

  if (ghsaMatcher.test(ref)) {
    return {
      id: ref,
      type: "GHSA",
      url: `https://github.com/advisories/${ref}`,
    };
  }

  return {
    id: ref,
    type: "OTHER",
  };
}

export function formatAdvisoryReferences(refs: string[]): AdvisoryDisplay[] {
  return refs.map(parseAdvisoryId);
}

export function hasAdvisories(advisories: string[]): boolean {
  return advisories && advisories.length > 0;
}

export function formatAdvisoryCount(count: number): string {
  if (count === 0) return "No advisories";
  return `${count} ${count === 1 ? "advisory" : "advisories"}`;
}

// ============================================================================
// SCAN HISTORY DISPLAY
// ============================================================================

export interface ScanHistoryDisplay {
  id: string;
  date: string;
  time: string;
  ecosystem: string;
  scanMode: string;
  scanModeColor: string;
  status: string;
  statusColor: string;
  packageCount: number;
  processedCount?: number;
  duration?: string;
  errorMessage?: string | null;
}

export function buildScanHistoryDisplay(item: ScanHistoryItem): ScanHistoryDisplay {
  const createdDate = new Date(item.created_at);
  const date = createdDate.toLocaleDateString();
  const time = createdDate.toLocaleTimeString();

  let duration: string | undefined;
  if (item.started_at && item.completed_at) {
    try {
      const startTime = new Date(item.started_at).getTime();
      const endTime = new Date(item.completed_at).getTime();
      const durationMs = endTime - startTime;
      const seconds = Math.floor(durationMs / 1000);
      const minutes = Math.floor(seconds / 60);
      const secs = seconds % 60;
      duration = minutes > 0 ? `${minutes}m ${secs}s` : `${secs}s`;
    } catch {
      duration = "N/A";
    }
  }

  return {
    id: item.id,
    date,
    time,
    ecosystem: item.ecosystem === "npm" ? "npm" : "PyPI",
    scanMode: formatScanModeDisplay(item.scan_mode),
    scanModeColor: getScanModeColor(item.scan_mode),
    status: item.status.charAt(0).toUpperCase() + item.status.slice(1),
    statusColor: getScanStatusColor(item.status),
    packageCount: item.total_packages,
    processedCount: item.processed_packages ?? item.scanned_packages,
    duration,
    errorMessage: item.error_message,
  };
}

export function formatScanModeDisplay(mode: ScanMode): string {
  switch (mode) {
    case "full":
      return "Full";
    case "static_only":
      return "Static";
    case "lightweight":
      return "Lightweight";
    case "dynamic_only":
      return "Dynamic";
    default:
      return mode;
  }
}

export function getScanModeColor(mode: ScanMode): string {
  switch (mode) {
    case "full":
      return "blue";
    case "static_only":
      return "purple";
    case "lightweight":
      return "teal";
    case "dynamic_only":
      return "orange";
    default:
      return "slate";
  }
}

export function getScanStatusColor(status: string): string {
  switch (status) {
    case "completed":
      return "emerald";
    case "running":
      return "cyan";
    case "pending":
      return "slate";
    case "failed":
      return "rose";
    case "cancelled":
      return "slate";
    default:
      return "slate";
  }
}

export function formatScanHistoryRow(item: ScanHistoryItem): {
  dateTime: string;
  ecosystem: string;
  scanMode: string;
  status: string;
  packages: string;
  duration?: string;
} {
  const display = buildScanHistoryDisplay(item);
  const dateTime = `${display.date} ${display.time}`;
  const packages =
    display.processedCount !== undefined
      ? `${display.processedCount} / ${display.packageCount}`
      : `${display.packageCount}`;

  return {
    dateTime,
    ecosystem: display.ecosystem,
    scanMode: display.scanMode,
    status: display.status,
    packages,
    duration: display.duration,
  };
}

// ============================================================================
// PAGINATION HELPERS
// ============================================================================

export function calculatePageCount(total: number, perPage: number): number {
  return Math.ceil(total / perPage);
}

export function getPaginationRange(page: number, perPage: number, total: number): {
  start: number;
  end: number;
  total: number;
} {
  const start = (page - 1) * perPage + 1;
  const end = Math.min(page * perPage, total);

  return { start, end, total };
}

export function canGoToPreviousPage(page: number): boolean {
  return page > 1;
}

export function canGoToNextPage(page: number, pageCount: number): boolean {
  return page < pageCount;
}

// ============================================================================
// ERROR DISPLAY HELPERS
// ============================================================================

export interface ScanErrorDisplay {
  title: string;
  message: string;
  actionable: boolean;
  actionLabel?: string;
}

export function buildScanErrorDisplay(error: string | null): ScanErrorDisplay | null {
  if (!error) return null;

  if (error.includes("401") || error.includes("Unauthorized")) {
    return {
      title: "Authentication Error",
      message: "Your session has expired. Please log in again.",
      actionable: true,
      actionLabel: "Login",
    };
  }

  if (error.includes("404")) {
    return {
      title: "Not Found",
      message: "The scan job was not found. It may have been deleted.",
      actionable: false,
    };
  }

  if (error.includes("502") || error.includes("503")) {
    return {
      title: "Service Unavailable",
      message: "The backend service is temporarily unavailable. Please try again later.",
      actionable: false,
    };
  }

  if (error.includes("timeout") || error.includes("Timeout")) {
    return {
      title: "Request Timeout",
      message: "The request took too long. Please try again.",
      actionable: true,
      actionLabel: "Retry",
    };
  }

  return {
    title: "Scan Error",
    message: error || "An unknown error occurred.",
    actionable: false,
  };
}

// ============================================================================
// SUMMARY HELPERS
// ============================================================================

export interface ScanSummary {
  status: string;
  processedCount: number | null;
  totalCount: number | null;
  completedAt: string | null;
  riskBreakdown?: {
    clean: number;
    suspicious: number;
    malicious: number;
  };
}

export function buildScanSummary(
  status: string | null,
  processed: number | null,
  total: number | null,
  completedAt: string | null,
): ScanSummary {
  return {
    status: status || "No completed scans yet",
    processedCount: processed,
    totalCount: total,
    completedAt,
  };
}

export function shouldShowScanSummary(summary: ScanSummary): boolean {
  return summary.status !== "No completed scans yet";
}

export function formatScanCompletionTime(timestamp: string | null): string {
  if (!timestamp) return "-";
  try {
    const date = new Date(timestamp);
    return date.toLocaleString();
  } catch {
    return "-";
  }
}
