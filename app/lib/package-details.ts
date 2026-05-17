import { Ecosystem } from "@/app/types/dashboard";
import { PackageSearchResult, PackageVersionsResponse } from "@/app/lib/api/dependency-pr";

// ============================================================================
// TYPES - Package Details
// ============================================================================

export interface PackageDetails {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  description: string;
  downloads?: {
    monthly: number;
  };
  homepage?: string;
  registry_url?: string;
  repository?: {
    url: string;
    type: string;
  };
  license?: string;
  maintainers?: Array<{
    name: string;
    email?: string;
  }>;
  latest_version?: string;
  all_versions?: string[];
}

export interface PackageDetailsContext {
  baseUrl: string;
  authHeaders?: HeadersInit;
}

// ============================================================================
// UTILITIES
// ============================================================================

function formatDownloadCount(count: number): string {
  if (count >= 1_000_000) {
    return `${(count / 1_000_000).toFixed(1)}M`;
  }
  if (count >= 1_000) {
    return `${(count / 1_000).toFixed(1)}K`;
  }
  return String(count);
}

export function buildPackageDetailsDisplay(
  search: PackageSearchResult,
  versions: PackageVersionsResponse,
): PackageDetails {
  return {
    name: search.name,
    version: search.version || versions.versions[0] || "unknown",
    ecosystem: search.ecosystem,
    description: search.description,
    downloads: search.monthly_downloads ? { monthly: search.monthly_downloads } : undefined,
    homepage: search.homepage || undefined,
    registry_url: search.registry_url || undefined,
    latest_version: versions.versions?.[0],
    all_versions: versions.versions || [],
  };
}

export function formatPackageDownloads(downloads?: { monthly: number } | null): string {
  if (!downloads?.monthly) return "No data";
  return `${formatDownloadCount(downloads.monthly)} / month`;
}

export function truncateDescription(description: string, maxLength: number = 200): string {
  if (description.length <= maxLength) {
    return description;
  }
  return description.substring(0, maxLength).trim() + "...";
}

export function shouldShowPackageDetails(pkg: PackageDetails | null): boolean {
  return pkg !== null && (!!pkg.description || !!pkg.homepage || !!pkg.downloads);
}

export function getPackageLabel(name: string, version: string): string {
  return `${name}@${version}`;
}

// ============================================================================
// PACKAGE METADATA HELPERS
// ============================================================================

export interface PackageRiskAssessment {
  malware_status: string;
  risk_status: string;
  risk_score: number;
  advisories_count: number;
  is_allowlisted: boolean;
}

export function buildPackageRiskAssessment(data: unknown): PackageRiskAssessment | null {
  if (!data || typeof data !== "object") return null;

  const record = data as Record<string, unknown>;

  return {
    malware_status: typeof record.malware_status === "string" ? record.malware_status : "unknown",
    risk_status: typeof record.risk_overall_status === "string" ? record.risk_overall_status : "unknown",
    risk_score: typeof record.risk_overall_score === "number" ? record.risk_overall_score : 0,
    advisories_count: Array.isArray(record.advisory_references) ? record.advisory_references.length : 0,
    is_allowlisted: record.risk_allowlisted === true,
  };
}

export function formatPackageRiskBadge(risk: PackageRiskAssessment): {
  label: string;
  color: string;
  icon: string;
} {
  if (risk.is_allowlisted) {
    return {
      label: "Allowlisted",
      color: "blue",
      icon: "✓",
    };
  }

  switch (risk.risk_status) {
    case "clean":
      return {
        label: `Clean (${(risk.risk_score * 100).toFixed(0)}%)`,
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
    default:
      return {
        label: "Unknown",
        color: "slate",
        icon: "?",
      };
  }
}

// ============================================================================
// VERSION PICKER HELPERS
// ============================================================================

export function sortVersions(versions: string[], order: "asc" | "desc" = "desc"): string[] {
  const sorted = [...versions].sort((a, b) => {
    // Simple semver-like sorting
    const aParts = a.split(".").map((p) => parseInt(p, 10) || 0);
    const bParts = b.split(".").map((p) => parseInt(p, 10) || 0);

    const maxLen = Math.max(aParts.length, bParts.length);
    for (let i = 0; i < maxLen; i++) {
      const aVal = aParts[i] || 0;
      const bVal = bParts[i] || 0;

      if (aVal !== bVal) {
        return order === "desc" ? bVal - aVal : aVal - bVal;
      }
    }

    return 0;
  });

  return sorted;
}

export function getLatestVersion(versions: string[]): string | null {
  const sorted = sortVersions(versions, "desc");
  return sorted.length > 0 ? sorted[0] : null;
}

export function filterVersionsByRange(versions: string[], query: string): string[] {
  if (!query) return versions;

  const lower = query.toLowerCase();
  return versions.filter((v) => v.toLowerCase().includes(lower));
}

// ============================================================================
// SEARCH RESULT DISPLAY HELPERS
// ============================================================================

export function getPackageQueryDistance(result: PackageSearchResult): number {
  if (result.typosquat.levenshtein_distance !== null) {
    return result.typosquat.levenshtein_distance;
  }
  if (result.typosquat.edit_distance !== null) {
    return result.typosquat.edit_distance;
  }
  return 0;
}

export function getQueryDistanceWarning(distance: number): {
  show: boolean;
  icon: string;
  message: string;
  severity: "low" | "medium" | "high";
} {
  if (distance <= 2) {
    return { show: false, icon: "", message: "", severity: "low" };
  }

  if (distance <= 5) {
    return {
      show: true,
      icon: "⚠",
      message: "Name differs from your query",
      severity: "medium",
    };
  }

  return {
    show: true,
    icon: "⛔",
    message: "This package is quite different from what you searched",
    severity: "high",
  };
}

export function formatPackageScore(score: number | null): string {
  if (score === null) return "N/A";
  const percentage = Math.round(score * 100);
  return `${percentage}%`;
}

export function getPackageScoreBadgeColor(score: number | null): string {
  if (score === null) return "slate";
  if (score >= 0.8) return "emerald";
  if (score >= 0.5) return "amber";
  return "rose";
}

// ============================================================================
// TYPOSQUAT DISPLAY
// ============================================================================

export function formatTyposquatWarnings(result: PackageSearchResult): {
  isDangerousTypo: boolean;
  isWeakTypo: boolean;
  message: string;
  reasons: string[];
} {
  if (!result.typosquat.is_suspected) {
    return {
      isDangerousTypo: false,
      isWeakTypo: false,
      message: "",
      reasons: [],
    };
  }

  const confidence = result.typosquat.confidence;
  const isDangerous = confidence > 0.7;

  return {
    isDangerousTypo: isDangerous,
    isWeakTypo: !isDangerous,
    message: isDangerous
      ? `Likely typosquat attack (${(confidence * 100).toFixed(0)}% confidence)`
      : `Possible typosquat (${(confidence * 100).toFixed(0)}% confidence)`,
    reasons: result.typosquat.reasons || [],
  };
}

// ============================================================================
// SELECTION STATE HELPERS
// ============================================================================

export interface SelectedPackage {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  score?: number | null;
  isSuspicious: boolean;
}

export function buildSelectedPackage(
  result: PackageSearchResult,
  selectedVersion: string,
): SelectedPackage {
  return {
    name: result.name,
    version: selectedVersion,
    ecosystem: result.ecosystem,
    score: result.score,
    isSuspicious: result.typosquat.is_suspected,
  };
}

export function getSelectedPackageLabel(pkg: SelectedPackage): string {
  return `${pkg.name}@${pkg.version}`;
}

export function deduplicateSelectedPackages(packages: SelectedPackage[]): SelectedPackage[] {
  const seen = new Set<string>();
  return packages.filter((pkg) => {
    const key = `${pkg.name}@${pkg.version}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

// ============================================================================
// VALIDATION & ERROR DISPLAY
// ============================================================================

export function isValidPackageName(name: string): boolean {
  // Basic npm/pypi name validation
  const trimmed = name.trim();

  if (trimmed.length === 0) {
    return false;
  }

  // npm: lowercase letters, numbers, hyphens (not starting/ending with hyphen)
  // pypi: lowercase letters, numbers, hyphens, underscores
  if (!/^[a-z0-9\-_]+$/.test(trimmed)) {
    return false;
  }

  return !trimmed.startsWith("-") && !trimmed.endsWith("-");
}

export function isValidVersion(version: string): boolean {
  const trimmed = version.trim();
  // Simple semver-ish validation
  if (trimmed.length === 0) {
    return false;
  }
  // Allow versions like 1.0.0, 1.0, 1.x, *, >=1.0.0, etc.
  return /^[0-9*.v\-+><=.,x\s]+$/i.test(trimmed);
}

export interface PackageValidationError {
  field: "name" | "version";
  message: string;
}

export function validatePackage(name: string, version: string): PackageValidationError[] {
  const errors: PackageValidationError[] = [];

  if (!isValidPackageName(name)) {
    errors.push({
      field: "name",
      message: "Invalid package name format",
    });
  }

  if (!isValidVersion(version)) {
    errors.push({
      field: "version",
      message: "Invalid version format",
    });
  }

  return errors;
}
