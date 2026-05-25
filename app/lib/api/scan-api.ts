import { Ecosystem } from "@/app/types/dashboard";

// ============================================================================
// TYPES - Scan Management
// ============================================================================

export type ScanMode = "full" | "static_only" | "lightweight" | "dynamic_only";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type MalwareStatus = "clean" | "malicious" | "suspicious" | "error" | "unknown";
export type RiskStatus = "clean" | "suspicious" | "malicious";
export type AnalysisStatus = string;
export type AnalysisCoverage = "full" | "partial" | "none";

export interface ScanTriggerRequest {
  ecosystem: Ecosystem;
  selected_packages?: string[];
  scan_mode?: ScanMode;
}

export interface ScanTriggerResponse {
  job_id: string;
  status: ScanStatus;
}

export type StaticFeatures = Record<string, number>;

export interface DynamicFinding {
  status?: string;
  coverage?: string;
  sandbox_provider?: string;
  sandbox_job_id?: string;
  sandbox_timed_out?: boolean;
  vm_evasion_observed?: boolean;
  syscall_trace?: { suspicious_count?: number; categories?: string[] } | null;
  network_activity?: { outbound_connections?: number; destinations?: string[] } | null;
  filesystem_changes?: { sensitive_path_writes?: number; paths?: string[] } | null;
  ioc_detail?: {
    verdict?: string;
    dynamic_hit?: boolean;
    network_iocs?: string[];
    process_iocs?: string[];
    file_iocs?: string[];
    dns_iocs?: string[];
    crypto_iocs?: string[];
    raw_line_count?: number;
    flagged_lines?: string[];
  } | null;
}

export interface ScanResultResponse {
  id: string;
  package_name: string;
  package_version: string;
  ecosystem: Ecosystem;
  malware_status: MalwareStatus;
  malware_score: number;
  scanner_version?: string;
  error_message: string | null;
  scan_timestamp: string;
  analyzed_by?: string[];
  risk_assessment?: Record<string, unknown>;
  risk_overall_status: RiskStatus;
  risk_overall_score: number;
  risk_allowlisted: boolean;
  risk_suppressed?: boolean;
  risk_suppression_reason?: string | null;
  risk_breakdown?: Record<string, number>;
  analysis_status: AnalysisStatus;
  analysis_coverage?: AnalysisCoverage | null;
  advisory_references: string[];
  static_features?: StaticFeatures | null;
  dynamic_findings?: DynamicFinding | null;
}

export interface ScanJobResponse {
  id: string;
  owner: string;
  repo_name: string;
  ecosystem: Ecosystem;
  scan_mode: ScanMode;
  status: ScanStatus;
  total_packages: number;
  scanned_packages: number;
  total_dependency_nodes: number;
  total_unique_packages: number;
  progress_percent: number;
  elapsed_seconds: number;
  packages_per_minute?: number;
  estimated_seconds_remaining?: number;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  results?: ScanResultResponse[];
}

export interface ScanHistoryItem {
  id: string;
  ecosystem: Ecosystem;
  scan_mode: ScanMode;
  status: ScanStatus;
  total_packages: number;
  processed_packages?: number;
  scanned_packages?: number;
  total_dependency_nodes?: number;
  total_unique_packages?: number;
  error_message: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface ScanHistoryResponse {
  jobs: ScanHistoryItem[];
  total: number;
  page: number;
  per_page: number;
}

// Map of "package@version" -> ScanResultMapEntry
export interface ScanResultMapEntry extends Omit<ScanResultResponse, "id"> {
  id: string;
}

// ============================================================================
// TYPES - Paginated Scan Results
// ============================================================================

export interface PaginatedScanResultsRequest {
  q?: string;
  malware_status?: MalwareStatus;
  page?: number;
  per_page?: number;
}

export interface PaginatedScanResultsResponse {
  job_id: string;
  total: number;
  page: number;
  per_page: number;
  results: ScanResultResponse[];
}

// ============================================================================
// TYPES - Compatibility & Dependencies
// ============================================================================

export interface DependencyForCheck {
  name: string;
  version: string;
}

export interface CompatibilityCheckItem {
  name: string;
  requested_version: string;
  existing_constraint?: string | null;
  compatible: boolean;
  exists_in_manifest: boolean;
  reason?: string;
  suggestion?: string | null;
}

export interface CompatibilityCheckRequest {
  ecosystem: Ecosystem;
  dependencies: DependencyForCheck[];
}

export interface CompatibilityCheckResponse {
  ecosystem: Ecosystem;
  compatible: boolean;
  checks: CompatibilityCheckItem[];
}

// ============================================================================
// TYPES - SBOM
// ============================================================================

export interface SbomLicense {
  id: string;
  name: string;
  url?: string | null;
}

export interface SbomVulnerability {
  id: string;
  source: string | null;
  severity: number | null;
  description: string | null;
}

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  purl: string;
  licenses: SbomLicense[];
  vulnerabilities: SbomVulnerability[];
  risk_status: string | null;
  risk_score: number | null;
  is_direct: boolean;
  sha256?: string | null;
}

export interface SbomToolInfo {
  vendor: string;
  name: string;
  version: string;
}

export interface SbomMetadata {
  timestamp: string;
  tool: SbomToolInfo;
  repository_owner: string;
  repository_name: string;
  ecosystem: Ecosystem;
  component_count: number;
}

export interface SbomDocument {
  schema_version: string;
  metadata: SbomMetadata;
  components: SbomComponent[];
}

// ============================================================================
// ERROR CLASS
// ============================================================================

export class ScanApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

// ============================================================================
// UTILITIES
// ============================================================================

async function parseJsonSafe(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function toErrorMessage(payload: unknown, fallback: string): string {
  if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>;
    if (typeof record.detail === "string" && record.detail.trim().length > 0) {
      return record.detail;
    }
    if (typeof record.message === "string" && record.message.trim().length > 0) {
      return record.message;
    }
  }
  return fallback;
}

function normalizeScanResult(payload: unknown): ScanResultResponse {
  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};

  const advisoryRefs = Array.isArray(record.advisory_references)
    ? record.advisory_references.filter((item): item is string => typeof item === "string")
    : [];

  const analyzedBy = Array.isArray(record.analyzed_by)
    ? record.analyzed_by.filter((item): item is string => typeof item === "string")
    : undefined;

  const riskBreakdown = record.risk_breakdown && typeof record.risk_breakdown === "object"
    ? (record.risk_breakdown as Record<string, number>)
    : undefined;

  const staticFeatures = record.static_features && typeof record.static_features === "object"
    ? (record.static_features as Record<string, unknown>)
    : null;

  const dynamicFindings = record.dynamic_findings && typeof record.dynamic_findings === "object"
    ? (record.dynamic_findings as Record<string, unknown>)
    : null;

  const normalizedStaticFeatures: StaticFeatures | null = staticFeatures
    ? (Object.fromEntries(
        Object.entries(staticFeatures).filter(([, v]) => typeof v === "number")
      ) as StaticFeatures)
    : null;

  const normalizedDynamicFindings: DynamicFinding | null = dynamicFindings
    ? {
        status: typeof dynamicFindings.status === "string" ? dynamicFindings.status : undefined,
        coverage: typeof dynamicFindings.coverage === "string" ? dynamicFindings.coverage : undefined,
        sandbox_provider: typeof dynamicFindings.sandbox_provider === "string" ? dynamicFindings.sandbox_provider : undefined,
        sandbox_job_id: typeof dynamicFindings.sandbox_job_id === "string" ? dynamicFindings.sandbox_job_id : undefined,
        sandbox_timed_out: typeof dynamicFindings.sandbox_timed_out === "boolean" ? dynamicFindings.sandbox_timed_out : undefined,
        vm_evasion_observed: typeof dynamicFindings.vm_evasion_observed === "boolean" ? dynamicFindings.vm_evasion_observed : undefined,
        syscall_trace: dynamicFindings.syscall_trace && typeof dynamicFindings.syscall_trace === "object"
          ? dynamicFindings.syscall_trace as DynamicFinding["syscall_trace"]
          : null,
        network_activity: dynamicFindings.network_activity && typeof dynamicFindings.network_activity === "object"
          ? dynamicFindings.network_activity as DynamicFinding["network_activity"]
          : null,
        filesystem_changes: dynamicFindings.filesystem_changes && typeof dynamicFindings.filesystem_changes === "object"
          ? dynamicFindings.filesystem_changes as DynamicFinding["filesystem_changes"]
          : null,
        ioc_detail: dynamicFindings.ioc_detail && typeof dynamicFindings.ioc_detail === "object"
          ? dynamicFindings.ioc_detail as DynamicFinding["ioc_detail"]
          : null,
      }
    : null;

  return {
    id: typeof record.id === "string" ? record.id : "",
    package_name: typeof record.package_name === "string" ? record.package_name : "",
    package_version: typeof record.package_version === "string" ? record.package_version : "",
    ecosystem: (record.ecosystem === "npm" || record.ecosystem === "pypi") ? record.ecosystem : "npm",
    malware_status: (["clean", "malicious", "suspicious", "error", "unknown"].includes(String(record.malware_status))
      ? record.malware_status
      : "unknown") as MalwareStatus,
    malware_score: typeof record.malware_score === "number" ? record.malware_score : 0,
    scanner_version: typeof record.scanner_version === "string" ? record.scanner_version : undefined,
    error_message: typeof record.error_message === "string" ? record.error_message : null,
    scan_timestamp: typeof record.scan_timestamp === "string" ? record.scan_timestamp : new Date().toISOString(),
    analyzed_by: analyzedBy,
    risk_overall_status: (["clean", "suspicious", "malicious"].includes(String(record.risk_overall_status))
      ? record.risk_overall_status
      : "clean") as RiskStatus,
    risk_overall_score: typeof record.risk_overall_score === "number" ? record.risk_overall_score : 0,
    risk_allowlisted: record.risk_allowlisted === true,
    risk_suppressed: record.risk_suppressed === true,
    risk_suppression_reason: typeof record.risk_suppression_reason === "string" ? record.risk_suppression_reason : null,
    risk_breakdown: riskBreakdown,
    advisory_references: advisoryRefs,
    static_features: normalizedStaticFeatures,
    dynamic_findings: normalizedDynamicFindings,
    analysis_status: (typeof record.analysis_status === "string" && record.analysis_status.length > 0
      ? record.analysis_status
      : "unknown") as AnalysisStatus,
    analysis_coverage: (["full", "partial", "none"].includes(String(record.analysis_coverage))
      ? record.analysis_coverage
      : null) as AnalysisCoverage | null,
  };
}

function normalizeScanJob(payload: unknown): ScanJobResponse {
  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const results = Array.isArray(record.results)
    ? record.results.map((item) => normalizeScanResult(item))
    : [];

  return {
    id: typeof record.id === "string" ? record.id : "",
    owner: typeof record.owner === "string" ? record.owner : "",
    repo_name: typeof record.repo_name === "string" ? record.repo_name : "",
    ecosystem: (record.ecosystem === "npm" || record.ecosystem === "pypi") ? record.ecosystem : "npm",
    scan_mode: (["full", "static_only", "lightweight", "dynamic_only"].includes(String(record.scan_mode))
      ? record.scan_mode
      : "full") as ScanMode,
    status: (["pending", "running", "completed", "failed", "cancelled"].includes(String(record.status))
      ? record.status
      : "pending") as ScanStatus,
    total_packages: typeof record.total_packages === "number" ? record.total_packages : 0,
    scanned_packages: typeof record.scanned_packages === "number" ? record.scanned_packages : 0,
    total_dependency_nodes: typeof record.total_dependency_nodes === "number" ? record.total_dependency_nodes : 0,
    total_unique_packages: typeof record.total_unique_packages === "number" ? record.total_unique_packages : 0,
    progress_percent: typeof record.progress_percent === "number" ? Math.max(0, Math.min(100, record.progress_percent)) : 0,
    elapsed_seconds: typeof record.elapsed_seconds === "number" ? Math.max(0, record.elapsed_seconds) : 0,
    packages_per_minute: typeof record.packages_per_minute === "number" ? record.packages_per_minute : undefined,
    estimated_seconds_remaining:
      typeof record.estimated_seconds_remaining === "number" ? record.estimated_seconds_remaining : undefined,
    error_message: typeof record.error_message === "string" ? record.error_message : null,
    started_at: typeof record.started_at === "string" ? record.started_at : null,
    completed_at: typeof record.completed_at === "string" ? record.completed_at : null,
    created_at: typeof record.created_at === "string" ? record.created_at : new Date().toISOString(),
    results: results.length > 0 ? results : undefined,
  };
}

export function mapScanApiError(error: unknown): string {
  if (error instanceof ScanApiError) {
    if (error.status === 400) {
      return `Invalid scan request. ${error.detail}`;
    }
    if (error.status === 401 || error.status === 403) {
      return "You are not authorized. Sign in again or check GitHub app access.";
    }
    if (error.status === 404) {
      return "Scan or repository not found.";
    }
    if (error.status === 409) {
      return `Scan conflict: ${error.detail}`;
    }
    if (error.status === 429) {
      return "Rate limited. Please wait before starting another scan.";
    }
    if (error.status === 502) {
      return "Backend could not reach registry/GitHub services. Please retry shortly.";
    }
    return error.detail;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "Unexpected scan error.";
}

// ============================================================================
// SCAN API FUNCTIONS
// ============================================================================

export interface ScanApiContext {
  baseUrl: string;
  authHeaders?: HeadersInit;
  owner: string;
  repoName: string;
}

export async function triggerScan(
  context: ScanApiContext,
  request: ScanTriggerRequest,
  options?: { signal?: AbortSignal },
): Promise<ScanTriggerResponse> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/scan`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...context.authHeaders,
    },
    credentials: "include",
    body: JSON.stringify(request),
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Scan trigger failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};

  return {
    job_id: typeof record.job_id === "string" ? record.job_id : "",
    status: (["pending", "running", "completed", "failed", "cancelled"].includes(String(record.status))
      ? record.status
      : "pending") as ScanStatus,
  };
}

export async function pollScanJob(
  context: ScanApiContext,
  jobId: string,
  options?: { signal?: AbortSignal },
): Promise<ScanJobResponse> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/scan/${encodeURIComponent(jobId)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: context.authHeaders,
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Poll scan failed (${response.status}).`));
  }

  return normalizeScanJob(payload);
}

export async function cancelScan(
  context: ScanApiContext,
  jobId: string,
  options?: { signal?: AbortSignal },
): Promise<{ job_id: string; status: ScanStatus; message: string }> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/scan/${encodeURIComponent(jobId)}/cancel`;

  const response = await fetch(url, {
    method: "POST",
    headers: context.authHeaders,
    credentials: "include",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Cancel scan failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};

  return {
    job_id: typeof record.job_id === "string" ? record.job_id : "",
    status: (["pending", "running", "completed", "failed", "cancelled"].includes(String(record.status))
      ? record.status
      : "cancelled") as ScanStatus,
    message: typeof record.message === "string" ? record.message : "Scan cancelled.",
  };
}

export async function getLatestScan(
  context: ScanApiContext,
  options?: { signal?: AbortSignal },
): Promise<ScanJobResponse | null> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/scan/latest`;

  const response = await fetch(url, {
    method: "GET",
    headers: context.authHeaders,
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  if (response.status === 404) {
    return null;
  }

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Fetch latest scan failed (${response.status}).`));
  }

  if (payload === null) {
    return null;
  }

  return normalizeScanJob(payload);
}

export async function getLatestScanResults(
  context: ScanApiContext,
  options?: { signal?: AbortSignal },
): Promise<Record<string, ScanResultMapEntry>> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/scan/latest/results`;

  const response = await fetch(url, {
    method: "GET",
    headers: context.authHeaders,
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  if (response.status === 404 || response.status === 204) {
    return {};
  }

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Fetch scan results failed (${response.status}).`));
  }

  if (!payload || typeof payload !== "object") {
    return {};
  }

  const record = payload as Record<string, unknown>;
  const resultsMap: Record<string, ScanResultMapEntry> = {};

  for (const [key, value] of Object.entries(record)) {
    if (value && typeof value === "object") {
      resultsMap[key] = normalizeScanResult(value) as ScanResultMapEntry;
    }
  }

  return resultsMap;
}

export async function getPaginatedScanResults(
  context: ScanApiContext,
  jobId: string,
  params?: PaginatedScanResultsRequest,
  options?: { signal?: AbortSignal },
): Promise<PaginatedScanResultsResponse> {
  const searchParams = new URLSearchParams();
  if (params?.q) searchParams.set("q", params.q);
  if (params?.malware_status) searchParams.set("malware_status", params.malware_status);
  searchParams.set("page", String(Math.max(1, params?.page ?? 1)));
  searchParams.set("per_page", String(Math.max(1, Math.min(100, params?.per_page ?? 20))));

  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/scan/${encodeURIComponent(jobId)}/results?${searchParams.toString()}`;

  const response = await fetch(url, {
    method: "GET",
    headers: context.authHeaders,
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Fetch paginated results failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const rawResults = Array.isArray(record.results) ? record.results : [];

  return {
    job_id: typeof record.job_id === "string" ? record.job_id : jobId,
    total: typeof record.total === "number" ? record.total : rawResults.length,
    page: typeof record.page === "number" ? record.page : (params?.page ?? 1),
    per_page: typeof record.per_page === "number" ? record.per_page : (params?.per_page ?? 20),
    results: rawResults.map((item) => normalizeScanResult(item)),
  };
}

export async function getScanHistory(
  context: ScanApiContext,
  page = 1,
  perPage = 20,
  options?: { signal?: AbortSignal },
): Promise<ScanHistoryResponse> {
  const sanitizedPage = Math.max(1, Math.floor(page));
  const sanitizedPerPage = Math.max(1, Math.min(100, Math.floor(perPage)));
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/scan/history?page=${sanitizedPage}&per_page=${sanitizedPerPage}`;

  const response = await fetch(url, {
    method: "GET",
    headers: context.authHeaders,
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  if (response.status === 404) {
    return {
      jobs: [],
      total: 0,
      page: sanitizedPage,
      per_page: sanitizedPerPage,
    };
  }

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Fetch scan history failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const rawJobs = Array.isArray(record.jobs) ? record.jobs : [];

  const jobs: ScanHistoryItem[] = rawJobs
    .map((item): ScanHistoryItem | null => {
      if (!item || typeof item !== "object") return null;
      const entry = item as Record<string, unknown>;
      return {
        id: typeof entry.id === "string" ? entry.id : "",
        ecosystem: (entry.ecosystem === "npm" || entry.ecosystem === "pypi") ? entry.ecosystem : "npm",
        scan_mode: (["full", "static_only", "lightweight", "dynamic_only"].includes(String(entry.scan_mode))
          ? entry.scan_mode
          : "full") as ScanMode,
        status: (["pending", "running", "completed", "failed", "cancelled"].includes(String(entry.status))
          ? entry.status
          : "pending") as ScanStatus,
        total_packages: typeof entry.total_packages === "number" ? entry.total_packages : 0,
        processed_packages: typeof entry.processed_packages === "number" ? entry.processed_packages : undefined,
        scanned_packages: typeof entry.scanned_packages === "number" ? entry.scanned_packages : undefined,
        total_dependency_nodes: typeof entry.total_dependency_nodes === "number" ? entry.total_dependency_nodes : undefined,
        total_unique_packages: typeof entry.total_unique_packages === "number" ? entry.total_unique_packages : undefined,
        error_message: typeof entry.error_message === "string" ? entry.error_message : null,
        created_at: typeof entry.created_at === "string" ? entry.created_at : new Date().toISOString(),
        started_at: typeof entry.started_at === "string" ? entry.started_at : null,
        completed_at: typeof entry.completed_at === "string" ? entry.completed_at : null,
      };
    })
    .filter((item): item is ScanHistoryItem => item !== null);

  return {
    jobs,
    total: typeof record.total === "number" ? record.total : jobs.length,
    page: sanitizedPage,
    per_page: sanitizedPerPage,
  };
}

// ============================================================================
// COMPATIBILITY & DEPENDENCY CHECK
// ============================================================================

export async function checkDependencyCompatibility(
  context: ScanApiContext,
  request: CompatibilityCheckRequest,
  options?: { signal?: AbortSignal },
): Promise<CompatibilityCheckResponse> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/dependencies/check-compatibility`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...context.authHeaders,
    },
    credentials: "include",
    body: JSON.stringify(request),
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Compatibility check failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const rawChecks = Array.isArray(record.checks) ? record.checks : [];

  const checks: CompatibilityCheckItem[] = rawChecks
    .map((item): CompatibilityCheckItem | null => {
      if (!item || typeof item !== "object") return null;
      const entry = item as Record<string, unknown>;
      return {
        name: typeof entry.name === "string" ? entry.name : "",
        requested_version: typeof entry.requested_version === "string" ? entry.requested_version : "",
        existing_constraint: typeof entry.existing_constraint === "string" ? entry.existing_constraint : null,
        compatible: entry.compatible === true,
        exists_in_manifest: entry.exists_in_manifest === true,
        reason: typeof entry.reason === "string" ? entry.reason : undefined,
        suggestion: typeof entry.suggestion === "string" ? entry.suggestion : null,
      };
    })
    .filter((item): item is CompatibilityCheckItem => item !== null);

  return {
    ecosystem: request.ecosystem,
    compatible: record.compatible === true,
    checks,
  };
}

// ============================================================================
// SBOM
// ============================================================================

export async function generateSbom(
  context: ScanApiContext,
  ecosystem: Ecosystem,
  options?: { signal?: AbortSignal },
): Promise<SbomDocument> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/sbom?ecosystem=${encodeURIComponent(ecosystem)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: context.authHeaders,
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Generate SBOM failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};

  return record as unknown as SbomDocument;
}

export async function generateCycloneDxSbom(
  context: ScanApiContext,
  ecosystem: Ecosystem,
  options?: { signal?: AbortSignal },
): Promise<Record<string, unknown>> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(context.owner)}/${encodeURIComponent(context.repoName)}/sbom/cyclonedx?ecosystem=${encodeURIComponent(ecosystem)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: context.authHeaders,
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new ScanApiError(response.status, toErrorMessage(payload, `Generate CycloneDX SBOM failed (${response.status}).`));
  }

  return (payload as Record<string, unknown>) || {};
}

export function downloadSbom(data: Record<string, unknown>, filename: string): void {
  if (typeof window === "undefined") {
    return;
  }

  const jsonString = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonString], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  URL.revokeObjectURL(url);
}
