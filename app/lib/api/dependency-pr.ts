import { Ecosystem } from "@/app/types/dashboard";

export interface TyposquatInfo {
  is_suspected: boolean;
  confidence: number;
  levenshtein_distance: number | null;
  edit_distance: number | null;
  normalized_conflict: boolean;
  reasons: string[];
}

export interface PackageSearchResult {
  ecosystem: Ecosystem;
  name: string;
  version: string | null;
  description: string;
  homepage: string | null;
  registry_url: string | null;
  score: number | null;
  monthly_downloads: number | null;
  query_distance?: number | null;
  keywords?: string[] | null;
  latest_version?: string | null;
  package_age_days?: number | null;
  maintainer_count?: number | null;
  has_repository?: boolean | null;
  direct_dependencies_count?: number | null;
  stars?: number | null;
  forks?: number | null;
  contributors_count?: number | null;
  dependents_count?: number | null;
  source_rank?: number | null;
  typosquat: TyposquatInfo;
}

export interface PackageSearchResponse {
  ecosystem: Ecosystem;
  query: string;
  page: number;
  limit: number;
  total: number;
  results: PackageSearchResult[];
  did_you_mean: string | null;
}

export interface PackageVersionsResponse {
  ecosystem: Ecosystem;
  package_name: string;
  latest_version: string | null;
  name: string;
  versions: string[];
}

export interface PackageDetailsResponse {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  description: string;
  license: string | null;
  homepage: string | null;
  registry_url: string | null;
  keywords: string[] | null;
  latest_version: string | null;
  package_age_days: number | null;
  monthly_downloads: number | null;
  maintainer_count: number | null;
  has_repository: boolean | null;
  direct_dependencies_count: number | null;
  stars: number | null;
  forks: number | null;
  contributors_count: number | null;
  dependents_count: number | null;
  source_rank: number | null;
}

export interface DependencyDraft {
  name: string;
  version: string;
}

export interface TyposquatWarning {
  package_name: string;
  risk_level: string;
  reasons: string[];
  similar_to: string | null;
  monthly_downloads: number | null;
}

export interface CreateDependencyPrRequest {
  ecosystem: Ecosystem;
  dependencies: DependencyDraft[];
  idempotency_key?: string;
  branch_name?: string;
  pr_title?: string;
  pr_body?: string;
  updated_package_lock_json?: string | null;
  generate_lockfile_server_side?: boolean;
}

export interface CreateDependencyPrResponse {
  pr_url?: string;
  pr_number?: number;
  branch_name?: string;
  status?: string;
  message?: string;
  typosquat_warnings?: TyposquatWarning[];
  scan_job_id?: string | null;
}

export interface DependencyApiContext {
  baseUrl: string;
  authHeaders?: HeadersInit;
}

export class DependencyApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

function normalizeTyposquat(payload: unknown): TyposquatInfo {
  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const reasons = Array.isArray(record.reasons)
    ? record.reasons.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];

  return {
    is_suspected: record.is_suspected === true,
    confidence: typeof record.confidence === "number" && Number.isFinite(record.confidence) ? record.confidence : 0,
    levenshtein_distance:
      typeof record.levenshtein_distance === "number" && Number.isFinite(record.levenshtein_distance)
        ? record.levenshtein_distance
        : null,
    edit_distance:
      typeof record.edit_distance === "number" && Number.isFinite(record.edit_distance)
        ? record.edit_distance
        : null,
    normalized_conflict: record.normalized_conflict === true,
    reasons,
  };
}

function levenshteinDistance(source: string, target: string): number {
  if (source.length === 0) return target.length;
  if (target.length === 0) return source.length;

  const sourceLength = source.length;
  const targetLength = target.length;
  const matrix: number[][] = [];

  for (let i = 0; i <= targetLength; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= sourceLength; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= targetLength; i++) {
    for (let j = 1; j <= sourceLength; j++) {
      if (target.charAt(i - 1) === source.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }

  return matrix[targetLength][sourceLength];
}

function compareSearchResultRelevance(query: string, left: PackageSearchResult, right: PackageSearchResult): number {
  const leftDistance = left.typosquat.levenshtein_distance ?? left.typosquat.edit_distance ?? Number.POSITIVE_INFINITY;
  const rightDistance = right.typosquat.levenshtein_distance ?? right.typosquat.edit_distance ?? Number.POSITIVE_INFINITY;

  if (leftDistance !== rightDistance) {
    return leftDistance - rightDistance;
  }

  const leftHasVersion = left.version !== null;
  const rightHasVersion = right.version !== null;

  if (leftHasVersion !== rightHasVersion) {
    return leftHasVersion ? -1 : 1;
  }

  if (left.typosquat.is_suspected !== right.typosquat.is_suspected) {
    return left.typosquat.is_suspected ? 1 : -1;
  }

  const leftDownloads = left.monthly_downloads ?? Number.NEGATIVE_INFINITY;
  const rightDownloads = right.monthly_downloads ?? Number.NEGATIVE_INFINITY;

  if (leftDownloads !== rightDownloads) {
    return rightDownloads - leftDownloads;
  }

  const leftScore = left.score ?? Number.NEGATIVE_INFINITY;
  const rightScore = right.score ?? Number.NEGATIVE_INFINITY;

  if (leftScore !== rightScore) {
    return rightScore - leftScore;
  }

  const leftName = left.name.toLowerCase();
  const rightName = right.name.toLowerCase();

  if (leftName !== rightName) {
    return leftName.localeCompare(rightName);
  }

  const queryLower = query.toLowerCase();
  const leftDistanceFromQuery = levenshteinDistance(queryLower, left.name.toLowerCase());
  const rightDistanceFromQuery = levenshteinDistance(queryLower, right.name.toLowerCase());

  return leftDistanceFromQuery - rightDistanceFromQuery;
}

function normalizeSearchResult(item: unknown, ecosystem: Ecosystem): PackageSearchResult | null {
  if (!item || typeof item !== "object") return null;

  const entry = item as Record<string, unknown>;
  const name = typeof entry.name === "string" ? entry.name.trim() : "";
  const version = typeof entry.version === "string" && entry.version.trim().length > 0 ? entry.version.trim() : null;

  if (!name) return null;

  return {
    ecosystem,
    name,
    version,
    description: typeof entry.description === "string" ? entry.description : "",
    homepage: typeof entry.homepage === "string" ? entry.homepage : null,
    registry_url: typeof entry.registry_url === "string" ? entry.registry_url : null,
    score: typeof entry.score === "number" && Number.isFinite(entry.score) ? entry.score : null,
    monthly_downloads:
      typeof entry.monthly_downloads === "number" && Number.isFinite(entry.monthly_downloads)
        ? entry.monthly_downloads
        : null,
    query_distance: typeof entry.query_distance === "number" ? entry.query_distance : null,
    keywords: Array.isArray(entry.keywords)
      ? entry.keywords.filter((k): k is string => typeof k === "string")
      : null,
    latest_version: typeof entry.latest_version === "string" ? entry.latest_version : null,
    package_age_days: typeof entry.package_age_days === "number" ? entry.package_age_days : null,
    maintainer_count: typeof entry.maintainer_count === "number" ? entry.maintainer_count : null,
    has_repository: typeof entry.has_repository === "boolean" ? entry.has_repository : null,
    direct_dependencies_count: typeof entry.direct_dependencies_count === "number" ? entry.direct_dependencies_count : null,
    stars: typeof entry.stars === "number" ? entry.stars : null,
    forks: typeof entry.forks === "number" ? entry.forks : null,
    contributors_count: typeof entry.contributors_count === "number" ? entry.contributors_count : null,
    dependents_count: typeof entry.dependents_count === "number" ? entry.dependents_count : null,
    source_rank: typeof entry.source_rank === "number" ? entry.source_rank : null,
    typosquat: normalizeTyposquat(entry.typosquat),
  };
}

function normalizeSearchResponse(ecosystem: Ecosystem, query: string, page: number, limit: number, payload: unknown): PackageSearchResponse {
  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const rawResults = Array.isArray(record.results) ? record.results : [];

  const results = rawResults
    .map((item) => normalizeSearchResult(item, ecosystem))
    .filter((item): item is PackageSearchResult => item !== null);

  const sortedResults = [...results].sort((left, right) => compareSearchResultRelevance(query, left, right));

  return {
    ecosystem,
    query,
    page: typeof record.page === "number" && Number.isFinite(record.page) && record.page >= 1 ? Math.floor(record.page) : page,
    limit: typeof record.limit === "number" && Number.isFinite(record.limit) && record.limit >= 1 ? Math.floor(record.limit) : limit,
    total: typeof record.total === "number" && Number.isFinite(record.total) ? record.total : sortedResults.length,
    results: sortedResults,
    did_you_mean: typeof record.did_you_mean === "string" && record.did_you_mean.trim().length > 0 ? record.did_you_mean.trim() : null,
  };
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

async function parseJsonSafe(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export function mapDependencyApiError(error: unknown): string {
  if (error instanceof DependencyApiError) {
    if (error.status === 400) {
      return `Invalid request data. ${error.detail}`;
    }

    if (error.status === 401 || error.status === 403) {
      return "You are not authorized for this repository. Sign in again or check GitHub app access.";
    }

    if (error.status === 409) {
      return `Dependency PR conflict: ${error.detail}`;
    }

    if (error.status === 502) {
      return "Backend could not reach GitHub/registry services. Please retry shortly.";
    }

    return error.detail;
  }

  if (error instanceof Error) {
    if (/(network|fetch)/i.test(error.message)) {
      return "Cannot reach the backend server. Make sure it is running and try again.";
    }
    return error.message;
  }

  return "Unexpected dependency API error.";
}

export function createDependencyIdempotencyKey(owner: string, repoName: string): string {
  const suffix = typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.round(Math.random() * 1_000_000)}`;

  return `dep-add-${owner}-${repoName}-${suffix}`;
}

export async function searchPackages(
  context: DependencyApiContext,
  ecosystem: Ecosystem,
  query: string,
  page = 1,
  limit = 8,
  options?: { signal?: AbortSignal },
): Promise<PackageSearchResponse> {
  const sanitizedPage = Math.max(1, Math.floor(page));
  const sanitizedLimit = Math.max(1, limit);
  const trimmedQuery = query.trim();
  const url = `${context.baseUrl}/api/repos/packages/search?ecosystem=${encodeURIComponent(ecosystem)}&q=${encodeURIComponent(trimmedQuery)}&page=${sanitizedPage}&limit=${sanitizedLimit}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      ...context.authHeaders,
    },
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new DependencyApiError(response.status, toErrorMessage(payload, `Package search failed (${response.status}).`));
  }

  return normalizeSearchResponse(ecosystem, trimmedQuery, sanitizedPage, sanitizedLimit, payload);
}

export async function fetchPackageVersions(
  context: DependencyApiContext,
  ecosystem: Ecosystem,
  packageName: string,
  options?: { signal?: AbortSignal },
): Promise<PackageVersionsResponse> {
  const trimmedName = packageName.trim();
  const url = `${context.baseUrl}/api/repos/packages/versions?ecosystem=${encodeURIComponent(ecosystem)}&name=${encodeURIComponent(trimmedName)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      ...context.authHeaders,
    },
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new DependencyApiError(response.status, toErrorMessage(payload, `Version lookup failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const versions = Array.isArray(record.versions)
    ? record.versions.filter((version): version is string => typeof version === "string" && version.trim().length > 0)
    : [];

  const packageNameFromRecord = typeof record.package_name === "string" ? record.package_name : trimmedName;
  const nameFromRecord = typeof record.name === "string" ? record.name : packageNameFromRecord;

  return {
    ecosystem: (record.ecosystem === "npm" || record.ecosystem === "pypi") ? record.ecosystem : ecosystem,
    package_name: packageNameFromRecord,
    latest_version: typeof record.latest_version === "string" ? record.latest_version : (versions[0] ?? null),
    name: nameFromRecord,
    versions,
  };
}

export async function fetchPackageDetails(
  context: DependencyApiContext,
  ecosystem: Ecosystem,
  packageName: string,
  version?: string,
  options?: { signal?: AbortSignal },
): Promise<PackageDetailsResponse> {
  const params = new URLSearchParams({
    ecosystem,
    name: packageName.trim(),
  });
  if (version) {
    params.set("version", version.trim());
  }

  const url = `${context.baseUrl}/api/repos/packages/details?${params.toString()}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      ...context.authHeaders,
    },
    credentials: "include",
    cache: "no-store",
    signal: options?.signal,
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new DependencyApiError(response.status, toErrorMessage(payload, `Package details fetch failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};

  return {
    name: typeof record.name === "string" ? record.name : packageName,
    version: typeof record.version === "string" ? record.version : (version ?? ""),
    ecosystem: (record.ecosystem === "npm" || record.ecosystem === "pypi") ? record.ecosystem : ecosystem,
    description: typeof record.description === "string" ? record.description : "",
    license: typeof record.license === "string" ? record.license : null,
    homepage: typeof record.homepage === "string" ? record.homepage : null,
    registry_url: typeof record.registry_url === "string" ? record.registry_url : null,
    keywords: Array.isArray(record.keywords)
      ? record.keywords.filter((k): k is string => typeof k === "string")
      : null,
    latest_version: typeof record.latest_version === "string" ? record.latest_version : null,
    package_age_days: typeof record.package_age_days === "number" ? record.package_age_days : null,
    monthly_downloads: typeof record.monthly_downloads === "number" ? record.monthly_downloads : null,
    maintainer_count: typeof record.maintainer_count === "number" ? record.maintainer_count : null,
    has_repository: typeof record.has_repository === "boolean" ? record.has_repository : null,
    direct_dependencies_count: typeof record.direct_dependencies_count === "number" ? record.direct_dependencies_count : null,
    stars: typeof record.stars === "number" ? record.stars : null,
    forks: typeof record.forks === "number" ? record.forks : null,
    contributors_count: typeof record.contributors_count === "number" ? record.contributors_count : null,
    dependents_count: typeof record.dependents_count === "number" ? record.dependents_count : null,
    source_rank: typeof record.source_rank === "number" ? record.source_rank : null,
  };
}

export async function createDependencyPr(
  context: DependencyApiContext,
  owner: string,
  repoName: string,
  request: CreateDependencyPrRequest,
): Promise<CreateDependencyPrResponse> {
  const url = `${context.baseUrl}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/dependencies/add`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...context.authHeaders,
    },
    credentials: "include",
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(150_000),
  });

  const payload = await parseJsonSafe(response);

  if (!response.ok) {
    throw new DependencyApiError(response.status, toErrorMessage(payload, `Dependency PR failed (${response.status}).`));
  }

  const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};

  const typosquatWarnings: TyposquatWarning[] = Array.isArray(record.typosquat_warnings)
    ? record.typosquat_warnings
        .filter((item): item is Record<string, unknown> => !!item && typeof item === "object")
        .map((item) => ({
          package_name: typeof item.package_name === "string" ? item.package_name : "",
          risk_level: typeof item.risk_level === "string" ? item.risk_level : "warning",
          reasons: Array.isArray(item.reasons)
            ? item.reasons.filter((r): r is string => typeof r === "string")
            : [],
          similar_to: typeof item.similar_to === "string" ? item.similar_to : null,
          monthly_downloads: typeof item.monthly_downloads === "number" ? item.monthly_downloads : null,
        }))
    : [];

  return {
    pr_url: typeof record.pr_url === "string" ? record.pr_url : undefined,
    pr_number: typeof record.pr_number === "number" ? record.pr_number : undefined,
    branch_name: typeof record.branch_name === "string" ? record.branch_name : undefined,
    status: typeof record.status === "string" ? record.status : undefined,
    message: typeof record.message === "string" ? record.message : undefined,
    typosquat_warnings: typosquatWarnings.length > 0 ? typosquatWarnings : undefined,
    scan_job_id: typeof record.scan_job_id === "string" ? record.scan_job_id : null,
  };
}
