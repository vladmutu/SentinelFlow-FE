"use client";

import React, { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AddDependencyPanel } from "@/app/components/add-dependency-panel";
import { DependencyTree } from "@/app/components/dependency-tree";
import { DependencyNode, Ecosystem } from "@/app/types/dashboard";
import { clientSessionStorage } from "@/app/lib/auth/client-session";
import { createCacheKey, getCachedValue, hashString, setCachedValue } from "@/app/lib/browser-cache";
import { triggerScan, pollScanJob as apiPollScanJob, cancelScan as apiCancelScan, getLatestScan, getLatestScanResults, getScanHistory, generateSbom, generateCycloneDxSbom, downloadSbom, ScanApiError, ScanJobResponse, ScanResultResponse, ScanHistoryItem, SbomDocument, ScanApiContext, DynamicFinding, VulnerabilityDetail, LookupStatus, ScanMode } from "@/app/lib/api/scan-api";
import { fetchPackageDetails, type PackageDetailsResponse } from "@/app/lib/api/dependency-pr";
import { deriveScanDisplay, computeScanProgress, normalizeLiveElapsedSeconds, SCAN_TERMINAL_DONE, SCAN_TERMINAL_FAILED, SCAN_TERMINAL_CANCELLED, isPollingStatus, normalizeScanPhase, normalizeStatusValue, normalizeLatestCompletedScan, resolvePollErrorMeta, SCAN_POLL_INTERVAL_MS, SCAN_RETRY_MAX_DELAY_MS, POLL_RETRY_SILENT_ATTEMPTS, POLL_ERROR_VISIBLE_RETRY_DELAY_MS } from "@/app/lib/scan-display";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL;
const DASHBOARD_CACHE_TTL_MS = 1000 * 60 * 20;
const TREE_CACHE_TTL_MS = 1000 * 60 * 10;
const SCAN_RESULTS_CACHE_TTL_MS = 1000 * 60 * 3;
const MAX_CACHE_BYTES = 1_500_000;

type RepoDetailsPageProps = {
  params: Promise<{ id: string }>;
};

type InternalScanJobResponse = Partial<ScanJobResponse> & {
  status?: ScanJobResponse["status"];
  scanned_packages?: number;
  total_unique_packages?: number;
  progress_percent?: number;
};

type UserPayload = {
  username?: unknown;
  login?: unknown;
  user?: {
    username?: unknown;
    login?: unknown;
  };
};

type ScanResultMapEntry = {
  malware_status?: string;
  malware_score?: number | null;
  risk_overall_status?: string | null;
  risk_overall_score?: number | null;
  scan_timestamp?: string | null;
  scanner_version?: string | null;
  static_features?: Record<string, number> | null;
  vulnerability_details?: VulnerabilityDetail[] | null;
  reputation_metadata?: Record<string, unknown> | null;
  lookup_status?: LookupStatus | null;
  dynamic_findings?: DynamicFinding | null;
};

type ScanResultRow = {
  id: string;
  packageName: string;
  version: string;
  status: string;
  malwareStatus: string;
  malwareScore: number | null;
  riskStatus: string | null;
  riskScore: number | null;
  analysisStatus: string | null;
  advisoryRefs: string[];
  errorMessage: string | null;
  scanTimestamp: string | null;
  staticFeatures: Record<string, number> | null;
  dynamicFindings: DynamicFinding | null;
};

type LatestScanSummary = {
  status: string | null;
  processed: number | null;
  total: number | null;
  completedAt: string | null;
};

type ScanScope = "full" | "partial";
type ScanHistoryStatusFilter = "all" | ScanHistoryItem["status"];

type ActiveScanJob = {
  jobId: string;
  scanMode: ScanMode;
  status: string;
  progress: number;
  details: InternalScanJobResponse | null;
  error: string | null;
  elapsedSeconds: number;
  sourceTab: "graph" | "static-analysis" | "dynamic-analysis" | "lightweight";
};

type RepoCoordinates = {
  owner: string;
  repoName: string;
  headers: HeadersInit;
};

type RepoMetadata = {
  id?: unknown;
  node_id?: unknown;
  name?: unknown;
  full_name?: unknown;
  language?: unknown;
  description?: unknown;
  visibility?: unknown;
  private?: unknown;
};

type RepoContext = RepoCoordinates & {
  language: string;
  ecosystem: Ecosystem;
};

type DashboardCacheSnapshot = {
  user: UserPayload;
  repos: RepoMetadata[];
};

type CachedRepositoryItem = {
  id: string;
  name: string;
  visibility: "public" | "private";
  description: string;
  language: string;
  full_name: string;
};

const ALL_ECOSYSTEMS: Ecosystem[] = ["npm", "pypi"];

function coerceNonNegativeNumber(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return null;
  }

  return value;
}

function formatDuration(totalSeconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(safeSeconds / 3600);
  const minutes = Math.floor((safeSeconds % 3600) / 60);
  const seconds = safeSeconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }

  return `${seconds}s`;
}


function coerceString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function formatVerdict(status: string | null | undefined): string {
  switch ((status ?? "").toLowerCase()) {
    case "clean":      return "Benign";
    case "benign":     return "Benign";
    case "suspicious": return "Suspicious";
    case "malicious":  return "Malicious";
    case "error":      return "Error";
    default:           return "—";
  }
}

function verdictBadgeClass(status: string | null | undefined): string {
  switch ((status ?? "").toLowerCase()) {
    case "malicious":          return "border-rose-400/50 bg-rose-500/15 text-rose-200";
    case "suspicious":         return "border-amber-400/50 bg-amber-500/15 text-amber-200";
    case "clean": case "benign": return "border-emerald-400/50 bg-emerald-500/15 text-emerald-200";
    default:                   return "border-slate-600 bg-slate-800/60 text-slate-400";
  }
}

function getScanModeLabel(mode: string): string {
  switch (mode) {
    case "full":
      return "Full";
    case "static_enrichment":
      return "Static + Enrichment";
    case "dynamic":
      return "Dynamic";
    case "static":
      return "Static";
    case "lightweight":
      return "Lightweight";
    case "unknown":
    default:
      return "Unknown";
  }
}

function buildResultDedupKey(row: ScanResultRow): string {
  return `${row.packageName}|${row.version}|${row.scanTimestamp ?? "-"}|${row.status}|${row.errorMessage ?? "-"}`;
}

function normalizeResultMapFromRows(rows: ScanResultRow[]): Record<string, ScanResultMapEntry> {
  return rows.reduce<Record<string, ScanResultMapEntry>>((accumulator, row) => {
    const key = `${row.packageName}@${row.version}`;
    accumulator[key] = {
      malware_status: row.malwareStatus,
      malware_score: row.malwareScore,
      risk_overall_status: row.riskStatus ?? row.malwareStatus,
      risk_overall_score: row.riskScore ?? row.malwareScore,
    };
    return accumulator;
  }, {});
}

function normalizeResultRow(input: unknown, index: number): ScanResultRow {
  const record = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  const packageName =
    coerceString(record.package_name) ??
    coerceString(record.packageName) ??
    coerceString(record.name) ??
    coerceString(record.package) ??
    "unknown-package";
  const version =
    coerceString(record.version) ??
    coerceString(record.package_version) ??
    coerceString(record.resolved_version) ??
    "unknown";
  const status =
    normalizeStatusValue(record.status ?? record.task_status ?? record.scan_status ?? record.malware_status);
  const malwareStatus = normalizeStatusValue(record.malware_status ?? record.status);
  const malwareScore = coerceNonNegativeNumber(record.malware_score);
  const riskStatus = coerceString(record.risk_overall_status);
  const riskScore = coerceNonNegativeNumber(record.risk_overall_score);
  const advisoryRefs = Array.isArray(record.advisory_references)
    ? (record.advisory_references as unknown[]).filter((r): r is string => typeof r === "string")
    : [];
  const errorMessage =
    coerceString(record.error_message) ?? coerceString(record.error) ?? coerceString(record.failure_reason);
  const scanTimestamp = coerceString(record.scan_timestamp);
  const analysisStatus = coerceString(record.analysis_status);
  const staticFeatures = record.static_features && typeof record.static_features === "object"
    ? (record.static_features as Record<string, number>)
    : null;
  const dynamicFindings = record.dynamic_findings && typeof record.dynamic_findings === "object"
    ? (record.dynamic_findings as DynamicFinding)
    : null;

  return {
    id: coerceString(record.id) ?? `${packageName}@${version}:${index}`,
    packageName,
    version,
    status,
    malwareStatus,
    malwareScore,
    riskStatus,
    riskScore,
    analysisStatus,
    advisoryRefs,
    errorMessage,
    scanTimestamp,
    staticFeatures,
    dynamicFindings,
  };
}

function normalizeScanResultsPayload(payload: unknown): {
  rows: ScanResultRow[];
  map: Record<string, ScanResultMapEntry>;
} {
  let rows: ScanResultRow[] = [];
  let map: Record<string, ScanResultMapEntry> = {};

  if (Array.isArray(payload)) {
    rows = payload.map((entry, index) => normalizeResultRow(entry, index));
    map = normalizeResultMapFromRows(rows);
  } else if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>;

    if (Array.isArray(record.results)) {
      rows = record.results.map((entry, index) => normalizeResultRow(entry, index));
      map = normalizeResultMapFromRows(rows);
    } else {
      const legacyMap: Record<string, ScanResultMapEntry> = {};
      const legacyRows: ScanResultRow[] = [];

      Object.entries(record).forEach(([key, value], index) => {
        if (!value || typeof value !== "object") {
          return;
        }

        const entryRecord = value as Record<string, unknown>;
        const malwareStatus = normalizeStatusValue(entryRecord.malware_status);
        const malwareScore = coerceNonNegativeNumber(entryRecord.malware_score);
        legacyMap[key] = {
          malware_status: malwareStatus,
          malware_score: malwareScore,
          risk_overall_status: coerceString(entryRecord.risk_overall_status),
          risk_overall_score: coerceNonNegativeNumber(entryRecord.risk_overall_score),
          scan_timestamp: coerceString(entryRecord.scan_timestamp),
          scanner_version: coerceString(entryRecord.scanner_version),
        };

        const splitAt = key.lastIndexOf("@");
        const packageName = splitAt > 0 ? key.slice(0, splitAt) : key;
        const version = splitAt > 0 ? key.slice(splitAt + 1) : "unknown";

        legacyRows.push({
          id: `${key}:${index}`,
          packageName,
          version,
          status: malwareStatus,
          malwareStatus,
          malwareScore,
          riskStatus: coerceString(entryRecord.risk_overall_status),
          riskScore: coerceNonNegativeNumber(entryRecord.risk_overall_score),
          analysisStatus: coerceString(entryRecord.analysis_status),
          advisoryRefs: Array.isArray(entryRecord.advisory_references)
            ? (entryRecord.advisory_references as unknown[]).filter((r): r is string => typeof r === "string")
            : [],
          errorMessage: null,
          scanTimestamp: coerceString(entryRecord.scan_timestamp),
          staticFeatures: null,
          dynamicFindings: null,
        });
      });

      rows = legacyRows;
      map = legacyMap;
    }

    return {
      rows,
      map,
    };
  }

  return {
    rows,
    map,
  };
}





function formatTimestampForDisplay(value: string | null): string {
  if (!value) {
    return "-";
  }

  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    return value;
  }

  return new Date(parsed).toLocaleString();
}







function normalizeLanguageToEcosystem(language: string): Ecosystem {
  const normalized = language.trim().toLowerCase();

  if (normalized.includes("python")) {
    return "pypi";
  }

  return "npm";
}

function getEcosystemLabel(ecosystem: Ecosystem): string {
  return ecosystem === "pypi" ? "PyPI" : "npm";
}

function normalizeChildren(input: unknown, ecosystem: Ecosystem): DependencyNode[] {
  if (Array.isArray(input)) {
    return input
      .map((child) => normalizeNode(undefined, child, ecosystem))
      .filter((child): child is DependencyNode => child !== null);
  }

  if (input && typeof input === "object") {
    return Object.entries(input as Record<string, unknown>)
      .map(([name, child]) => normalizeNode(name, child, ecosystem))
      .filter((child): child is DependencyNode => child !== null);
  }

  return [];
}

function normalizeNode(nameHint: string | undefined, input: unknown, ecosystem: Ecosystem): DependencyNode | null {
  if (!input || typeof input !== "object") {
    if (!nameHint) {
      return null;
    }

    return {
      name: nameHint,
      version: typeof input === "string" ? input : "unknown",
      ecosystem,
    };
  }

  const record = input as Record<string, unknown>;
  const name =
    typeof record.name === "string" && record.name.length > 0
      ? record.name
      : nameHint && nameHint.length > 0
        ? nameHint
        : "unknown-package";
  const version =
    typeof record.version === "string" && record.version.length > 0
      ? record.version
      : typeof record.installed_version === "string" && record.installed_version.length > 0
        ? record.installed_version
        : typeof record.resolved === "string" && record.resolved.length > 0
          ? record.resolved
          : "unknown";

  const children = normalizeChildren(record.children ?? record.dependencies ?? [], ecosystem);

  return {
    name,
    version,
    ecosystem,
    children,
  };
}

function normalizeDependencyTree(payload: unknown, ecosystem: Ecosystem): DependencyNode[] {
  if (Array.isArray(payload)) {
    return payload
      .map((node) => normalizeNode(undefined, node, ecosystem))
      .filter((node): node is DependencyNode => node !== null);
  }

  if (!payload || typeof payload !== "object") {
    return [];
  }

  const record = payload as Record<string, unknown>;

  if (record.tree) {
    return normalizeDependencyTree(record.tree, ecosystem);
  }

  if (record.nodes) {
    return normalizeDependencyTree(record.nodes, ecosystem);
  }

  if (record.dependencies) {
    return normalizeChildren(record.dependencies, ecosystem);
  }

  const rootNode = normalizeNode(undefined, payload, ecosystem);
  return rootNode ? [rootNode] : [];
}

async function fetchDependencyTreeForEcosystem(
  owner: string,
  repoName: string,
  headers: HeadersInit,
  ecosystem: Ecosystem,
): Promise<{ ok: boolean; status: number; nodes: DependencyNode[] }> {
  const treeResponse = await fetch(
    `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/dependencies/${ecosystem}`,
    {
      method: "GET",
      headers,
      credentials: "include",
      cache: "no-store",
    },
  );

  if (!treeResponse.ok) {
    return {
      ok: false,
      status: treeResponse.status,
      nodes: [],
    };
  }

  const payload = await treeResponse.json();
  return {
    ok: true,
    status: treeResponse.status,
    nodes: normalizeDependencyTree(payload, ecosystem),
  };
}

function normalizeOwner(payload: UserPayload): string | null {
  const source = payload.user ?? payload;

  if (typeof source.username === "string" && source.username.length > 0) {
    return source.username;
  }

  if (typeof source.login === "string" && source.login.length > 0) {
    return source.login;
  }

  return null;
}

function buildDashboardCacheKey(token: string) {
  return createCacheKey("dashboard-snapshot", hashString(token));
}

function buildRepoTreeCacheKey(token: string, owner: string, repoName: string, ecosystem: Ecosystem) {
  return createCacheKey("repo-tree", hashString(token), owner, repoName, ecosystem);
}

function buildScanResultsCacheKey(token: string, owner: string, repoName: string) {
  return createCacheKey("scan-results", hashString(token), owner, repoName);
}

function toCachedRepositoryItem(payload: RepoMetadata, index: number): CachedRepositoryItem {
  const idSource = payload.id ?? payload.node_id ?? payload.full_name ?? payload.name ?? index;
  const name = typeof payload.name === "string" && payload.name.length > 0 ? payload.name : `repository-${index + 1}`;
  const fullName = typeof payload.full_name === "string" && payload.full_name.length > 0 ? payload.full_name : name;
  const language = typeof payload.language === "string" && payload.language.length > 0 ? payload.language : "Unknown";
  const description = typeof payload.description === "string" && payload.description.length > 0 ? payload.description : "No description provided.";
  const visibility = payload.visibility === "private" || payload.private === true ? "private" : "public";

  return {
    id: String(idSource),
    name,
    visibility,
    description,
    language,
    full_name: fullName,
  };
}

function normalizeCachedRepositoryList(repositories: RepoMetadata[]): CachedRepositoryItem[] {
  return repositories.map((repo, index) => toCachedRepositoryItem(repo, index));
}

function LoadingState() {
  return (
    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/65 p-6">
      <div className="space-y-3">
        <div className="h-5 w-52 animate-pulse rounded bg-slate-700/70" />
        <div className="h-4 w-full animate-pulse rounded bg-slate-800/80" />
        <div className="h-4 w-5/6 animate-pulse rounded bg-slate-800/80" />
        <div className="h-4 w-2/3 animate-pulse rounded bg-slate-800/80" />
      </div>
      <p className="mt-5 text-sm text-slate-300">Building dependency graph...</p>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-rose-300/30 bg-rose-500/10 p-6 text-rose-100 shadow-[0_24px_70px_-42px_rgba(251,113,133,0.85)]">
      <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-rose-200">Malware Scan Unavailable</p>
      <p className="mt-3 text-sm leading-relaxed text-rose-100/90">{message}</p>
    </div>
  );
}

function lookupStatusChipClass(status: string): string {
  if (status === "ok" || status === "found") return "border-emerald-400/40 bg-emerald-500/10 text-emerald-200";
  if (status === "error") return "border-rose-400/40 bg-rose-500/10 text-rose-200";
  if (status === "not_found") return "border-amber-400/40 bg-amber-500/10 text-amber-200";
  return "border-slate-600 bg-slate-800/60 text-slate-400";
}

function lookupStatusLabel(source: string, status: string): string {
  if (source === "cve") {
    if (status === "ok") return "CVE: ok";
    if (status === "error") return "CVE: error";
    return "CVE: skipped";
  }
  if (status === "found") return "Libraries.io: found";
  if (status === "not_found") return "Libraries.io: not indexed";
  if (status === "error") return "Libraries.io: error";
  return "Libraries.io: skipped";
}

function FeatureGrid({ features }: { features: Record<string, number> | null }) {
  if (!features) return null;
  const entries = Object.entries(features).filter(([, v]) => v !== null && v !== undefined);
  if (entries.length === 0) return <p className="mt-2 text-sm text-slate-500">No features available.</p>;
  return (
    <div className="mt-3 grid grid-cols-2 gap-2">
      {entries.map(([key, val]) => (
        <div key={key} className="rounded-lg border border-slate-700/60 bg-slate-900/60 px-3 py-2.5">
          <p className="text-[10px] uppercase tracking-[0.1em] text-slate-500">{key.replace(/_/g, " ")}</p>
          <p className="mt-1 font-mono text-sm font-medium text-slate-200">
            {Number.isInteger(val) ? val : val.toFixed(4)}
          </p>
        </div>
      ))}
    </div>
  );
}

export default function RepoDetailsPage({ params }: RepoDetailsPageProps) {
  const resolvedParams = use(params);
  const decodedId = useMemo(() => decodeURIComponent(resolvedParams.id), [resolvedParams.id]);
  const [nodes, setNodes] = useState<DependencyNode[]>([]);
  const [treeError, setTreeError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResultsMap, setScanResultsMap] = useState<Record<string, ScanResultMapEntry>>({});
  const [scanResultRows, setScanResultRows] = useState<ScanResultRow[]>([]);
  const [latestScanSummary, setLatestScanSummary] = useState<LatestScanSummary>({
    status: null,
    processed: null,
    total: null,
    completedAt: null,
  });
  const [repositoryLanguage, setRepositoryLanguage] = useState("");
  const [repositoryEcosystem, setRepositoryEcosystem] = useState<Ecosystem | null>(null);
  const [isLoadingTree, setIsLoadingTree] = useState(false);
  const [activeScanJobs, setActiveScanJobs] = useState<Map<string, ActiveScanJob>>(new Map());
  const [isCancellingScan, setIsCancellingScan] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [activeSection, setActiveSection] = useState("graph");
  const [graphScanView, setGraphScanView] = useState<"progress" | "results">("progress");
  const [isHydrated, setIsHydrated] = useState(false);
  const [scanScope, setScanScope] = useState<ScanScope>("full");
  const [selectedScanPackages, setSelectedScanPackages] = useState<string[]>([]);
  const [isAgentChatOpen, setIsAgentChatOpen] = useState(true);
  const [agentChatWidth, setAgentChatWidth] = useState(320);
  const [isResizingSidebar, setIsResizingSidebar] = useState(false);
  const [analysisPackageSearch, setAnalysisPackageSearch] = useState("");
  const [selectedAnalysisPackages, setSelectedAnalysisPackages] = useState<string[]>([]);
  const [detailsPackageSearch, setDetailsPackageSearch] = useState("");
  const [selectedDetailsPackage, setSelectedDetailsPackage] = useState<string | null>(null);
  // Scan history
  const [scanHistoryJobs, setScanHistoryJobs] = useState<ScanHistoryItem[]>([]);
  const [isScanHistoryLoading, setIsScanHistoryLoading] = useState(false);
  const [scanHistoryTotal, setScanHistoryTotal] = useState(0);
  const [scanHistoryPage, setScanHistoryPage] = useState(1);
  const [scanHistoryModeFilter, setScanHistoryModeFilter] = useState<"all" | ScanMode>("all");
  const [scanHistoryStatusFilter, setScanHistoryStatusFilter] = useState<ScanHistoryStatusFilter>("all");
  const [selectedHistoryJobId, setSelectedHistoryJobId] = useState<string | null>(null);
  const [selectedHistoryJob, setSelectedHistoryJob] = useState<ScanJobResponse | null>(null);
  const [isHistoryJobLoading, setIsHistoryJobLoading] = useState(false);
  const [expandedResultId, setExpandedResultId] = useState<string | null>(null);
  const [expandedStaticResultId, setExpandedStaticResultId] = useState<string | null>(null);
  const [expandedDynamicRowId, setExpandedDynamicRowId] = useState<string | null>(null);
  const [selectedStaticJobId, setSelectedStaticJobId] = useState<string | null>(null);
  const [selectedDynamicJobId, setSelectedDynamicJobId] = useState<string | null>(null);
  const [selectedLightweightJobId, setSelectedLightweightJobId] = useState<string | null>(null);
  const [graphDetailNode, setGraphDetailNode] = useState<{ label: string; features: Record<string, number> | null; scanEntry: ScanResultMapEntry | null } | null>(null);
  const [graphNodePkgDetails, setGraphNodePkgDetails] = useState<PackageDetailsResponse | null>(null);
  const [graphNodePkgDetailsLoading, setGraphNodePkgDetailsLoading] = useState(false);
  // Lightweight scan tab
  const [lightweightScope, setLightweightScope] = useState<"partial" | "full">("partial");
  const [lightweightSelectedPackages, setLightweightSelectedPackages] = useState<string[]>([]);
  const [lightweightPackageSearch, setLightweightPackageSearch] = useState("");
  const [lightweightSources, setLightweightSources] = useState({ cve: true, librariesio: true });
  const [lightweightExpandedId, setLightweightExpandedId] = useState<string | null>(null);
  const historyScrollRef = useRef<HTMLDivElement | null>(null);
  // SBOM
  const [sbomDocument, setSbomDocument] = useState<SbomDocument | null>(null);
  const [isSbomLoading, setIsSbomLoading] = useState(false);
  const [sbomError, setSbomError] = useState<string | null>(null);
  const [isSbomCdxLoading, setIsSbomCdxLoading] = useState(false);
  // Package details
  const [packageDetailsData, setPackageDetailsData] = useState<PackageDetailsResponse | null>(null);
  const [isPackageDetailsLoading, setIsPackageDetailsLoading] = useState(false);
  const [packageDetailsVersions, setPackageDetailsVersions] = useState<string[]>([]);
  const [packageDetailsLatestVersion, setPackageDetailsLatestVersion] = useState<string | null>(null);
  const [packageDetailsScanEntry, setPackageDetailsScanEntry] = useState<{ advisory_references?: string[]; risk_overall_status?: string; risk_overall_score?: number; risk_allowlisted?: boolean; static_features?: Record<string, number | null>; dynamic_findings?: DynamicFinding | null; analyzed_by?: string[]; risk_assessment?: Record<string, unknown>; vulnerability_details?: VulnerabilityDetail[] | null; reputation_metadata?: Record<string, unknown> | null; lookup_status?: LookupStatus | null } | null>(null);
  // Scan mode
  const [activeScanMode, setActiveScanMode] = useState<ScanMode>("full");
  const [forceRescan, setForceRescan] = useState(false);
  const [graphScanPackageSearch, setGraphScanPackageSearch] = useState("");
  const isMountedRef = useRef(true);
  const scanPollTimersRef = useRef<Map<string, number>>(new Map());
  const elapsedTickersRef = useRef<Map<string, number>>(new Map());
  const scanRetryAttemptsRef = useRef<Map<string, number>>(new Map());
  const liveResultKeysRef = useRef<Set<string>>(new Set());
  const repoContextRef = useRef<RepoContext | null>(null);
  const repoContextPromiseRef = useRef<Promise<RepoContext> | null>(null);

  // Graph-tab-scoped: only jobs that originated from the dependency graph tab
  const graphTabJobs = Array.from(activeScanJobs.values()).filter(j => j.sourceTab === "graph");
  const isGraphTabScanRunning = graphTabJobs.some(j => j.status === "pending" || j.status === "running");

  // isScanRunning kept for legacy progress displays that show the graph-tab primary job
  const isScanRunning = isGraphTabScanRunning;

  // Primary job = most recently started graph-tab job; used for backward-compatible single-job displays
  const primaryJob: ActiveScanJob | null = graphTabJobs.length > 0
    ? graphTabJobs.at(-1) ?? null
    : null;

  const scanJobId = primaryJob?.jobId ?? null;
  const scanProgress = primaryJob?.progress ?? 0;
  const scanStatus = primaryJob?.status ?? "Waiting to start malware scan.";
  const scanDetails = primaryJob?.details ?? null;
  const liveElapsedSeconds = primaryJob?.elapsedSeconds ?? 0;

  const scanDisplay = useMemo(
    () => deriveScanDisplay(scanDetails as ScanJobResponse | null, scanProgress, isScanRunning, scanError),
    [scanDetails, scanProgress, isScanRunning, scanError],
  );
  const hasScanStarted = isScanRunning || hasScanned || scanJobId !== null || scanDetails !== null || scanError !== null;
  const shouldShowScanRuntime = isHydrated && hasScanStarted;
  const liveFailedRowsCount = useMemo(
    () => scanResultRows.filter((row) => row.errorMessage !== null || row.status === "failed").length,
    [scanResultRows],
  );
  const canCancelScan = primaryJob !== null &&
    (primaryJob.status === "pending" || primaryJob.status === "running");
  const canShowGraphScanResults = scanDisplay.phase === "completed" || hasScanned;
  const addDependencyEcosystems = useMemo(() => {
    const nodeEcosystems = Array.from(
      new Set(
        nodes
          .map((node) => node.ecosystem)
          .filter((ecosystem): ecosystem is Ecosystem => ecosystem === "npm" || ecosystem === "pypi"),
      ),
    );

    if (nodeEcosystems.length > 0) {
      return nodeEcosystems;
    }

    return repositoryEcosystem ? [repositoryEcosystem] : [];
  }, [nodes, repositoryEcosystem]);
  const isPartialScan = scanScope === "partial";
  const canStartScan = !isGraphTabScanRunning && (scanScope === "full" || selectedScanPackages.length > 0);
  const availablePackagesForAnalysis = useMemo(() => {
    const labels = new Set<string>();
    const walk = (node: DependencyNode) => {
      labels.add(`${node.name}@${node.version}`);
      (node.children ?? []).forEach(walk);
    };
    nodes.forEach(walk);
    return Array.from(labels).sort((left, right) => left.localeCompare(right));
  }, [nodes]);
  const filteredPackagesForAnalysis = useMemo(() => {
    const query = analysisPackageSearch.trim().toLowerCase();
    if (!query) return availablePackagesForAnalysis;
    return availablePackagesForAnalysis.filter((pkg) => pkg.toLowerCase().includes(query));
  }, [availablePackagesForAnalysis, analysisPackageSearch]);
  const canStartPartialAnalysisScan = selectedAnalysisPackages.length > 0;
  const toggleSelectedScanPackage = useCallback((packageLabel: string) => {
    setSelectedScanPackages((current) =>
      current.includes(packageLabel) ? current.filter((item) => item !== packageLabel) : [...current, packageLabel],
    );
  }, []);
  const toggleSelectedAnalysisPackage = useCallback((packageLabel: string) => {
    setSelectedAnalysisPackages((current) =>
      current.includes(packageLabel) ? current.filter((item) => item !== packageLabel) : [...current, packageLabel],
    );
  }, []);
  const scanStartLabel = graphTabJobs.some(
    j => j.scanMode === activeScanMode && (j.status === "pending" || j.status === "running")
  ) ? `${activeScanMode} running...` : isPartialScan ? "Start Partial Scan" : "Start Scan";
  const runtimeElapsedLabel = useMemo(() => {
    if (scanDisplay.phase === "pending" || scanDisplay.phase === "running") {
      return `Elapsed ${formatDuration(liveElapsedSeconds)}`;
    }

    return scanDisplay.elapsedLabel;
  }, [liveElapsedSeconds, scanDisplay.elapsedLabel, scanDisplay.phase]);

  const staticTabResults = useMemo((): ScanResultRow[] => {
    const job = selectedStaticJobId ? activeScanJobs.get(selectedStaticJobId) : null;
    if (!job?.details) return [];
    return normalizeScanResultsPayload(job.details).rows;
  }, [selectedStaticJobId, activeScanJobs]);

  const dynamicTabResults = useMemo((): ScanResultRow[] => {
    const job = selectedDynamicJobId ? activeScanJobs.get(selectedDynamicJobId) : null;
    if (!job?.details) return [];
    return normalizeScanResultsPayload(job.details).rows;
  }, [selectedDynamicJobId, activeScanJobs]);

  const lightweightTabResults = useMemo((): ScanResultResponse[] => {
    const job = selectedLightweightJobId ? activeScanJobs.get(selectedLightweightJobId) : null;
    const details = job?.details as (InternalScanJobResponse & { results?: ScanResultResponse[] }) | null | undefined;
    return details?.results ?? [];
  }, [selectedLightweightJobId, activeScanJobs]);

  const sections = [
    { key: "graph", label: "Dependency Graph" },
    { key: "static-analysis", label: "Static Analysis" },
    { key: "lightweight", label: "Lightweight Scan" },
    { key: "dynamic-analysis", label: "Dynamic Analysis" },
    { key: "details", label: "Package Details" },
    { key: "sbom", label: "SBOM" },
    { key: "history", label: "Scan History" },
    { key: "add", label: "Add Dependency" },
  ] as const;

  useEffect(() => {
    setIsHydrated(true);

    return () => {
      isMountedRef.current = false;
      scanPollTimersRef.current.forEach(timer => window.clearTimeout(timer));
      elapsedTickersRef.current.forEach(timer => window.clearInterval(timer));
    };
  }, []);

  useEffect(() => {
    setNodes([]);
    setScanResultsMap({});
    setScanResultRows([]);
    setLatestScanSummary({
      status: null,
      processed: null,
      total: null,
      completedAt: null,
    });
    setTreeError(null);
    setScanError(null);
    setIsLoadingTree(true);
    setActiveScanJobs(new Map());
    setHasScanned(false);
    setScanScope("full");
    setSelectedScanPackages([]);
    setScanHistoryJobs([]);
    setIsScanHistoryLoading(false);
    setScanHistoryTotal(0);
    setScanHistoryPage(1);
    setScanHistoryModeFilter("all");
    setScanHistoryStatusFilter("all");
    setSelectedHistoryJobId(null);
    setSelectedHistoryJob(null);
    setSbomDocument(null);
    setSbomError(null);
    setPackageDetailsData(null);
    setPackageDetailsVersions([]);
    setPackageDetailsLatestVersion(null);
    setPackageDetailsScanEntry(null);
    setRepositoryLanguage("");
    setRepositoryEcosystem(null);
    liveResultKeysRef.current = new Set();
    repoContextRef.current = null;
    repoContextPromiseRef.current = null;
    scanPollTimersRef.current.forEach(timer => window.clearTimeout(timer));
    scanPollTimersRef.current.clear();
    elapsedTickersRef.current.forEach(timer => window.clearInterval(timer));
    elapsedTickersRef.current.clear();
    scanRetryAttemptsRef.current.clear();
  }, [decodedId]);

  useEffect(() => {
    // Start/stop per-job elapsed tickers based on active jobs
    activeScanJobs.forEach((job, jobId) => {
      if (job.status !== "pending" && job.status !== "running") {
        const timer = elapsedTickersRef.current.get(jobId);
        if (timer !== undefined) {
          window.clearInterval(timer);
          elapsedTickersRef.current.delete(jobId);
        }
        return;
      }
      if (!elapsedTickersRef.current.has(jobId)) {
        const timer = window.setInterval(() => {
          setActiveScanJobs(current => {
            const next = new Map(current);
            const j = next.get(jobId);
            if (j) next.set(jobId, { ...j, elapsedSeconds: j.elapsedSeconds + 1 });
            return next;
          });
        }, 1000);
        elapsedTickersRef.current.set(jobId, timer);
      }
    });

    // Clean up tickers for jobs that are no longer in the map
    elapsedTickersRef.current.forEach((timer, jobId) => {
      if (!activeScanJobs.has(jobId)) {
        window.clearInterval(timer);
        elapsedTickersRef.current.delete(jobId);
      }
    });
  }, [activeScanJobs]);

  const appendLiveResultRows = useCallback((incomingRows: ScanResultRow[]) => {
    if (incomingRows.length === 0) {
      return;
    }

    const newRows: ScanResultRow[] = [];

    incomingRows.forEach((row) => {
      const dedupKey = buildResultDedupKey(row);
      if (liveResultKeysRef.current.has(dedupKey)) {
        return;
      }

      liveResultKeysRef.current.add(dedupKey);
      newRows.push(row);
    });

    if (newRows.length === 0) {
      return;
    }

    setScanResultRows((current) => [...current, ...newRows]);
    setScanResultsMap((current) => ({
      ...current,
      ...normalizeResultMapFromRows(newRows),
    }));
  }, []);

  const resolveRepoCoordinates = useCallback(async (): Promise<RepoContext> => {
    if (!API_BASE_URL) {
      throw new Error("Missing NEXT_PUBLIC_API_URL configuration.");
    }

    if (repoContextRef.current) {
      return repoContextRef.current;
    }

    if (repoContextPromiseRef.current) {
      return repoContextPromiseRef.current;
    }

    repoContextPromiseRef.current = (async () => {
      try {
        const token = clientSessionStorage.readToken();
        const [candidateOwner, candidateRepo] = decodedId.includes("/")
          ? decodedId.split("/", 2)
          : [null, decodedId];
        const dashboardCacheKey = token ? buildDashboardCacheKey(token) : null;
        const cachedDashboard = dashboardCacheKey ? getCachedValue<DashboardCacheSnapshot>(dashboardCacheKey) : null;

        let owner = candidateOwner ?? null;

        if (!owner && cachedDashboard) {
          owner = normalizeOwner(cachedDashboard.user);
        }

        if (!owner) {
          if (!token) {
            throw new Error("Could not resolve repository owner because no session token is available.");
          }

          const meResponse = await fetch(`${API_BASE_URL}/api/auth/me`, {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
            },
            credentials: "include",
            cache: "no-store",
          });

          if (!meResponse.ok) {
            throw new Error("Unable to resolve authenticated owner for this repository.");
          }

          const userPayload = (await meResponse.json()) as UserPayload;
          owner = normalizeOwner(userPayload);

          if (!owner) {
            throw new Error("Authenticated session did not return a valid GitHub owner.");
          }
        }

        const safeOwner = owner;
        const safeRepoName = candidateRepo ?? decodedId;

        if (!safeOwner) {
          throw new Error("Could not resolve repository owner.");
        }

        const headers: HeadersInit = token
          ? {
              Authorization: `Bearer ${token}`,
            }
          : {};

        const cachedRepoFromDashboard = cachedDashboard?.repos.find((repo) => {
          const repoName = typeof repo.name === "string" ? repo.name : null;
          const fullName = typeof repo.full_name === "string" ? repo.full_name : null;

          return repoName === safeRepoName || fullName === `${safeOwner}/${safeRepoName}` || fullName?.endsWith(`/${safeRepoName}`) === true;
        });

        if (cachedRepoFromDashboard) {
          const language = typeof cachedRepoFromDashboard.language === "string" && cachedRepoFromDashboard.language.trim().length > 0
            ? cachedRepoFromDashboard.language.trim()
            : "Unknown";
          const ecosystem = normalizeLanguageToEcosystem(language);

          const context = {
            owner: safeOwner,
            repoName: safeRepoName,
            headers,
            language,
            ecosystem,
          };

          repoContextRef.current = context;
          return context;
        }

        const reposResponse = await fetch(`${API_BASE_URL}/api/repos`, {
          method: "GET",
          headers,
          credentials: "include",
          cache: "no-store",
        });

        if (!reposResponse.ok) {
          throw new Error(`Repository metadata fetch failed (${reposResponse.status}).`);
        }

        const reposPayload = (await reposResponse.json()) as { repos?: RepoMetadata[] } | RepoMetadata[];
        const repositoryList = Array.isArray(reposPayload) ? reposPayload : Array.isArray(reposPayload.repos) ? reposPayload.repos : [];
        const fullName = `${safeOwner}/${safeRepoName}`;

        const repositoryRecord = repositoryList.find((entry) => {
          if (!entry || typeof entry !== "object") {
            return false;
          }

          const record = entry as Record<string, unknown>;
          const entryName = typeof record.name === "string" ? record.name : null;
          const entryFullName = typeof record.full_name === "string" ? record.full_name : null;

          return entryName === safeRepoName || entryFullName === fullName || entryFullName?.endsWith(`/${safeRepoName}`) === true;
        });

        const language =
          repositoryRecord && typeof repositoryRecord.language === "string" && repositoryRecord.language.trim().length > 0
            ? repositoryRecord.language.trim()
            : "Unknown";
        const ecosystem = normalizeLanguageToEcosystem(language);

        const context = {
          owner: safeOwner,
          repoName: safeRepoName,
          headers,
          language,
          ecosystem,
        };

        if (dashboardCacheKey) {
          setCachedValue(dashboardCacheKey, {
            user: cachedDashboard?.user ?? { username: safeOwner, login: safeOwner, user: { username: safeOwner, login: safeOwner } },
            repos: normalizeCachedRepositoryList(repositoryList),
          }, {
            ttlMs: DASHBOARD_CACHE_TTL_MS,
            scope: "both",
            maxPersistentSizeBytes: MAX_CACHE_BYTES,
          });
        }

        repoContextRef.current = context;
        return context;
      } finally {
        repoContextPromiseRef.current = null;
      }
    })();

    return repoContextPromiseRef.current;
  }, [decodedId]);

  const loadDependencyTree = useCallback(async () => {
    setIsLoadingTree(true);

    try {
      const repoContext = await resolveRepoCoordinates();
      const { owner, repoName, headers, language, ecosystem } = repoContext;
      const token = clientSessionStorage.readToken();
      const treeCacheKey = token ? buildRepoTreeCacheKey(token, owner, repoName, ecosystem) : null;
      const cachedTree = treeCacheKey ? getCachedValue<DependencyNode[]>(treeCacheKey) : null;

      setRepositoryLanguage(language);

      if (cachedTree !== null) {
        setRepositoryEcosystem(ecosystem);
        setNodes(cachedTree);
        return;
      }

      const ecosystemCandidates: Ecosystem[] = [
        ecosystem,
        ...ALL_ECOSYSTEMS.filter((candidate) => candidate !== ecosystem),
      ];

      let selectedEcosystem: Ecosystem | null = null;
      let normalized: DependencyNode[] = [];
      let firstNon404ErrorStatus: number | null = null;

      for (const candidateEcosystem of ecosystemCandidates) {
        const result = await fetchDependencyTreeForEcosystem(owner, repoName, headers, candidateEcosystem);

        if (!result.ok) {
          if (result.status !== 404 && firstNon404ErrorStatus === null) {
            firstNon404ErrorStatus = result.status;
          }
          continue;
        }

        selectedEcosystem = candidateEcosystem;
        normalized = result.nodes;

        if (result.nodes.length > 0) {
          break;
        }
      }

      if (!selectedEcosystem) {
        if (firstNon404ErrorStatus !== null) {
          throw new Error(`Could not load dependency tree (${firstNon404ErrorStatus}).`);
        }

        throw new Error("Could not find a supported dependency ecosystem (npm or PyPI) for this repository.");
      }

      setRepositoryEcosystem(selectedEcosystem);
      if (repoContextRef.current) {
        repoContextRef.current = {
          ...repoContextRef.current,
          ecosystem: selectedEcosystem,
        };
      }

      setNodes(normalized);

      if (treeCacheKey) {
        setCachedValue(treeCacheKey, normalized, {
          ttlMs: TREE_CACHE_TTL_MS,
          scope: "both",
          maxPersistentSizeBytes: MAX_CACHE_BYTES,
        });
      }
    } catch (loadError) {
      const message = loadError instanceof Error ? loadError.message : "Unexpected error while loading dependencies.";
      setTreeError(message);
    } finally {
      setIsLoadingTree(false);
    }
  }, [resolveRepoCoordinates]);

  const loadLatestScanResults = useCallback(async () => {
    let cachedScanResults: Record<string, ScanResultMapEntry> | null = null;

    try {
      const repoContext = await resolveRepoCoordinates();
      const { owner, repoName, headers } = repoContext;
      const token = clientSessionStorage.readToken();
      const scanResultsCacheKey = token ? buildScanResultsCacheKey(token, owner, repoName) : null;
      cachedScanResults = scanResultsCacheKey ? getCachedValue<Record<string, ScanResultMapEntry>>(scanResultsCacheKey) : null;

      if (cachedScanResults !== null) {
        setScanResultsMap(cachedScanResults);
        setHasScanned(Object.keys(cachedScanResults).length > 0);
      }

      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL!, authHeaders: headers, owner, repoName };

      const resultsMap = await getLatestScanResults(scanContext);
      setScanResultsMap(resultsMap);
      setHasScanned(Object.keys(resultsMap).length > 0);

      if (scanResultsCacheKey) {
        setCachedValue(scanResultsCacheKey, resultsMap, {
          ttlMs: SCAN_RESULTS_CACHE_TTL_MS,
          scope: "both",
          maxPersistentSizeBytes: MAX_CACHE_BYTES,
        });
      }

      const latestJob = await getLatestScan(scanContext);
      if (latestJob === null) {
        setLatestScanSummary({ status: null, processed: null, total: null, completedAt: null });
      } else {
        setLatestScanSummary(normalizeLatestCompletedScan(latestJob));
        if (latestJob.results && latestJob.results.length > 0) {
          const rows = latestJob.results.map((r, i) => normalizeResultRow(r, i));
          setScanResultRows(rows);
        }
      }
    } catch {
      if (cachedScanResults === null) {
        setScanResultsMap({});
      }
    }
  }, [resolveRepoCoordinates]);

  const pollScanJob = useCallback(
    async (owner: string, repoName: string, jobId: string, headers: HeadersInit) => {
      try {
        const scanContext: ScanApiContext = { baseUrl: API_BASE_URL!, authHeaders: headers, owner, repoName };
        const payload = await apiPollScanJob(scanContext, jobId);
        const statusValue = normalizeStatusValue(payload.status);
        const phase = normalizeScanPhase(statusValue, true, false);

        if (!isMountedRef.current) return;

        scanRetryAttemptsRef.current.set(jobId, 0);

        setActiveScanJobs(current => {
          const next = new Map(current);
          const job = next.get(jobId);
          if (!job) return current;
          next.set(jobId, {
            ...job,
            status: statusValue,
            progress: computeScanProgress(payload, phase, job.progress),
            details: payload,
            error: null,
            elapsedSeconds: payload.started_at
              ? normalizeLiveElapsedSeconds(payload)
              : job.elapsedSeconds,
          });
          return next;
        });

        if (Array.isArray(payload.results)) {
          const liveResults = normalizeScanResultsPayload({ results: payload.results });
          appendLiveResultRows(liveResults.rows);
        }

        if (SCAN_TERMINAL_DONE.has(statusValue)) {
          if (Array.isArray(payload.results) && payload.results.length > 0) {
            const finalNormalized = normalizeScanResultsPayload({ results: payload.results });
            setScanResultRows(finalNormalized.rows);
            setScanResultsMap(prev => ({ ...prev, ...finalNormalized.map }));
            liveResultKeysRef.current = new Set(finalNormalized.rows.map(buildResultDedupKey));
          }
          // Keep completed job in activeScanJobs so per-tab panels can display results
          setActiveScanJobs(current => {
            const next = new Map(current);
            const job = next.get(jobId);
            if (job) next.set(jobId, { ...job, status: statusValue, progress: 100, details: payload });
            return next;
          });
          setHasScanned(true);
          await loadLatestScanResults();
          if (isMountedRef.current) { void loadScanHistory(); }
          return;
        }

        if (SCAN_TERMINAL_CANCELLED.has(statusValue)) {
          // Keep cancelled job in activeScanJobs for display
          setActiveScanJobs(current => {
            const next = new Map(current);
            const job = next.get(jobId);
            if (job) next.set(jobId, { ...job, status: statusValue });
            return next;
          });
          if (isMountedRef.current) { void loadScanHistory(); }
          return;
        }

        if (SCAN_TERMINAL_FAILED.has(statusValue)) {
          setActiveScanJobs(current => {
            const next = new Map(current);
            const job = next.get(jobId);
            if (job) next.set(jobId, { ...job, status: statusValue, error: `Scan failed: ${statusValue}`, details: payload });
            return next;
          });
          await loadLatestScanResults();
          if (isMountedRef.current) { void loadScanHistory(); }
          return;
        }

        // Schedule next poll for any non-terminal status
        const timer = window.setTimeout(() => {
          void pollScanJob(owner, repoName, jobId, headers);
        }, SCAN_POLL_INTERVAL_MS);
        scanPollTimersRef.current.set(jobId, timer);

      } catch (pollError) {
        if (!isMountedRef.current) return;

        const errorMeta = resolvePollErrorMeta(pollError);

        if (errorMeta.kind === "auth") {
          setActiveScanJobs(current => {
            const next = new Map(current);
            const job = next.get(jobId);
            if (job) next.set(jobId, { ...job, error: errorMeta.message });
            return next;
          });
          window.location.href = "/login";
          return;
        }

        if (errorMeta.kind === "not-found") {
          setActiveScanJobs(current => {
            const next = new Map(current);
            const job = next.get(jobId);
            if (job) next.set(jobId, { ...job, error: errorMeta.message });
            return next;
          });
          return;
        }

        const attempt = (scanRetryAttemptsRef.current.get(jobId) ?? 0) + 1;
        scanRetryAttemptsRef.current.set(jobId, attempt);

        if (attempt > POLL_RETRY_SILENT_ATTEMPTS) {
          setActiveScanJobs(current => {
            const next = new Map(current);
            const job = next.get(jobId);
            if (job) next.set(jobId, { ...job, error: `${errorMeta.message} Retrying...` });
            return next;
          });
        }

        const backoff = Math.min(
          SCAN_RETRY_MAX_DELAY_MS,
          SCAN_POLL_INTERVAL_MS * Math.max(1, 2 ** Math.max(0, attempt - POLL_RETRY_SILENT_ATTEMPTS)),
        );
        const delay = attempt > POLL_RETRY_SILENT_ATTEMPTS
          ? Math.max(POLL_ERROR_VISIBLE_RETRY_DELAY_MS, backoff)
          : SCAN_POLL_INTERVAL_MS;

        const timer = window.setTimeout(() => {
          void pollScanJob(owner, repoName, jobId, headers);
        }, delay);
        scanPollTimersRef.current.set(jobId, timer);
      }
    },
    // loadScanHistory is declared after pollScanJob — omitted from deps intentionally
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [appendLiveResultRows, loadLatestScanResults],
  );

  const triggerPackageScan = useCallback(async (overrideScanMode?: ScanMode) => {
    const scanMode: ScanMode = overrideScanMode ?? activeScanMode;

    setScanError(null);
    setGraphScanView("progress");
    liveResultKeysRef.current = new Set();
    scanRetryAttemptsRef.current.set("pending-" + scanMode, 0);

    try {
      const { owner, repoName, headers, ecosystem } = await resolveRepoCoordinates();
      const token = clientSessionStorage.readToken();
      const scanResultsCacheKey = token ? buildScanResultsCacheKey(token, owner, repoName) : null;
      if (scanResultsCacheKey) {
        setCachedValue(scanResultsCacheKey, {}, {
          ttlMs: SCAN_RESULTS_CACHE_TTL_MS,
          scope: "both",
          maxPersistentSizeBytes: MAX_CACHE_BYTES,
        });
      }

      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL!, authHeaders: headers, owner, repoName };
      const triggerPayload = await triggerScan(scanContext, {
        ecosystem,
        scan_mode: scanMode,
        selected_packages: isPartialScan && selectedScanPackages.length > 0
          ? selectedScanPackages
          : undefined,
        force_rescan: (isPartialScan || forceRescan) || undefined,
      });

      if (!triggerPayload.job_id) {
        throw new Error("Scan trigger did not return a job id.");
      }

      const jobId = String(triggerPayload.job_id);
      const newJob: ActiveScanJob = {
        jobId,
        scanMode,
        status: "pending",
        progress: 0,
        details: { status: "pending", scanned_packages: 0, total_unique_packages: 0, progress_percent: 0 },
        error: null,
        elapsedSeconds: 0,
        sourceTab: "graph",
      };

      setActiveScanJobs(current => new Map(current).set(jobId, newJob));
      setHasScanned(true);
      setScanResultRows([]);
      setScanResultsMap({});

      const timer = window.setTimeout(() => {
        void pollScanJob(owner, repoName, jobId, headers);
      }, SCAN_POLL_INTERVAL_MS);
      scanPollTimersRef.current.set(jobId, timer);

    } catch (err) {
      const is409 = err instanceof ScanApiError && err.status === 409;
      const message = is409
        ? `A '${scanMode}' scan is already in progress. Please wait or cancel it first.`
        : err instanceof Error ? err.message : "Unexpected error while starting scan.";
      setScanError(message);
      setHasScanned(false);
    }
  }, [
    activeScanJobs, activeScanMode, forceRescan, isPartialScan,
    pollScanJob, resolveRepoCoordinates, selectedScanPackages,
  ]);

  const triggerPartialAnalysisScan = useCallback(async (
    scanMode: ScanMode = "static",
    sourceTab: "static-analysis" | "dynamic-analysis" = scanMode === "dynamic" ? "dynamic-analysis" : "static-analysis",
  ) => {
    if (selectedAnalysisPackages.length === 0) {
      return;
    }
    setScanError(null);
    liveResultKeysRef.current = new Set();
    scanRetryAttemptsRef.current.set("pending-" + scanMode, 0);

    try {
      const { owner, repoName, headers, ecosystem } = await resolveRepoCoordinates();
      const token = clientSessionStorage.readToken();
      const scanResultsCacheKey = token ? buildScanResultsCacheKey(token, owner, repoName) : null;

      if (scanResultsCacheKey) {
        setCachedValue(scanResultsCacheKey, {}, {
          ttlMs: SCAN_RESULTS_CACHE_TTL_MS,
          scope: "both",
          maxPersistentSizeBytes: MAX_CACHE_BYTES,
        });
      }

      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL!, authHeaders: headers, owner, repoName };
      const triggerPayload = await triggerScan(scanContext, {
        ecosystem,
        scan_mode: scanMode,
        selected_packages: selectedAnalysisPackages,
        force_rescan: true,
      });

      if (!triggerPayload.job_id) {
        throw new Error("Scan trigger did not return a job id.");
      }

      const jobId = String(triggerPayload.job_id);
      const newJob: ActiveScanJob = {
        jobId,
        scanMode,
        status: "pending",
        progress: 0,
        details: { status: "pending", scanned_packages: 0, total_unique_packages: 0, progress_percent: 0 },
        error: null,
        elapsedSeconds: 0,
        sourceTab,
      };

      setActiveScanJobs(current => new Map(current).set(jobId, newJob));
      setHasScanned(true);
      if (sourceTab === "static-analysis") setSelectedStaticJobId(jobId);
      if (sourceTab === "dynamic-analysis") setSelectedDynamicJobId(jobId);

      const timer = window.setTimeout(() => {
        void pollScanJob(owner, repoName, jobId, headers);
      }, SCAN_POLL_INTERVAL_MS);
      scanPollTimersRef.current.set(jobId, timer);

    } catch (scanError) {
      const message = scanError instanceof Error
        ? scanError.message
        : "Unexpected error while running package scan.";
      setScanError(message);
    }
  }, [pollScanJob, resolveRepoCoordinates, selectedAnalysisPackages]);

  const triggerLightweightScan = useCallback(async () => {
    setScanError(null);

    try {
      const { owner, repoName, headers, ecosystem } = await resolveRepoCoordinates();
      const scanCtx: ScanApiContext = { baseUrl: API_BASE_URL!, authHeaders: headers, owner, repoName };

      const triggerPayload = await triggerScan(scanCtx, {
        ecosystem,
        scan_mode: "lightweight",
        selected_packages:
          lightweightScope === "partial" && lightweightSelectedPackages.length > 0
            ? lightweightSelectedPackages
            : undefined,
      });

      if (!triggerPayload.job_id) {
        throw new Error("Scan trigger did not return a job id.");
      }

      const jobId = String(triggerPayload.job_id);
      const newJob: ActiveScanJob = {
        jobId,
        scanMode: "lightweight",
        status: "pending",
        progress: 0,
        details: { status: "pending", scanned_packages: 0, total_unique_packages: 0, progress_percent: 0 },
        error: null,
        elapsedSeconds: 0,
        sourceTab: "lightweight",
      };

      setActiveScanJobs(current => new Map(current).set(jobId, newJob));
      setSelectedLightweightJobId(jobId);

      const timer = window.setTimeout(() => {
        void pollScanJob(owner, repoName, jobId, headers);
      }, SCAN_POLL_INTERVAL_MS);
      scanPollTimersRef.current.set(jobId, timer);

    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Failed to start lightweight scan.");
    }
  }, [lightweightScope, lightweightSelectedPackages, pollScanJob, resolveRepoCoordinates]);

  const cancelScanJob = useCallback(async (targetJobId?: string) => {
    const jobId = targetJobId ?? primaryJob?.jobId;
    if (!jobId || isCancellingScan) return;

    setIsCancellingScan(true);
    setScanError(null);

    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL!, authHeaders: headers, owner, repoName };
      await apiCancelScan(scanContext, jobId);

      const pollTimer = scanPollTimersRef.current.get(jobId);
      if (pollTimer !== undefined) {
        window.clearTimeout(pollTimer);
        scanPollTimersRef.current.delete(jobId);
      }
      const tickTimer = elapsedTickersRef.current.get(jobId);
      if (tickTimer !== undefined) {
        window.clearInterval(tickTimer);
        elapsedTickersRef.current.delete(jobId);
      }

      setActiveScanJobs(current => { const next = new Map(current); next.delete(jobId); return next; });
    } catch (cancelError) {
      const status =
        typeof cancelError === "object" && cancelError !== null && "status" in cancelError
          ? (cancelError as { status: number }).status
          : null;

      if (status === 400) {
        setActiveScanJobs(current => { const next = new Map(current); next.delete(jobId); return next; });
      } else if (status === 404) {
        setScanError("Scan job not found.");
      } else {
        setScanError(cancelError instanceof Error ? cancelError.message : "Unable to stop scan.");
      }
    } finally {
      setIsCancellingScan(false);
    }
  }, [isCancellingScan, primaryJob?.jobId, resolveRepoCoordinates]);

  const loadScanHistory = useCallback(async () => {
    if (!API_BASE_URL) return;
    setIsScanHistoryLoading(true);
    setScanHistoryJobs([]);
    setScanHistoryTotal(0);
    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL, authHeaders: headers, owner, repoName };
      const result = await getScanHistory(scanContext, {
        page: 1,
        per_page: 25,
        scan_mode: scanHistoryModeFilter === "all" ? undefined : scanHistoryModeFilter,
        status: scanHistoryStatusFilter === "all" ? undefined : scanHistoryStatusFilter,
      });
      if (isMountedRef.current) {
        setScanHistoryJobs(result.jobs);
        setScanHistoryTotal(result.total);
        setScanHistoryPage(result.page);
      }
    } catch { /* silent */ } finally {
      if (isMountedRef.current) setIsScanHistoryLoading(false);
    }
  }, [resolveRepoCoordinates, scanHistoryModeFilter, scanHistoryStatusFilter]);

  const loadMoreScanHistory = useCallback(async () => {
    if (!API_BASE_URL || isScanHistoryLoading || scanHistoryJobs.length >= scanHistoryTotal) {
      return;
    }

    const nextPage = scanHistoryPage + 1;
    setIsScanHistoryLoading(true);

    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL, authHeaders: headers, owner, repoName };
      const result = await getScanHistory(scanContext, {
        page: nextPage,
        per_page: 25,
        scan_mode: scanHistoryModeFilter === "all" ? undefined : scanHistoryModeFilter,
        status: scanHistoryStatusFilter === "all" ? undefined : scanHistoryStatusFilter,
      });

      if (isMountedRef.current) {
        setScanHistoryJobs((current) => {
          const existingIds = new Set(current.map((job) => job.id));
          const merged = [...current];
          result.jobs.forEach((job) => {
            if (!existingIds.has(job.id)) {
              merged.push(job);
            }
          });
          return merged;
        });
        setScanHistoryTotal(result.total);
        setScanHistoryPage(result.page);
      }
    } catch {
      // silent
    } finally {
      if (isMountedRef.current) {
        setIsScanHistoryLoading(false);
      }
    }
  }, [API_BASE_URL, isScanHistoryLoading, resolveRepoCoordinates, scanHistoryJobs.length, scanHistoryModeFilter, scanHistoryPage, scanHistoryStatusFilter, scanHistoryTotal]);

  const handleHistoryScroll = useCallback((event: React.UIEvent<HTMLDivElement>) => {
    const target = event.currentTarget;
    const nearBottom = target.scrollTop + target.clientHeight >= target.scrollHeight - 160;

    if (nearBottom && !isScanHistoryLoading && scanHistoryJobs.length < scanHistoryTotal) {
      void loadMoreScanHistory();
    }
  }, [isScanHistoryLoading, loadMoreScanHistory, scanHistoryJobs.length, scanHistoryTotal]);

  const loadHistoryJobDetails = useCallback(async (jobId: string) => {
    if (!API_BASE_URL) return;
    setSelectedHistoryJobId(jobId);
    setSelectedHistoryJob(null);
    setIsHistoryJobLoading(true);
    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL, authHeaders: headers, owner, repoName };
      const job = await apiPollScanJob(scanContext, jobId);
      if (isMountedRef.current) setSelectedHistoryJob(job);
    } catch { /* silent */ } finally {
      if (isMountedRef.current) setIsHistoryJobLoading(false);
    }
  }, [resolveRepoCoordinates]);

  const generateSbomHandler = useCallback(async () => {
    if (!API_BASE_URL || !repositoryEcosystem) return;
    setIsSbomLoading(true);
    setSbomError(null);
    setSbomDocument(null);
    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL, authHeaders: headers, owner, repoName };
      const doc = await generateSbom(scanContext, repositoryEcosystem);
      if (isMountedRef.current) setSbomDocument(doc);
    } catch (err) {
      if (isMountedRef.current) setSbomError(err instanceof Error ? err.message : "Failed to generate SBOM.");
    } finally {
      if (isMountedRef.current) setIsSbomLoading(false);
    }
  }, [resolveRepoCoordinates, repositoryEcosystem]);

  const downloadSbomSentinelFlow = useCallback(() => {
    if (!sbomDocument) return;
    downloadSbom(sbomDocument as unknown as Record<string, unknown>, "sbom.sentinelflow.json");
  }, [sbomDocument]);

  const downloadSbomCycloneDx = useCallback(async () => {
    if (!API_BASE_URL || isSbomCdxLoading || !repositoryEcosystem) return;
    setIsSbomCdxLoading(true);
    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL, authHeaders: headers, owner, repoName };
      const cdxDoc = await generateCycloneDxSbom(scanContext, repositoryEcosystem);
      downloadSbom(cdxDoc, "sbom.cdx.json");
    } catch { /* silent */ } finally {
      if (isMountedRef.current) setIsSbomCdxLoading(false);
    }
  }, [resolveRepoCoordinates, isSbomCdxLoading, repositoryEcosystem]);

  useEffect(() => {
    setIsLoadingTree(true);
    void Promise.all([loadDependencyTree(), loadLatestScanResults()]);
  }, [decodedId, loadDependencyTree, loadLatestScanResults]);

  useEffect(() => {
    if (activeSection === "history") {
      setScanHistoryPage(1);
      setSelectedHistoryJobId(null);
      setSelectedHistoryJob(null);
      setExpandedResultId(null);
      void loadScanHistory();
      if (historyScrollRef.current) {
        historyScrollRef.current.scrollTop = 0;
      }
    }
    // Only re-run when the active section or filter changes, not every loadScanHistory recreation
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection, decodedId, scanHistoryModeFilter, scanHistoryStatusFilter]);

  // When history refreshes and the currently-selected job transitions from running→done, re-fetch its details.
  useEffect(() => {
    if (!selectedHistoryJobId || !selectedHistoryJob) return;
    const updatedJob = scanHistoryJobs.find((j) => j.id === selectedHistoryJobId);
    if (!updatedJob) return;
    const wasInProgress = selectedHistoryJob.status === "running" || selectedHistoryJob.status === "pending";
    const isNowDone = updatedJob.status === "completed" || updatedJob.status === "failed" || updatedJob.status === "cancelled";
    if (wasInProgress && isNowDone) {
      void loadHistoryJobDetails(selectedHistoryJobId);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanHistoryJobs]);

  useEffect(() => {
    if (!selectedDetailsPackage || !repositoryEcosystem || !API_BASE_URL) {
      setPackageDetailsData(null);
      setPackageDetailsVersions([]);
      setPackageDetailsLatestVersion(null);
      setPackageDetailsScanEntry(null);
      return;
    }

    const lastAt = selectedDetailsPackage.lastIndexOf("@");
    const pkgName = lastAt > 0 ? selectedDetailsPackage.slice(0, lastAt) : selectedDetailsPackage;

    setIsPackageDetailsLoading(true);
    setPackageDetailsData(null);
    setPackageDetailsVersions([]);
    setPackageDetailsLatestVersion(null);
    setPackageDetailsScanEntry(null);

    let cancelled = false;

    const doFetch = async () => {
      try {
        const token = clientSessionStorage.readToken();
        const authHeaders: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
        const depContext = { baseUrl: API_BASE_URL!, authHeaders };

        const pkgVersion = selectedDetailsPackage.lastIndexOf("@") > 0
          ? selectedDetailsPackage.slice(selectedDetailsPackage.lastIndexOf("@") + 1)
          : undefined;

        const details = await fetchPackageDetails(depContext, repositoryEcosystem, pkgName, pkgVersion);

        if (cancelled) return;
        setPackageDetailsData(details);
        setPackageDetailsVersions([]);
        setPackageDetailsLatestVersion(details.latest_version ?? null);

        // Fetch full scan entry for advisory_references + risk data
        const repoCtx = await resolveRepoCoordinates();
        if (cancelled) return;
        const scanRes = await fetch(
          `${API_BASE_URL}/api/${encodeURIComponent(repoCtx.owner)}/${encodeURIComponent(repoCtx.repoName)}/scan/latest/results`,
          { method: "GET", headers: repoCtx.headers, credentials: "include", cache: "no-store" },
        );
        if (scanRes.ok && !cancelled) {
          const scanData = await scanRes.json() as Record<string, { advisory_references?: string[]; risk_overall_status?: string; risk_overall_score?: number; risk_allowlisted?: boolean; static_features?: Record<string, number | null>; dynamic_findings?: DynamicFinding | null; analyzed_by?: string[]; risk_assessment?: Record<string, unknown> }>;
          const entry = scanData[selectedDetailsPackage];
          if (entry && !cancelled) setPackageDetailsScanEntry(entry);
        }
      } catch { /* silent */ } finally {
        if (!cancelled) setIsPackageDetailsLoading(false);
      }
    };

    void doFetch();
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedDetailsPackage, repositoryEcosystem]);

  useEffect(() => {
    if (!graphDetailNode || !repositoryEcosystem || !API_BASE_URL) {
      setGraphNodePkgDetails(null);
      return;
    }
    const label = graphDetailNode.label;
    const lastAt = label.lastIndexOf("@");
    const pkgName = lastAt > 0 ? label.slice(0, lastAt) : label;
    const pkgVersion = lastAt > 0 ? label.slice(lastAt + 1) : undefined;

    setGraphNodePkgDetailsLoading(true);
    setGraphNodePkgDetails(null);
    let cancelled = false;

    const doFetch = async () => {
      try {
        const token = clientSessionStorage.readToken();
        const authHeaders: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
        const depContext = { baseUrl: API_BASE_URL!, authHeaders };
        const details = await fetchPackageDetails(depContext, repositoryEcosystem, pkgName, pkgVersion);
        if (!cancelled) setGraphNodePkgDetails(details);
      } catch { /* silent */ } finally {
        if (!cancelled) setGraphNodePkgDetailsLoading(false);
      }
    };
    void doFetch();
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphDetailNode?.label, repositoryEcosystem]);

  function handleSidebarResizeMouseDown(e: React.MouseEvent) {
    e.preventDefault();
    setIsResizingSidebar(true);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMouseMove = (ev: MouseEvent) => {
      const newWidth = Math.max(260, Math.min(540, window.innerWidth - ev.clientX));
      setAgentChatWidth(newWidth);
    };

    const onMouseUp = () => {
      setIsResizingSidebar(false);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  }

  return (
    <section className="relative flex h-[100dvh] w-full overflow-hidden bg-black">
      <div
        className={`flex h-full min-w-0 flex-1 flex-col ${isResizingSidebar ? "" : "transition-[padding-right] duration-300"}`}
        style={{ paddingRight: isAgentChatOpen ? agentChatWidth : 0 }}
      >
        <header className="border-b border-gray-800 bg-gray-950 px-6 py-4">
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Repository</p>
          <h1 className="mt-1 line-clamp-1 text-2xl font-semibold text-slate-100">{decodedId}</h1>
          {repositoryLanguage || repositoryEcosystem ? (
            <p className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-400">
              {repositoryLanguage}
              {repositoryLanguage && repositoryEcosystem ? " · " : ""}
              {repositoryEcosystem ? getEcosystemLabel(repositoryEcosystem) : ""}
            </p>
          ) : null}
        </header>

        <div className="flex flex-row items-center space-x-6 border-b border-gray-800 bg-gray-950 px-6 py-3">
          {sections.map((section) => {
            const isDisabled = isLoadingTree && section.key !== "graph";
            return (
              <button
                key={section.key}
                type="button"
                onClick={() => {
                  if (!isDisabled) {
                    setActiveSection(section.key);
                  }
                }}
                disabled={isDisabled}
                className={`border-b-2 pb-2 text-sm font-medium transition ${
                  activeSection === section.key
                    ? "border-teal-500 text-teal-400"
                    : "border-transparent text-gray-400 hover:text-gray-200"
                } ${isDisabled ? "cursor-not-allowed opacity-50" : ""}`}
                title={isDisabled ? "Available after dependency graph loads" : undefined}
              >
                {section.label}
              </button>
            );
          })}
        </div>

        <div className="relative flex-1 overflow-hidden">
          <main className="flex-1 relative h-full">
          {activeSection === "graph" ? (
            <div className="relative h-full w-full px-4 pb-0 pt-4">
              <div className="relative h-full overflow-hidden rounded-2xl border border-gray-800 bg-gray-950/90">
                <div className="absolute left-4 top-4 z-10 max-w-md rounded-2xl border border-gray-700/80 bg-gray-950/90 px-4 py-3 shadow-[0_18px_50px_-24px_rgba(2,6,23,0.95)] backdrop-blur">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Malware Package Scan</p>
                      <p className="mt-1 text-sm text-slate-400">Progress stays in the graph. Results appear here after completion.</p>
                    </div>
                    {/* Removed "View Results" toggle button per UI update request */}
                  </div>

                  {graphScanView === "progress" ? (
                    <div className="mt-3 space-y-2">
                      <p className="text-xs text-slate-400">{scanStatus}</p>
                      {shouldShowScanRuntime ? (
                        <span
                          className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${
                            scanDisplay.phase === "completed"
                              ? "border-emerald-300/50 bg-emerald-500/15 text-emerald-100"
                              : scanDisplay.phase === "cancelled"
                                ? "border-slate-300/50 bg-slate-500/15 text-slate-100"
                                : scanDisplay.phase === "failed"
                                  ? "border-rose-300/50 bg-rose-500/15 text-rose-100"
                                  : scanDisplay.phase === "running"
                                    ? "border-cyan-300/50 bg-cyan-500/15 text-cyan-100"
                                    : "border-amber-300/50 bg-amber-500/15 text-amber-100"
                          }`}
                        >
                          {scanDisplay.phase}
                        </span>
                      ) : null}

                      {shouldShowScanRuntime ? (
                        <div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            {scanDisplay.phase === "pending" ? (
                              <div className="h-full w-full animate-pulse rounded-full bg-cyan-300/40" />
                            ) : scanDisplay.phase === "running" && scanDisplay.progressPercent === 0 ? (
                              <div className="h-full w-1/5 animate-pulse rounded-full bg-cyan-300/60" />
                            ) : (
                              <div
                                className={`h-full rounded-full transition-all duration-300 ${scanError ? "bg-rose-400" : "bg-cyan-400"}`}
                                style={{ width: `${Math.max(2, Math.min(100, scanDisplay.progressPercent))}%` }}
                              />
                            )}
                          </div>
                          <p className="mt-1 text-[11px] uppercase tracking-[0.12em] text-slate-500">{scanDisplay.progressLabel}</p>
                          <p className="mt-1 text-xs text-slate-400">{scanDisplay.primaryCountLabel}</p>
                          {scanDisplay.secondaryCountLabel ? <p className="mt-1 text-xs text-slate-500">{scanDisplay.secondaryCountLabel}</p> : null}
                          <div className="mt-2 flex flex-wrap gap-3 text-[11px] uppercase tracking-[0.12em] text-slate-500">
                            {scanDisplay.etaLabel ? <span>{scanDisplay.etaLabel}</span> : null}
                            {scanDisplay.speedLabel ? <span>{scanDisplay.speedLabel}</span> : null}
                            {runtimeElapsedLabel ? <span>{runtimeElapsedLabel}</span> : null}
                          </div>
                        </div>
                      ) : null}

                      {scanResultRows.length > 0 ? (
                        <div className="max-h-[28vh] overflow-auto rounded-lg border border-slate-800">
                          <table className="w-full text-left text-xs text-slate-200">
                            <thead className="sticky top-0 bg-slate-900/95 text-slate-400">
                              <tr>
                                <th className="px-3 py-2 font-medium">Package</th>
                                <th className="px-3 py-2 font-medium">Verdict</th>
                                <th className="px-3 py-2 font-medium">Score</th>
                              </tr>
                            </thead>
                            <tbody>
                              {scanResultRows.map((row) => {
                                const verdictStatus = row.riskStatus ?? row.malwareStatus;
                                const verdictClass = verdictStatus === "malicious"
                                  ? "border-rose-400/50 bg-rose-500/15 text-rose-200"
                                  : verdictStatus === "suspicious"
                                    ? "border-amber-400/50 bg-amber-500/15 text-amber-200"
                                    : verdictStatus === "clean"
                                      ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-200"
                                      : "border-slate-600/50 bg-slate-800/30 text-slate-400";
                                const scoreValue = row.riskScore ?? row.malwareScore;
                                return (
                                  <tr key={row.id} className="border-t border-slate-800 hover:bg-slate-900/40">
                                    <td className="px-3 py-2 font-mono text-[11px]">{row.packageName}@{row.version}</td>
                                    <td className="px-3 py-2">
                                      {verdictStatus ? (
                                        <span className={`rounded-full border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] ${verdictClass}`}>
                                          {verdictStatus}
                                        </span>
                                      ) : <span className="text-slate-500">—</span>}
                                    </td>
                                    <td className="px-3 py-2 text-slate-300">
                                      {scoreValue != null ? `${(scoreValue * 100).toFixed(1)}%` : "—"}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      ) : null}

                      <div className="pt-1 space-y-2">
                        <div className="flex flex-wrap gap-1">
                          {(["full", "static_enrichment", "dynamic", "static"] as const).map((mode) => (
                            <button
                              key={mode}
                              type="button"
                              disabled={isScanRunning}
                              onClick={() => setActiveScanMode(mode)}
                              className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] transition ${
                                activeScanMode === mode
                                  ? "border-cyan-300/70 bg-cyan-500/20 text-cyan-50"
                                  : "border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-500"
                              } disabled:cursor-not-allowed disabled:opacity-50`}
                            >
                              {getScanModeLabel(mode)}
                            </button>
                          ))}
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {(["full", "partial"] as const).map((scope) => (
                            <button
                              key={scope}
                              type="button"
                              disabled={isScanRunning}
                              onClick={() => {
                                setScanScope(scope);
                                if (scope === "full") setSelectedScanPackages([]);
                              }}
                              className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] transition ${
                                scanScope === scope
                                  ? "border-cyan-300/70 bg-cyan-500/20 text-cyan-50"
                                  : "border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-500"
                              } disabled:cursor-not-allowed disabled:opacity-50`}
                            >
                              {scope === "full" ? "Full Scan" : "Partial Scan"}
                            </button>
                          ))}
                        </div>
                        {!isPartialScan ? (
                          <button
                            type="button"
                            disabled={isScanRunning}
                            onClick={() => setForceRescan((prev) => !prev)}
                            className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] transition ${
                              forceRescan
                                ? "border-amber-300/70 bg-amber-500/20 text-amber-50"
                                : "border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-500"
                            } disabled:cursor-not-allowed disabled:opacity-50`}
                          >
                            Force Rescan
                          </button>
                        ) : null}
                        {isPartialScan ? (
                          <div className="space-y-2">
                            <p className="text-[10px] text-slate-400">Select packages below, or click nodes on the graph.</p>
                            <input
                              type="text"
                              placeholder="Search packages..."
                              value={graphScanPackageSearch}
                              onChange={(e) => setGraphScanPackageSearch(e.target.value)}
                              disabled={isScanRunning}
                              className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60 disabled:opacity-50"
                            />
                            {selectedScanPackages.length > 0 ? (
                              <div className="flex flex-wrap gap-1.5">
                                {selectedScanPackages.map((pkg) => (
                                  <span key={pkg} className="inline-flex items-center gap-1 rounded-full border border-cyan-400/50 bg-cyan-500/20 px-2 py-0.5 text-[10px] text-cyan-100">
                                    <span className="max-w-[12rem] truncate font-mono">{pkg}</span>
                                    <button
                                      type="button"
                                      disabled={isScanRunning}
                                      onClick={() => toggleSelectedScanPackage(pkg)}
                                      className="ml-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full transition hover:bg-cyan-400/30 disabled:opacity-50"
                                    >
                                      ✕
                                    </button>
                                  </span>
                                ))}
                              </div>
                            ) : null}
                            <div className="max-h-32 overflow-auto rounded border border-slate-800 bg-slate-950/60 p-1.5">
                              {availablePackagesForAnalysis
                                .filter((p) => !graphScanPackageSearch || p.toLowerCase().includes(graphScanPackageSearch.toLowerCase()))
                                .map((pkg) => (
                                  <button
                                    key={pkg}
                                    type="button"
                                    disabled={isScanRunning}
                                    onClick={() => toggleSelectedScanPackage(pkg)}
                                    className={`block w-full rounded px-2 py-1 text-left font-mono text-[10px] transition ${
                                      selectedScanPackages.includes(pkg)
                                        ? "bg-cyan-500/20 text-cyan-100"
                                        : "text-slate-400 hover:bg-slate-800"
                                    } disabled:opacity-50`}
                                  >
                                    {pkg}
                                  </button>
                                ))}
                            </div>
                          </div>
                        ) : null}
                        {graphTabJobs.length > 1 ? (
                          <div className="mt-2 space-y-1">
                            {graphTabJobs.map(job => (
                              <div
                                key={job.jobId}
                                className="flex items-center justify-between gap-2 rounded-lg border border-slate-700/60 bg-slate-900/60 px-2 py-1.5"
                              >
                                <div className="flex items-center gap-2">
                                  {(job.status === "pending" || job.status === "running") ? (
                                    <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
                                  ) : (
                                    <span className={`h-2 w-2 rounded-full ${
                                      SCAN_TERMINAL_DONE.has(job.status) ? "bg-emerald-400"
                                      : SCAN_TERMINAL_FAILED.has(job.status) ? "bg-rose-400"
                                      : "bg-slate-500"
                                    }`} />
                                  )}
                                  <span className="text-[10px] uppercase tracking-[0.1em] text-slate-300">
                                    {job.scanMode}
                                  </span>
                                  <span className="text-[10px] text-slate-500">
                                    {job.progress > 0 ? `${job.progress.toFixed(0)}%` : job.status}
                                  </span>
                                </div>
                                {(job.status === "pending" || job.status === "running") ? (
                                  <button
                                    type="button"
                                    onClick={() => { void cancelScanJob(job.jobId); }}
                                    disabled={isCancellingScan}
                                    className="text-[9px] uppercase tracking-wide text-rose-300 hover:text-rose-100"
                                  >
                                    Stop
                                  </button>
                                ) : null}
                              </div>
                            ))}
                          </div>
                        ) : null}
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              void triggerPackageScan();
                            }}
                            disabled={!canStartScan}
                            className="inline-flex items-center rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200 transition hover:border-cyan-300 hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                          >
                            {scanStartLabel}
                          </button>
                          {canCancelScan ? (
                            <button
                              type="button"
                              onClick={() => {
                                void cancelScanJob();
                              }}
                              disabled={isCancellingScan}
                              className="inline-flex items-center rounded-lg border border-rose-400/40 bg-rose-500/15 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-rose-100 transition hover:bg-rose-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              {isCancellingScan ? "Stopping..." : "Stop Scan"}
                            </button>
                          ) : null}
                        </div>
                      </div>
                    </div>
                  ) : null}

                      {graphScanView === "results" && canShowGraphScanResults ? (
                    <div className="mt-3 rounded-xl border border-gray-800 bg-gray-900/70 p-3 text-xs text-slate-300">
                      <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-300">Results</p>
                      {latestScanSummary.status === null ? (
                        <p className="mt-2 text-slate-400">No completed scan results are available yet.</p>
                      ) : (
                        <div className="mt-2 space-y-1">
                          <p>Status: {latestScanSummary.status}</p>
                          <p>
                            Processed: {latestScanSummary.processed ?? "-"} / {latestScanSummary.total ?? "-"}
                          </p>
                          <p>Completed: {formatTimestampForDisplay(latestScanSummary.completedAt)}</p>
                          <p className="pt-1 text-slate-400">Results are highlighted directly on the dependency graph below.</p>
                        </div>
                      )}
                    </div>
                  ) : null}
                </div>

                <div className="absolute inset-0 h-full w-full">
                  <DependencyTree
                    nodes={nodes}
                    ecosystem={repositoryEcosystem ?? "npm"}
                    scanResultsMap={scanResultsMap}
                    selectedPackageLabels={selectedScanPackages}
                    selectionEnabled={isPartialScan}
                    onPackageToggleSelect={toggleSelectedScanPackage}
                    onNodeFeatureDetail={(label, features) => setGraphDetailNode({ label, features, scanEntry: scanResultsMap[label] ?? null })}
                  />
                </div>

                {graphDetailNode ? (
                  <div className="absolute bottom-4 right-4 top-4 z-20 flex w-[30rem] flex-col overflow-hidden rounded-2xl border border-slate-600 bg-slate-950/98 shadow-2xl backdrop-blur-sm">
                    <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-700/60 px-5 py-4">
                      <div className="min-w-0">
                        <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-indigo-400">Package Details</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => setGraphDetailNode(null)}
                        className="mt-0.5 shrink-0 rounded-lg px-2 py-1 text-sm text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition"
                      >
                        ✕
                      </button>
                    </div>
                    <div className="flex-1 overflow-y-auto space-y-4 px-5 py-4">
                      {/* Package identity + metadata */}
                      {(() => {
                        const label = graphDetailNode.label;
                        const lastAt = label.lastIndexOf("@");
                        const pkgName = lastAt > 0 ? label.slice(0, lastAt) : label;
                        const pkgVersion = lastAt > 0 ? label.slice(lastAt + 1) : null;
                        const scanEntry = graphDetailNode.scanEntry;
                        const verdict = scanEntry?.risk_overall_status ?? scanEntry?.malware_status;
                        const verdictCls = verdict === "malicious" ? "border-rose-400/50 bg-rose-500/15 text-rose-100"
                          : verdict === "suspicious" ? "border-amber-400/50 bg-amber-500/15 text-amber-100"
                          : verdict === "clean" ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-100"
                          : "border-slate-400/50 bg-slate-500/15 text-slate-300";
                        return (
                          <>
                            {/* Identity header */}
                            <div className="flex flex-wrap items-start justify-between gap-2">
                              <div>
                                <p className="text-base font-bold leading-snug text-slate-100">{pkgName}</p>
                                {pkgVersion ? <p className="mt-0.5 font-mono text-sm text-teal-300">v{pkgVersion}</p> : null}
                              </div>
                              <div className="flex flex-wrap items-center gap-1.5">
                                {graphNodePkgDetails?.ecosystem ? (
                                  <span className="rounded border border-slate-600 bg-slate-800/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-400">
                                    {graphNodePkgDetails.ecosystem}
                                  </span>
                                ) : null}
                                {graphNodePkgDetails?.license ? (
                                  <span className="rounded border border-slate-600 bg-slate-800/60 px-2 py-0.5 text-[10px] text-slate-300">
                                    {graphNodePkgDetails.license}
                                  </span>
                                ) : null}
                                {verdict && verdict !== "unknown" ? (
                                  <span className={`inline-flex rounded-full border px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${verdictCls}`}>
                                    {verdict}
                                  </span>
                                ) : null}
                              </div>
                            </div>

                            {/* Loading skeleton */}
                            {graphNodePkgDetailsLoading ? (
                              <div className="space-y-2">
                                <div className="h-4 w-full animate-pulse rounded bg-slate-800/80" />
                                <div className="h-4 w-3/4 animate-pulse rounded bg-slate-800/80" />
                              </div>
                            ) : (
                              <>
                                {/* Description */}
                                {graphNodePkgDetails?.description ? (
                                  <p className="text-xs leading-relaxed text-slate-300">{graphNodePkgDetails.description}</p>
                                ) : null}

                                {/* Links */}
                                {graphNodePkgDetails?.homepage || graphNodePkgDetails?.registry_url ? (
                                  <div className="flex flex-wrap gap-2">
                                    {graphNodePkgDetails.homepage ? (
                                      <a href={graphNodePkgDetails.homepage} target="_blank" rel="noreferrer"
                                        className="inline-flex items-center gap-1 rounded-lg border border-teal-400/30 bg-teal-500/10 px-2.5 py-1 text-[11px] font-medium text-teal-300 transition hover:bg-teal-500/20">
                                        Homepage ↗
                                      </a>
                                    ) : null}
                                    {graphNodePkgDetails.registry_url ? (
                                      <a href={graphNodePkgDetails.registry_url} target="_blank" rel="noreferrer"
                                        className="inline-flex items-center gap-1 rounded-lg border border-slate-600 bg-slate-800/60 px-2.5 py-1 text-[11px] font-medium text-slate-300 transition hover:bg-slate-700/60">
                                        {graphNodePkgDetails.ecosystem === "npm" ? "npmjs.com" : graphNodePkgDetails.ecosystem === "pypi" ? "PyPI" : "Registry"} ↗
                                      </a>
                                    ) : null}
                                  </div>
                                ) : null}

                                {/* Latest version */}
                                {graphNodePkgDetails?.latest_version ? (
                                  <p className="text-xs text-slate-400">
                                    Latest: <span className="font-mono text-teal-300">{graphNodePkgDetails.latest_version}</span>
                                  </p>
                                ) : null}

                                {/* Libraries.io metadata grid */}
                                {(() => {
                                  const d = graphNodePkgDetails;
                                  const metrics: [string, string][] = ([
                                    ["Monthly DL", d?.monthly_downloads != null
                                      ? d.monthly_downloads >= 1_000_000 ? `${(d.monthly_downloads / 1_000_000).toFixed(1)}M`
                                      : d.monthly_downloads >= 1_000 ? `${(d.monthly_downloads / 1_000).toFixed(0)}K`
                                      : String(d.monthly_downloads)
                                      : null],
                                    ["Stars", d?.stars != null ? String(d.stars) : null],
                                    ["Forks", d?.forks != null ? String(d.forks) : null],
                                    ["Contributors", d?.contributors_count != null ? String(d.contributors_count) : null],
                                    ["Dependents", d?.dependents_count != null ? String(d.dependents_count) : null],
                                    ["SourceRank", d?.source_rank != null ? String(d.source_rank) : null],
                                    ["Maintainers", d?.maintainer_count != null ? String(d.maintainer_count) : null],
                                    ["Age (days)", d?.package_age_days != null ? String(d.package_age_days) : null],
                                    ["Direct Deps", d?.direct_dependencies_count != null ? String(d.direct_dependencies_count) : null],
                                    ["Repository", d?.has_repository != null ? (d.has_repository ? "Yes" : "No") : null],
                                  ] as [string, string | null][]).filter(([, v]) => v !== null) as [string, string][];
                                  if (metrics.length === 0) return null;
                                  return (
                                    <div>
                                      <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-400">Package Metadata</p>
                                      <div className="grid grid-cols-3 gap-1.5">
                                        {metrics.map(([label, value]) => (
                                          <div key={label} className="rounded border border-slate-800 bg-slate-900/50 px-2 py-1.5">
                                            <p className="text-[9px] uppercase tracking-[0.08em] text-slate-500">{label}</p>
                                            <p className="mt-0.5 font-mono text-[11px] font-semibold text-slate-200">{value}</p>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  );
                                })()}

                                {/* Keywords */}
                                {graphNodePkgDetails?.keywords && graphNodePkgDetails.keywords.length > 0 ? (
                                  <div className="flex flex-wrap gap-1">
                                    {graphNodePkgDetails.keywords.map((kw) => (
                                      <span key={kw} className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 text-[10px] text-slate-400">{kw}</span>
                                    ))}
                                  </div>
                                ) : null}
                              </>
                            )}
                          </>
                        );
                      })()}

                      {/* Divider before scan results */}
                      {(graphDetailNode.scanEntry || graphDetailNode.features) ? (
                        <div className="border-t border-slate-700/60 pt-1">
                          <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Scan Results</p>
                        </div>
                      ) : null}

                      {/* Verdict */}
                      {((graphDetailNode.scanEntry?.risk_overall_status ?? graphDetailNode.scanEntry?.malware_status) && (graphDetailNode.scanEntry?.risk_overall_status ?? graphDetailNode.scanEntry?.malware_status) !== "unknown") ? (
                        <div>
                          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Verdict</p>
                          <div className="flex items-center gap-2">
                            <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${
                              (graphDetailNode.scanEntry?.risk_overall_status ?? graphDetailNode.scanEntry?.malware_status) === "malicious"
                                ? "border-rose-400/50 bg-rose-500/15 text-rose-200"
                                : (graphDetailNode.scanEntry?.risk_overall_status ?? graphDetailNode.scanEntry?.malware_status) === "suspicious"
                                  ? "border-amber-400/50 bg-amber-500/15 text-amber-200"
                                  : "border-emerald-400/50 bg-emerald-500/15 text-emerald-200"
                            }`}>
                              {(graphDetailNode.scanEntry?.risk_overall_status ?? graphDetailNode.scanEntry?.malware_status) ?? "unknown"}
                            </span>
                            {graphDetailNode.scanEntry.risk_overall_score != null ? (
                              <span className="text-[11px] text-slate-400">
                                {(graphDetailNode.scanEntry.risk_overall_score * 100).toFixed(1)}% confidence
                              </span>
                            ) : null}
                          </div>
                          {graphDetailNode.scanEntry.malware_score != null ? (
                            <p className="mt-1 text-[11px] text-slate-500">
                              Classifier confidence: {(graphDetailNode.scanEntry.malware_score * 100).toFixed(1)}%
                            </p>
                          ) : null}
                        </div>
                      ) : null}

                      {/* CVE findings */}
                      {graphDetailNode.scanEntry?.vulnerability_details && graphDetailNode.scanEntry.vulnerability_details.length > 0 ? (
                        <div>
                          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
                            CVE Findings ({graphDetailNode.scanEntry.vulnerability_details.length})
                          </p>
                          <div className="space-y-1">
                            {graphDetailNode.scanEntry.vulnerability_details.slice(0, 5).map((v, i) => {
                              const href = v.advisory_id.startsWith("CVE-")
                                ? `https://nvd.nist.gov/vuln/detail/${v.advisory_id}`
                                : v.advisory_id.startsWith("GHSA-")
                                  ? `https://github.com/advisories/${v.advisory_id}`
                                  : null;
                              return (
                                <div key={i} className="flex items-center justify-between gap-2 rounded border border-amber-400/30 bg-amber-500/10 px-2 py-1">
                                  {href ? (
                                    <a href={href} target="_blank" rel="noopener noreferrer" className="font-mono text-[10px] text-amber-200 underline hover:text-amber-100">
                                      {v.advisory_id}
                                    </a>
                                  ) : (
                                    <span className="font-mono text-[10px] text-amber-200">{v.advisory_id}</span>
                                  )}
                                  {v.value != null ? (
                                    <span className="shrink-0 text-[10px] text-slate-400">CVSS {v.value.toFixed(1)}</span>
                                  ) : null}
                                </div>
                              );
                            })}
                            {graphDetailNode.scanEntry.vulnerability_details.length > 5 ? (
                              <p className="text-[10px] text-slate-500">+{graphDetailNode.scanEntry.vulnerability_details.length - 5} more</p>
                            ) : null}
                          </div>
                        </div>
                      ) : null}

                      {/* Reputation */}
                      {graphDetailNode.scanEntry?.reputation_metadata && Object.keys(graphDetailNode.scanEntry.reputation_metadata).length > 0 ? (
                        <div>
                          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Reputation</p>
                          <div className="grid grid-cols-2 gap-1.5">
                            {(["libraries_io_rank", "stars", "forks", "dependents_count", "monthly_downloads", "trust_score"] as const).map((k) => {
                              const val = graphDetailNode.scanEntry?.reputation_metadata?.[k];
                              if (val == null) return null;
                              const label = k === "libraries_io_rank" ? "SourceRank" : k === "monthly_downloads" ? "Monthly DL" : k === "dependents_count" ? "Dependents" : k === "trust_score" ? "Trust Score" : k.replace(/_/g, " ");
                              return (
                                <div key={k} className="rounded border border-slate-700/60 bg-slate-900/60 px-2 py-1.5">
                                  <p className="text-[9px] uppercase tracking-wide text-slate-500">{label}</p>
                                  <p className="mt-0.5 font-mono text-[11px] text-slate-200">
                                    {k === "trust_score" ? `${(Number(val) * 100).toFixed(0)}%` : String(val)}
                                  </p>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      ) : null}

                      {/* Static features */}
                      {graphDetailNode.features && Object.keys(graphDetailNode.features).length > 0 ? (
                        <div>
                          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">Static Features</p>
                          <FeatureGrid features={graphDetailNode.features} />
                        </div>
                      ) : null}

                      {graphDetailNode.scanEntry?.dynamic_findings &&
                        graphDetailNode.scanEntry.dynamic_findings.status &&
                        graphDetailNode.scanEntry.dynamic_findings.status !== "skipped" ? (
                        <div>
                          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
                            Dynamic Analysis
                          </p>
                          <div className="grid grid-cols-2 gap-1.5">
                            {(
                              [
                                ["Status",    graphDetailNode.scanEntry.dynamic_findings.status],
                                ["Coverage",  graphDetailNode.scanEntry.dynamic_findings.coverage],
                                ["Risk Score", graphDetailNode.scanEntry.dynamic_findings.risk_score != null
                                  ? `${(graphDetailNode.scanEntry.dynamic_findings.risk_score * 100).toFixed(1)}%`
                                  : null],
                                ["VM Evasion", graphDetailNode.scanEntry.dynamic_findings.vm_evasion_observed != null
                                  ? (graphDetailNode.scanEntry.dynamic_findings.vm_evasion_observed ? "Detected" : "None")
                                  : null],
                                ["IOC Hit", graphDetailNode.scanEntry.dynamic_findings.ioc_hit != null
                                  ? (graphDetailNode.scanEntry.dynamic_findings.ioc_hit ? "Yes" : "None")
                                  : null],
                              ] as [string, string | null | undefined][]
                            )
                              .filter(([, v]) => v != null)
                              .map(([label, value]) => (
                                <div key={label} className="rounded border border-slate-700/60 bg-slate-900/60 px-2 py-1.5">
                                  <p className="text-[9px] uppercase tracking-wide text-slate-500">{label}</p>
                                  <p className={`mt-0.5 font-mono text-[11px] ${
                                    (label === "VM Evasion" || label === "IOC Hit") && value !== "None"
                                      ? "text-rose-300"
                                      : "text-slate-200"
                                  }`}>
                                    {value}
                                  </p>
                                </div>
                              ))}
                          </div>
                        </div>
                      ) : null}

                      {/* Empty state — only if no scan data exists and not loading */}
                      {!graphDetailNode.scanEntry?.malware_status &&
                        !(graphDetailNode.scanEntry?.vulnerability_details?.length) &&
                        !(graphDetailNode.scanEntry?.reputation_metadata && Object.keys(graphDetailNode.scanEntry.reputation_metadata).length > 0) &&
                        !graphDetailNode.features &&
                        !graphNodePkgDetailsLoading ? (
                        <p className="text-xs text-slate-500">No scan data available for this package yet.</p>
                      ) : null}
                    </div>
                  </div>
                ) : null}

                {isLoadingTree ? (
                  <div className="absolute inset-0 flex items-center justify-center p-8">
                    <LoadingState />
                  </div>
                ) : null}

                {!isLoadingTree && treeError ? (
                  <div className="absolute inset-0 flex items-center justify-center p-8">
                    <ErrorState message={treeError} />
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}

          {activeSection === "static-analysis" ? (
            <div className="h-full overflow-y-auto px-4 pb-6 pt-4">
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
                {/* Left column — controls only */}
                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-300">Static Analysis</p>
                    <p className="mt-1 text-sm text-slate-300">Select packages and run the static-analysis microservice only. Results appear in the right pane.</p>
                  </div>

                  <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                    <label className="block text-xs uppercase tracking-[0.14em] text-slate-400">
                      Select packages for analysis
                    </label>
                    <input
                      type="text"
                      value={analysisPackageSearch}
                      onChange={(event) => setAnalysisPackageSearch(event.target.value)}
                      placeholder="Search packages..."
                      className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
                    />
                    {selectedAnalysisPackages.length > 0 ? (
                      <div className="flex flex-wrap gap-2 rounded-md bg-slate-950/40 p-2">
                        {selectedAnalysisPackages.map((pkg) => (
                          <div
                            key={pkg}
                            className="inline-flex items-center gap-1.5 rounded-full border border-cyan-400/50 bg-cyan-500/20 px-2.5 py-1 text-xs text-cyan-100"
                          >
                            <span className="truncate font-medium">{pkg}</span>
                            <button
                              type="button"
                              onClick={() => toggleSelectedAnalysisPackage(pkg)}
                              className="ml-0.5 flex h-4 w-4 items-center justify-center rounded-full hover:bg-cyan-400/30 transition"
                              title="Remove package"
                            >
                              ✕
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : null}
                    <div className="max-h-52 overflow-auto rounded-md border border-slate-800 bg-slate-950/60 p-2">
                      {filteredPackagesForAnalysis.length === 0 ? (
                        <p className="p-2 text-xs text-slate-400">No packages found.</p>
                      ) : (
                        <div className="space-y-1">
                          {filteredPackagesForAnalysis.map((pkg) => {
                            const isSelected = selectedAnalysisPackages.includes(pkg);
                            return (
                              <button
                                key={pkg}
                                type="button"
                                onClick={() => toggleSelectedAnalysisPackage(pkg)}
                                className={`w-full rounded-md border px-3 py-2 text-left text-xs transition ${
                                  isSelected
                                    ? "border-cyan-400/60 bg-cyan-500/20 text-cyan-100 font-medium"
                                    : "border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-600 hover:bg-slate-900/50"
                                }`}
                              >
                                <div className="flex items-center justify-between">
                                  <span className="truncate">{pkg}</span>
                                  {isSelected ? <span className="ml-2 text-cyan-400">✓</span> : null}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                    {selectedAnalysisPackages.length > 0 ? (
                      <button
                        type="button"
                        onClick={() => {
                          void triggerPartialAnalysisScan();
                        }}
                        disabled={!canStartPartialAnalysisScan}
                        className="w-full rounded-md border border-cyan-400/40 bg-cyan-500/15 py-2 text-xs font-semibold uppercase tracking-[0.12em] text-cyan-100 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Run Analysis on {selectedAnalysisPackages.length} Package{selectedAnalysisPackages.length === 1 ? "" : "s"}
                      </button>
                    ) : null}
                    {/* Active static-analysis jobs started from this tab */}
                    {Array.from(activeScanJobs.values()).filter(j => j.sourceTab === "static-analysis").length > 0 ? (
                      <div className="mt-1 space-y-1">
                        {Array.from(activeScanJobs.values()).filter(j => j.sourceTab === "static-analysis").map(job => (
                          <div
                            key={job.jobId}
                            onClick={() => setSelectedStaticJobId(job.jobId)}
                            className={`flex items-center justify-between gap-2 rounded-lg border px-2 py-1.5 cursor-pointer transition ${selectedStaticJobId === job.jobId ? "border-cyan-500/50 bg-cyan-500/10" : "border-slate-700/60 bg-slate-900/60 hover:bg-slate-800/60"}`}
                          >
                            <div className="flex items-center gap-2">
                              {(job.status === "pending" || job.status === "running") ? (
                                <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
                              ) : (
                                <span className={`h-2 w-2 rounded-full ${
                                  SCAN_TERMINAL_DONE.has(job.status) ? "bg-emerald-400"
                                  : SCAN_TERMINAL_FAILED.has(job.status) ? "bg-rose-400"
                                  : "bg-slate-500"
                                }`} />
                              )}
                              <span className="text-[10px] uppercase tracking-[0.1em] text-slate-300">{job.scanMode}</span>
                              <span className="text-[10px] text-slate-500">
                                {job.progress > 0 ? `${job.progress.toFixed(0)}%` : job.status}
                              </span>
                              {job.elapsedSeconds > 0 ? (
                                <span className="text-[10px] text-slate-600">{formatDuration(job.elapsedSeconds)}</span>
                              ) : null}
                            </div>
                            {(job.status === "pending" || job.status === "running") ? (
                              <button
                                type="button"
                                onClick={() => { void cancelScanJob(job.jobId); }}
                                disabled={isCancellingScan}
                                className="text-[9px] uppercase tracking-wide text-rose-300 hover:text-rose-100"
                              >
                                Stop
                              </button>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </div>

                  <div className="grid gap-3 sm:grid-cols-3">
                    <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
                      <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Status</p>
                      <p className="mt-1 text-sm font-medium text-slate-100">{latestScanSummary.status ?? "—"}</p>
                    </div>
                    <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
                      <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Processed</p>
                      <p className="mt-1 text-sm font-medium text-slate-100">
                        {latestScanSummary.processed ?? "-"} / {latestScanSummary.total ?? "-"}
                      </p>
                    </div>
                    <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
                      <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Completed</p>
                      <p className="mt-1 text-sm font-medium text-slate-100">{formatTimestampForDisplay(latestScanSummary.completedAt)}</p>
                    </div>
                  </div>
                </div>

                {/* Right column — findings */}
                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">Scan Results</p>
                    {selectedStaticJobId ? (
                      <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-0.5 text-[10px] font-medium text-cyan-300">
                        {activeScanJobs.get(selectedStaticJobId)?.status ?? "—"}
                      </span>
                    ) : null}
                  </div>

                  {staticTabResults.length > 0 ? (
                    <div className="space-y-2">
                      {staticTabResults.map((row) => {
                        const isErrorRow = row.errorMessage !== null || row.status === "failed";
                        const isExpanded = expandedStaticResultId === row.id;
                        const riskBadgeClass =
                          row.riskStatus === "malicious"
                            ? "border-rose-400/50 bg-rose-500/15 text-rose-200"
                            : row.riskStatus === "suspicious"
                              ? "border-amber-400/50 bg-amber-500/15 text-amber-200"
                              : row.riskStatus === "clean"
                                ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-200"
                                : "border-slate-600 bg-slate-800/60 text-slate-400";
                        const entryFeatures = row.staticFeatures;

                        return (
                          <div
                            key={row.id}
                            className={`rounded-lg border text-sm ${isErrorRow ? "border-rose-400/30 bg-rose-500/10 text-rose-100" : "border-slate-700 bg-slate-950/60 text-slate-200"}`}
                          >
                            <button
                              type="button"
                              onClick={() => setExpandedStaticResultId(isExpanded ? null : row.id)}
                              className="w-full p-3 text-left"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <p className="font-medium">
                                  {row.packageName} <span className="text-slate-400">@</span> {row.version}
                                </p>
                                <div className="flex items-center gap-2">
                                  {row.riskStatus ? (
                                    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${riskBadgeClass}`}>
                                      {formatVerdict(row.riskStatus)}
                                    </span>
                                  ) : null}
                                  <span className="text-[11px] text-slate-500">{isExpanded ? "▲" : "▼"}</span>
                                </div>
                              </div>
                              <div className="mt-1 flex flex-wrap gap-4 text-xs text-slate-400">
                                <span>Classifier: {row.malwareScore !== null ? `${(row.malwareScore * 100).toFixed(1)}%` : row.malwareStatus ?? "-"}</span>
                                {row.riskScore !== null ? (
                                  <span>Risk: {(row.riskScore * 100).toFixed(1)}%</span>
                                ) : null}
                              </div>
                              {row.advisoryRefs.length > 0 ? (
                                <div className="mt-2 flex flex-wrap gap-1.5">
                                  {row.advisoryRefs.map((ref) => {
                                    const isCve = ref.toUpperCase().startsWith("CVE-");
                                    const isGhsa = ref.toUpperCase().startsWith("GHSA-");
                                    const href = isCve
                                      ? `https://nvd.nist.gov/vuln/detail/${ref}`
                                      : isGhsa
                                        ? `https://github.com/advisories/${ref}`
                                        : null;
                                    return href ? (
                                      <a
                                        key={ref}
                                        href={href}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        onClick={(e) => e.stopPropagation()}
                                        className="rounded border border-amber-400/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-200 hover:bg-amber-500/20 transition"
                                      >
                                        {ref}
                                      </a>
                                    ) : (
                                      <span key={ref} className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 text-[10px] text-slate-400">
                                        {ref}
                                      </span>
                                    );
                                  })}
                                </div>
                              ) : null}
                              {row.errorMessage ? <p className="mt-1 text-xs text-rose-200">{row.errorMessage}</p> : null}
                            </button>
                            {isExpanded ? (
                              <div className="border-t border-slate-700/60 px-3 pb-3 pt-2 space-y-3">
                                <div className="flex flex-wrap gap-3 text-xs">
                                  <div>
                                    <p className="text-[10px] uppercase tracking-wide text-slate-500">Static Analysis</p>
                                    <p className="mt-0.5 font-medium uppercase text-slate-200">
                                      {row.errorMessage ? "Error" : row.malwareScore !== null ? "Completed" : "Not Run"}
                                    </p>
                                  </div>
                                  {row.malwareScore !== null ? (
                                    <div>
                                      <p className="text-[10px] uppercase tracking-wide text-slate-500">Classifier Score</p>
                                      <p className="mt-0.5 font-mono font-medium text-slate-200">{(row.malwareScore * 100).toFixed(2)}%</p>
                                    </div>
                                  ) : null}
                                  {row.riskScore !== null ? (
                                    <div>
                                      <p className="text-[10px] uppercase tracking-wide text-slate-500">Risk Score</p>
                                      <p className="mt-0.5 font-mono font-medium text-slate-200">{(row.riskScore * 100).toFixed(2)}%</p>
                                    </div>
                                  ) : null}
                                  {row.scanTimestamp ? (
                                    <div>
                                      <p className="text-[10px] uppercase tracking-wide text-slate-500">Scanned At</p>
                                      <p className="mt-0.5 text-slate-300">{formatTimestampForDisplay(row.scanTimestamp)}</p>
                                    </div>
                                  ) : null}
                                </div>
                                {entryFeatures && Object.keys(entryFeatures).length > 0 ? (
                                  <div>
                                    <p className="mb-1.5 text-[10px] uppercase tracking-wide text-slate-500">Static Features</p>
                                    <FeatureGrid features={entryFeatures} />
                                  </div>
                                ) : null}
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-400">
                      {selectedStaticJobId
                        ? "No results available for the selected scan yet."
                        : "Select a scan above to view results."}
                    </p>
                  )}

                </div>
              </div>
            </div>
          ) : null}

          {activeSection === "dynamic-analysis" ? (
            <div className="h-full overflow-y-auto px-4 pb-6 pt-4">
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-300">Dynamic Analysis</p>
                    <p className="mt-1 text-sm text-slate-300">Track the live scan job while packages are being processed.</p>
                  </div>

                  <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                    <label className="block text-xs uppercase tracking-[0.14em] text-slate-400">
                      Select packages for analysis
                    </label>
                    <input
                      type="text"
                      value={analysisPackageSearch}
                      onChange={(event) => setAnalysisPackageSearch(event.target.value)}
                      placeholder="Search packages..."
                      className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
                    />
                    {selectedAnalysisPackages.length > 0 ? (
                      <div className="flex flex-wrap gap-2 rounded-md bg-slate-950/40 p-2">
                        {selectedAnalysisPackages.map((pkg) => (
                          <div
                            key={pkg}
                            className="inline-flex items-center gap-1.5 rounded-full border border-cyan-400/50 bg-cyan-500/20 px-2.5 py-1 text-xs text-cyan-100"
                          >
                            <span className="truncate font-medium">{pkg}</span>
                            <button
                              type="button"
                              onClick={() => toggleSelectedAnalysisPackage(pkg)}
                              className="ml-0.5 flex h-4 w-4 items-center justify-center rounded-full hover:bg-cyan-400/30 transition"
                              title="Remove package"
                            >
                              ✕
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : null}
                    <div className="max-h-40 overflow-auto rounded-md border border-slate-800 bg-slate-950/60 p-2">
                      {filteredPackagesForAnalysis.length === 0 ? (
                        <p className="p-2 text-xs text-slate-400">No packages found.</p>
                      ) : (
                        <div className="space-y-1">
                          {filteredPackagesForAnalysis.map((pkg) => {
                            const isSelected = selectedAnalysisPackages.includes(pkg);
                            return (
                              <button
                                key={pkg}
                                type="button"
                                onClick={() => toggleSelectedAnalysisPackage(pkg)}
                                className={`w-full rounded-md border px-3 py-2 text-left text-xs transition ${
                                  isSelected
                                    ? "border-cyan-400/60 bg-cyan-500/20 text-cyan-100 font-medium"
                                    : "border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-600 hover:bg-slate-900/50"
                                }`}
                              >
                                <div className="flex items-center justify-between">
                                  <span className="truncate">{pkg}</span>
                                  {isSelected ? <span className="ml-2 text-cyan-400">✓</span> : null}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                    {selectedAnalysisPackages.length > 0 ? (
                      <button
                        type="button"
                        onClick={() => {
                          void triggerPartialAnalysisScan("dynamic");
                        }}
                        disabled={!canStartPartialAnalysisScan}
                        className="w-full rounded-md border border-cyan-400/40 bg-cyan-500/15 py-2 text-xs font-semibold uppercase tracking-[0.12em] text-cyan-100 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Run Analysis on {selectedAnalysisPackages.length} Package{selectedAnalysisPackages.length === 1 ? "" : "s"}
                      </button>
                    ) : null}
                    {/* Active dynamic-analysis jobs started from this tab */}
                    {Array.from(activeScanJobs.values()).filter(j => j.sourceTab === "dynamic-analysis").length > 0 ? (
                      <div className="mt-1 space-y-1">
                        {Array.from(activeScanJobs.values()).filter(j => j.sourceTab === "dynamic-analysis").map(job => (
                          <div
                            key={job.jobId}
                            onClick={() => setSelectedDynamicJobId(job.jobId)}
                            className={`flex items-center justify-between gap-2 rounded-lg border px-2 py-1.5 cursor-pointer transition ${selectedDynamicJobId === job.jobId ? "border-cyan-500/50 bg-cyan-500/10" : "border-slate-700/60 bg-slate-900/60 hover:bg-slate-800/60"}`}
                          >
                            <div className="flex items-center gap-2">
                              {(job.status === "pending" || job.status === "running") ? (
                                <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
                              ) : (
                                <span className={`h-2 w-2 rounded-full ${
                                  SCAN_TERMINAL_DONE.has(job.status) ? "bg-emerald-400"
                                  : SCAN_TERMINAL_FAILED.has(job.status) ? "bg-rose-400"
                                  : "bg-slate-500"
                                }`} />
                              )}
                              <span className="text-[10px] uppercase tracking-[0.1em] text-slate-300">{job.scanMode}</span>
                              <span className="text-[10px] text-slate-500">
                                {job.progress > 0 ? `${job.progress.toFixed(0)}%` : job.status}
                              </span>
                              {job.elapsedSeconds > 0 ? (
                                <span className="text-[10px] text-slate-600">{formatDuration(job.elapsedSeconds)}</span>
                              ) : null}
                            </div>
                            {(job.status === "pending" || job.status === "running") ? (
                              <button
                                type="button"
                                onClick={() => { void cancelScanJob(job.jobId); }}
                                disabled={isCancellingScan}
                                className="text-[9px] uppercase tracking-wide text-rose-300 hover:text-rose-100"
                              >
                                Stop
                              </button>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </div>

                </div>

                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">Scan Results</p>
                    {selectedDynamicJobId ? (
                      <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-0.5 text-[10px] font-medium text-cyan-300">
                        {activeScanJobs.get(selectedDynamicJobId)?.status ?? "—"}
                      </span>
                    ) : null}
                  </div>

                  {dynamicTabResults.length > 0 ? (
                    <div className="space-y-2">
                      {dynamicTabResults.map((row) => {
                        const isErrorRow = row.errorMessage !== null || row.status === "failed";
                        const isExpanded = expandedDynamicRowId === row.id;
                        const verdictStatus = row.riskStatus ?? row.malwareStatus;
                        const verdictBadgeClass = verdictStatus === "malicious"
                          ? "border-rose-400/50 bg-rose-500/15 text-rose-200"
                          : verdictStatus === "suspicious"
                            ? "border-amber-400/50 bg-amber-500/15 text-amber-200"
                            : verdictStatus === "clean"
                              ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-200"
                              : "border-slate-600 bg-slate-800/60 text-slate-400";

                        return (
                          <div
                            key={row.id}
                            className={`rounded-lg border text-sm ${isErrorRow ? "border-rose-400/30 bg-rose-500/10 text-rose-100" : "border-slate-700 bg-slate-950/60 text-slate-200"}`}
                          >
                            <button
                              type="button"
                              onClick={() => setExpandedDynamicRowId(isExpanded ? null : row.id)}
                              className="w-full p-3 text-left"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <p className="font-medium">
                                  {row.packageName} <span className="text-slate-400">@</span> {row.version}
                                </p>
                                <div className="flex items-center gap-2">
                                  {verdictStatus ? (
                                    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${verdictBadgeClass}`}>
                                      {formatVerdict(verdictStatus)}
                                    </span>
                                  ) : null}
                                  <span className="text-[11px] text-slate-500">{isExpanded ? "▲" : "▼"}</span>
                                </div>
                              </div>
                              <div className="mt-1 flex flex-wrap gap-4 text-xs text-slate-400">
                                <span>Classifier: {row.malwareScore !== null ? `${(row.malwareScore * 100).toFixed(1)}%` : row.malwareStatus ?? "-"}</span>
                                {row.riskScore !== null ? (
                                  <span>Risk: {(row.riskScore * 100).toFixed(1)}%</span>
                                ) : null}
                              </div>
                              {row.advisoryRefs.length > 0 ? (
                                <div className="mt-2 flex flex-wrap gap-1.5">
                                  {row.advisoryRefs.map((ref) => {
                                    const isCve = ref.toUpperCase().startsWith("CVE-");
                                    const isGhsa = ref.toUpperCase().startsWith("GHSA-");
                                    const href = isCve
                                      ? `https://nvd.nist.gov/vuln/detail/${ref}`
                                      : isGhsa ? `https://github.com/advisories/${ref}` : null;
                                    return href ? (
                                      <a
                                        key={ref}
                                        href={href}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        onClick={(e) => e.stopPropagation()}
                                        className="rounded border border-amber-400/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-200 hover:bg-amber-500/20 transition"
                                      >
                                        {ref}
                                      </a>
                                    ) : (
                                      <span key={ref} className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 text-[10px] text-slate-400">{ref}</span>
                                    );
                                  })}
                                </div>
                              ) : null}
                              {row.errorMessage ? <p className="mt-1 text-xs text-rose-200">{row.errorMessage}</p> : null}
                            </button>
                            {isExpanded ? (
                              <div className="border-t border-slate-700/60 px-3 pb-3 pt-2 space-y-3">
                                <div className="flex flex-wrap gap-3 text-xs">
                                  <div>
                                    <p className="text-[10px] uppercase tracking-wide text-slate-500">Analysis Status</p>
                                    <p className="mt-0.5 font-medium uppercase text-slate-200">{row.analysisStatus ?? row.malwareStatus ?? "—"}</p>
                                  </div>
                                  {row.malwareScore !== null ? (
                                    <div>
                                      <p className="text-[10px] uppercase tracking-wide text-slate-500">Classifier Score</p>
                                      <p className="mt-0.5 font-mono font-medium text-slate-200">{(row.malwareScore * 100).toFixed(2)}%</p>
                                    </div>
                                  ) : null}
                                  {row.riskScore !== null ? (
                                    <div>
                                      <p className="text-[10px] uppercase tracking-wide text-slate-500">Risk Score</p>
                                      <p className="mt-0.5 font-mono font-medium text-slate-200">{(row.riskScore * 100).toFixed(2)}%</p>
                                    </div>
                                  ) : null}
                                  {row.scanTimestamp ? (
                                    <div>
                                      <p className="text-[10px] uppercase tracking-wide text-slate-500">Scanned At</p>
                                      <p className="mt-0.5 text-slate-300">{formatTimestampForDisplay(row.scanTimestamp)}</p>
                                    </div>
                                  ) : null}
                                </div>
                                {/* Dynamic findings */}
                                {row.dynamicFindings ? (
                                  <div className="space-y-2.5">
                                    <p className="text-[10px] uppercase tracking-wide text-slate-500">Dynamic Findings</p>
                                    <div className="flex flex-wrap gap-2">
                                      {row.dynamicFindings.sandbox_provider ? (
                                        <span className="rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[10px] text-slate-300">
                                          Sandbox: {row.dynamicFindings.sandbox_provider}
                                        </span>
                                      ) : null}
                                      {row.dynamicFindings.coverage ? (
                                        <span className="rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[10px] text-slate-300 uppercase">
                                          Coverage: {row.dynamicFindings.coverage}
                                        </span>
                                      ) : null}
                                      {row.dynamicFindings.ioc_hit !== undefined ? (
                                        <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${row.dynamicFindings.ioc_hit ? "border-rose-400/50 bg-rose-500/15 text-rose-200" : "border-slate-700 bg-slate-800/60 text-slate-400"}`}>
                                          IOC: {row.dynamicFindings.ioc_hit ? "HIT" : "clean"}
                                        </span>
                                      ) : null}
                                      {row.dynamicFindings.sandbox_timed_out ? (
                                        <span className="rounded border border-amber-400/40 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300">Timed Out</span>
                                      ) : null}
                                      {row.dynamicFindings.vm_evasion_observed ? (
                                        <span className="rounded border border-rose-400/40 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-300">VM Evasion</span>
                                      ) : null}
                                      {row.dynamicFindings.risk_score != null ? (
                                        <span className="rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 font-mono text-[10px] text-slate-300">
                                          Dynamic Risk: {(row.dynamicFindings.risk_score * 100).toFixed(1)}%
                                        </span>
                                      ) : null}
                                    </div>
                                    {row.dynamicFindings.syscall_trace ? (
                                      <div className="rounded border border-slate-700/60 bg-slate-900/60 px-3 py-2">
                                        <p className="mb-1 text-[9px] uppercase tracking-wide text-slate-500">Syscall Trace</p>
                                        <div className="flex flex-wrap gap-4 text-[10px]">
                                          {row.dynamicFindings.syscall_trace.suspicious_count != null ? (
                                            <span className="text-slate-300">Suspicious: <span className="font-mono text-amber-300">{row.dynamicFindings.syscall_trace.suspicious_count}</span></span>
                                          ) : null}
                                          {row.dynamicFindings.syscall_trace.categories && row.dynamicFindings.syscall_trace.categories.length > 0 ? (
                                            <span className="text-slate-300">Categories: {row.dynamicFindings.syscall_trace.categories.map(c => (
                                              <span key={c} className="ml-1 rounded bg-slate-800 px-1 py-0.5 text-slate-300">{c}</span>
                                            ))}</span>
                                          ) : null}
                                        </div>
                                      </div>
                                    ) : null}
                                    {row.dynamicFindings.network_activity ? (
                                      <div className="rounded border border-slate-700/60 bg-slate-900/60 px-3 py-2">
                                        <p className="mb-1 text-[9px] uppercase tracking-wide text-slate-500">Network Activity</p>
                                        {row.dynamicFindings.network_activity.outbound_connections != null ? (
                                          <p className="text-[10px] text-slate-300">Outbound connections: <span className="font-mono text-slate-200">{row.dynamicFindings.network_activity.outbound_connections}</span></p>
                                        ) : null}
                                        {row.dynamicFindings.network_activity.destinations && row.dynamicFindings.network_activity.destinations.length > 0 ? (
                                          <div className="mt-1 flex flex-wrap gap-1">
                                            {row.dynamicFindings.network_activity.destinations.map((d, i) => (
                                              <span key={i} className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">{d}</span>
                                            ))}
                                          </div>
                                        ) : null}
                                      </div>
                                    ) : null}
                                    {row.dynamicFindings.filesystem_changes ? (
                                      <div className="rounded border border-slate-700/60 bg-slate-900/60 px-3 py-2">
                                        <p className="mb-1 text-[9px] uppercase tracking-wide text-slate-500">Filesystem Changes</p>
                                        {row.dynamicFindings.filesystem_changes.sensitive_path_writes != null ? (
                                          <p className="text-[10px] text-slate-300">Sensitive path writes: <span className={`font-mono ${row.dynamicFindings.filesystem_changes.sensitive_path_writes > 0 ? "text-rose-300" : "text-slate-200"}`}>{row.dynamicFindings.filesystem_changes.sensitive_path_writes}</span></p>
                                        ) : null}
                                        {row.dynamicFindings.filesystem_changes.paths && row.dynamicFindings.filesystem_changes.paths.length > 0 ? (
                                          <div className="mt-1 flex flex-wrap gap-1">
                                            {row.dynamicFindings.filesystem_changes.paths.map((p, i) => (
                                              <span key={i} className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">{p}</span>
                                            ))}
                                          </div>
                                        ) : null}
                                      </div>
                                    ) : null}
                                    {row.dynamicFindings.ioc_detail ? (
                                      <div className="rounded border border-slate-700/60 bg-slate-900/60 px-3 py-2 space-y-1.5">
                                        <p className="text-[9px] uppercase tracking-wide text-slate-500">IOC Details</p>
                                        <div className="flex flex-wrap gap-3 text-[10px]">
                                          {row.dynamicFindings.ioc_detail.verdict ? (
                                            <span className="text-slate-300">Verdict: <span className="font-semibold uppercase text-slate-200">{row.dynamicFindings.ioc_detail.verdict}</span></span>
                                          ) : null}
                                          {row.dynamicFindings.ioc_detail.raw_line_count != null ? (
                                            <span className="text-slate-300">Log lines: <span className="font-mono text-slate-200">{row.dynamicFindings.ioc_detail.raw_line_count}</span></span>
                                          ) : null}
                                        </div>
                                        {(["network_iocs", "process_iocs", "file_iocs", "dns_iocs", "crypto_iocs"] as const).map((field) => {
                                          const items = row.dynamicFindings!.ioc_detail?.[field];
                                          if (!items || items.length === 0) return null;
                                          const label = field.replace("_iocs", "").replace("_", " ").toUpperCase();
                                          return (
                                            <div key={field}>
                                              <p className="mb-0.5 text-[9px] uppercase tracking-wide text-slate-500">{label} IOCs ({items.length})</p>
                                              <div className="flex flex-wrap gap-1">
                                                {items.map((item, i) => (
                                                  <span key={i} className="rounded bg-rose-950/60 border border-rose-700/40 px-1.5 py-0.5 font-mono text-[9px] text-rose-300">{item}</span>
                                                ))}
                                              </div>
                                            </div>
                                          );
                                        })}
                                        {row.dynamicFindings.ioc_detail.flagged_lines && row.dynamicFindings.ioc_detail.flagged_lines.length > 0 ? (
                                          <div>
                                            <p className="mb-0.5 text-[9px] uppercase tracking-wide text-slate-500">Flagged Lines ({row.dynamicFindings.ioc_detail.flagged_lines.length})</p>
                                            <div className="max-h-24 overflow-auto rounded bg-slate-950 p-1.5">
                                              {row.dynamicFindings.ioc_detail.flagged_lines.map((line, i) => (
                                                <p key={i} className="font-mono text-[9px] text-slate-300">{line}</p>
                                              ))}
                                            </div>
                                          </div>
                                        ) : null}
                                      </div>
                                    ) : null}
                                  </div>
                                ) : (
                                  <p className="text-[10px] text-slate-500">
                                    {(!row.analysisStatus || ["skipped", "not_malicious", "mode_excluded"].includes(row.analysisStatus))
                                      ? "Dynamic analysis not run for this package."
                                      : "No dynamic findings available."}
                                  </p>
                                )}
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-sm text-slate-400">
                      {selectedDynamicJobId ? "No results yet for selected scan." : "Select a scan above to view results."}
                    </p>
                  )}
                </div>
              </div>
            </div>
          ) : null}

          {activeSection === "details" ? (
            <div className="h-full overflow-y-auto px-4 pb-6 pt-4">
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
                <div className="space-y-4">
                  <div className="rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-teal-300">Package Details</p>
                    <p className="mt-1 text-sm text-slate-300">Browse installed packages and view detailed metadata.</p>
                  </div>
                  {selectedDetailsPackage ? (
                    <div className="space-y-5 rounded-2xl border border-slate-700 bg-slate-950/70 p-5">
                      {isPackageDetailsLoading ? (
                        <div className="space-y-3">
                          <div className="h-7 w-56 animate-pulse rounded bg-slate-700/60" />
                          <div className="h-5 w-full animate-pulse rounded bg-slate-800/80" />
                          <div className="h-5 w-3/4 animate-pulse rounded bg-slate-800/80" />
                        </div>
                      ) : (
                        <>
                          {/* Identity header */}
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                              <h3 className="text-2xl font-bold text-slate-100">
                                {selectedDetailsPackage.slice(0, selectedDetailsPackage.lastIndexOf("@")) || selectedDetailsPackage}
                              </h3>
                              <p className="mt-0.5 font-mono text-base text-teal-300">
                                v{selectedDetailsPackage.slice(selectedDetailsPackage.lastIndexOf("@") + 1) || "unknown"}
                              </p>
                            </div>
                            <div className="flex flex-wrap items-center gap-2">
                              {packageDetailsData?.ecosystem ? (
                                <span className="rounded border border-slate-600 bg-slate-800/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-400">
                                  {packageDetailsData.ecosystem}
                                </span>
                              ) : null}
                              {packageDetailsData?.license ? (
                                <span className="rounded border border-slate-600 bg-slate-800/60 px-2 py-0.5 text-[10px] text-slate-300">
                                  {packageDetailsData.license}
                                </span>
                              ) : null}
                              {(() => {
                                const entry = scanResultsMap[selectedDetailsPackage] as { malware_status?: string } | undefined;
                                const status = packageDetailsScanEntry?.risk_overall_status ?? entry?.malware_status;
                                if (!status) return null;
                                const cls = status === "malicious" ? "border-rose-400/50 bg-rose-500/15 text-rose-100"
                                  : status === "suspicious" ? "border-amber-400/50 bg-amber-500/15 text-amber-100"
                                  : status === "clean" ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-100"
                                  : "border-slate-400/50 bg-slate-500/15 text-slate-300";
                                return (
                                  <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] ${cls}`}>
                                    {status}
                                  </span>
                                );
                              })()}
                            </div>
                          </div>

                          {/* Description */}
                          {packageDetailsData?.description ? (
                            <p className="text-sm leading-relaxed text-slate-300">{packageDetailsData.description}</p>
                          ) : null}

                          {/* Links */}
                          {packageDetailsData?.homepage || packageDetailsData?.registry_url ? (
                            <div className="flex flex-wrap gap-4">
                              {packageDetailsData.homepage ? (
                                <a href={packageDetailsData.homepage} target="_blank" rel="noreferrer"
                                  className="inline-flex items-center gap-1.5 rounded-lg border border-teal-400/30 bg-teal-500/10 px-3 py-1.5 text-xs font-medium text-teal-300 transition hover:bg-teal-500/20">
                                  Homepage ↗
                                </a>
                              ) : null}
                              {packageDetailsData.registry_url ? (
                                <a href={packageDetailsData.registry_url} target="_blank" rel="noreferrer"
                                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-600 bg-slate-800/60 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-slate-700/60">
                                  {packageDetailsData.ecosystem === "npm" ? "npmjs.com" : packageDetailsData.ecosystem === "pypi" ? "PyPI" : "Registry"} ↗
                                </a>
                              ) : null}
                            </div>
                          ) : null}

                          {/* Version comparison */}
                          {packageDetailsLatestVersion ? (
                            <div className="flex flex-wrap items-center gap-4 text-sm">
                              <span className="text-slate-400">
                                Installed: <span className="font-mono text-slate-200">{selectedDetailsPackage.slice(selectedDetailsPackage.lastIndexOf("@") + 1) || "unknown"}</span>
                              </span>
                              <span className="text-slate-700">·</span>
                              <span className="text-slate-400">
                                Latest: <span className="font-mono text-teal-300">{packageDetailsLatestVersion}</span>
                              </span>
                              {packageDetailsVersions.length > 1 ? (
                                <span className="text-xs text-slate-500">{packageDetailsVersions.length} versions available</span>
                              ) : null}
                            </div>
                          ) : null}

                          {/* Libraries.io metadata grid */}
                          {(() => {
                            const d = packageDetailsData;
                            const metrics: [string, string | null][] = [
                              ["Monthly Downloads", d?.monthly_downloads != null
                                ? d.monthly_downloads >= 1_000_000 ? `${(d.monthly_downloads / 1_000_000).toFixed(1)}M`
                                : d.monthly_downloads >= 1_000 ? `${(d.monthly_downloads / 1_000).toFixed(0)}K`
                                : String(d.monthly_downloads)
                                : null],
                              ["Stars", d?.stars != null ? String(d.stars) : null],
                              ["Forks", d?.forks != null ? String(d.forks) : null],
                              ["Contributors", d?.contributors_count != null ? String(d.contributors_count) : null],
                              ["Dependents", d?.dependents_count != null ? String(d.dependents_count) : null],
                              ["SourceRank", d?.source_rank != null ? String(d.source_rank) : null],
                              ["Maintainers", d?.maintainer_count != null ? String(d.maintainer_count) : null],
                              ["Age (days)", d?.package_age_days != null ? String(d.package_age_days) : null],
                              ["Direct Deps", d?.direct_dependencies_count != null ? String(d.direct_dependencies_count) : null],
                              ["Repository", d?.has_repository != null ? (d.has_repository ? "Yes" : "No") : null],
                            ].filter(([, v]) => v !== null) as [string, string][];
                            if (metrics.length === 0) return null;
                            return (
                              <div>
                                <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">Package Metadata</p>
                                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                                  {metrics.map(([label, value]) => (
                                    <div key={label} className="rounded-lg border border-slate-800 bg-slate-900/50 px-3 py-2.5">
                                      <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">{label}</p>
                                      <p className="mt-1 font-mono text-sm font-semibold text-slate-200">{value}</p>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            );
                          })()}

                          {/* Keywords */}
                          {packageDetailsData?.keywords && packageDetailsData.keywords.length > 0 ? (
                            <div>
                              <p className="mb-2 text-[11px] uppercase tracking-[0.14em] text-slate-500">Keywords</p>
                              <div className="flex flex-wrap gap-1.5">
                                {packageDetailsData.keywords.map((kw) => (
                                  <span key={kw} className="rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[11px] text-slate-400">{kw}</span>
                                ))}
                              </div>
                            </div>
                          ) : null}

                          {(() => {
                            const ra = packageDetailsScanEntry?.risk_assessment as Record<string, unknown> | undefined;
                            const raMetadata = ra?.metadata as Record<string, unknown> | undefined;
                            const repMeta = raMetadata?.reputation as Record<string, unknown> | undefined;
                            const vulnSignals = (ra?.vulnerability_signals as Array<Record<string, unknown>> | undefined) ?? [];
                            const hasReputation = repMeta && Object.keys(repMeta).length > 0 && (repMeta.rank != null || repMeta.stars != null || repMeta.trust_score != null);
                            const hasVulnDetails = vulnSignals.length > 0;

                            const advisoryIds = packageDetailsScanEntry?.advisory_references ?? [];
                            return (
                              <>
                                {/* CVE / Advisory References */}
                                {advisoryIds.length > 0 ? (
                                  <div className="rounded-lg border border-amber-400/25 bg-amber-500/10 p-4">
                                    <p className="text-sm font-semibold uppercase tracking-[0.12em] text-amber-200">
                                      {advisoryIds.length} CVE / Advisory Reference{advisoryIds.length !== 1 ? "s" : ""}
                                    </p>
                                    <div className="mt-3 space-y-2.5">
                                      {hasVulnDetails ? vulnSignals.map((sig, idx) => {
                                        const sigMeta = sig.metadata as Record<string, unknown> | undefined;
                                        const advId = (sigMeta?.advisory_id ?? advisoryIds[idx] ?? "") as string;
                                        const cvss = sigMeta?.cvss_score ?? sig.value;
                                        const desc = sigMeta?.summary ?? sigMeta?.details ?? null;
                                        const refs = (sigMeta?.references as string[] | undefined) ?? [];
                                        return (
                                          <div key={advId || idx} className="rounded-lg border border-amber-400/20 bg-amber-500/10 p-3">
                                            <div className="flex flex-wrap items-center gap-2">
                                              <span className="font-mono text-sm text-amber-100">{advId}</span>
                                              {cvss != null ? (
                                                <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-semibold ${Number(cvss) >= 7 ? "border-rose-400/40 bg-rose-500/15 text-rose-200" : Number(cvss) >= 4 ? "border-amber-400/40 bg-amber-500/15 text-amber-200" : "border-slate-600 bg-slate-800 text-slate-400"}`}>
                                                  CVSS {Number(cvss).toFixed(1)}
                                                </span>
                                              ) : null}
                                            </div>
                                            {desc ? <p className="mt-1.5 text-sm text-slate-300">{String(desc).slice(0, 200)}{String(desc).length > 200 ? "…" : ""}</p> : null}
                                            {refs.length > 0 ? (
                                              <div className="mt-2 flex flex-wrap gap-2">
                                                {refs.slice(0, 3).map((ref, i) => (
                                                  <a key={i} href={ref} target="_blank" rel="noreferrer" className="text-xs text-teal-300 underline decoration-teal-400/50 underline-offset-2">{new URL(ref).hostname} ↗</a>
                                                ))}
                                              </div>
                                            ) : null}
                                          </div>
                                        );
                                      }) : (
                                        <div className="flex flex-wrap gap-2">
                                          {advisoryIds.map((ref) => (
                                            <span key={ref} className="inline-flex rounded border border-amber-400/30 bg-amber-500/15 px-2 py-1 font-mono text-xs text-amber-100">{ref}</span>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                ) : packageDetailsScanEntry ? (
                                  <p className="text-sm text-slate-500">No CVE advisories found for this package.</p>
                                ) : null}

                                {/* Libraries.io / Reputation */}
                                {hasReputation ? (
                                  <div className="rounded-lg border border-slate-700 bg-slate-900/50 p-4">
                                    <p className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-slate-400">Package Reputation (Libraries.io)</p>
                                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                                      {([
                                        ["SourceRank", repMeta!.rank, null],
                                        ["Stars", repMeta!.stars, null],
                                        ["Dependents", repMeta!.dependents_count, null],
                                        ["Forks", repMeta!.forks, null],
                                        ["Contributors", repMeta!.contributions_count, null],
                                        ["Trust Score", repMeta!.trust_score, "%"],
                                      ] as [string, unknown, string | null][]).filter(([, v]) => v != null).map(([label, val, unit]) => (
                                        <div key={label} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                          <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">{label}</p>
                                          <p className="mt-1 font-mono text-sm text-slate-200">
                                            {unit === "%" ? `${(Number(val) * 100).toFixed(0)}%` : String(val)}
                                          </p>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                ) : null}
                              </>
                            );
                          })()}

                          {packageDetailsScanEntry?.static_features && Object.keys(packageDetailsScanEntry.static_features).length > 0 ? (
                            <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
                              <p className="mb-3 text-sm font-semibold uppercase tracking-[0.12em] text-slate-400">Static Features</p>
                              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                                {Object.entries(packageDetailsScanEntry.static_features).map(([key, val]) => (
                                  <div key={key} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                    <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">
                                      {({"max_entropy": "Max Entropy", "avg_entropy": "Avg Entropy", "eval_count": "eval() Calls", "exec_count": "exec() Calls", "base64_count": "Base64 Strings", "network_imports": "Network Imports", "obfuscation_index": "Obfuscation Score"} as Record<string, string>)[key] ?? key.replace(/_/g, " ")}
                                    </p>
                                    <p className="mt-1 font-mono text-sm text-slate-200">{val != null ? (typeof val === "number" && val < 1 && val > 0 ? `${(val * 100).toFixed(0)}%` : String(val)) : "-"}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : null}

                          {packageDetailsScanEntry?.dynamic_findings && packageDetailsScanEntry.analyzed_by?.includes("dynamic") ? (
                            <div className="space-y-4 rounded-lg border border-slate-800 bg-slate-900/50 p-4">
                              <p className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-400">Dynamic Analysis</p>

                              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                  <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">Status</p>
                                  <p className="mt-1 font-mono text-sm text-slate-200">
                                    {packageDetailsScanEntry.dynamic_findings.status ?? "—"}
                                  </p>
                                </div>
                                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                  <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">Coverage</p>
                                  <p className="mt-1 font-mono text-sm text-slate-200">
                                    {packageDetailsScanEntry.dynamic_findings.coverage ?? "—"}
                                  </p>
                                </div>
                                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                  <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">Risk Score</p>
                                  <p className="mt-1 font-mono text-sm text-slate-200">
                                    {packageDetailsScanEntry.dynamic_findings.risk_score != null
                                      ? `${(packageDetailsScanEntry.dynamic_findings.risk_score * 100).toFixed(1)}%`
                                      : "—"}
                                  </p>
                                </div>
                                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                  <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">VM Evasion</p>
                                  <p className={`mt-1 font-mono text-sm font-semibold ${
                                    packageDetailsScanEntry.dynamic_findings.vm_evasion_observed
                                      ? "text-rose-300"
                                      : "text-emerald-300"
                                  }`}>
                                    {packageDetailsScanEntry.dynamic_findings.vm_evasion_observed ? "Detected" : "None"}
                                  </p>
                                </div>
                                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                  <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">IOC Hit</p>
                                  <p className={`mt-1 font-mono text-sm font-semibold ${
                                    packageDetailsScanEntry.dynamic_findings.ioc_hit
                                      ? "text-rose-300"
                                      : "text-emerald-300"
                                  }`}>
                                    {packageDetailsScanEntry.dynamic_findings.ioc_hit ? "Yes" : "None"}
                                  </p>
                                </div>
                                {packageDetailsScanEntry.dynamic_findings.sandbox_provider ? (
                                  <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2.5">
                                    <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">Sandbox</p>
                                    <p className="mt-1 font-mono text-sm text-slate-200">
                                      {packageDetailsScanEntry.dynamic_findings.sandbox_provider}
                                    </p>
                                  </div>
                                ) : null}
                              </div>

                              <div className="flex flex-wrap gap-2">
                                {packageDetailsScanEntry.dynamic_findings.status ? (
                                  <span className={`inline-flex rounded border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.08em] ${packageDetailsScanEntry.dynamic_findings.status === "completed" ? "border-emerald-400/30 bg-emerald-500/15 text-emerald-200" : packageDetailsScanEntry.dynamic_findings.status === "partial" ? "border-amber-400/30 bg-amber-500/15 text-amber-200" : "border-rose-400/30 bg-rose-500/15 text-rose-200"}`}>
                                    {packageDetailsScanEntry.dynamic_findings.status}
                                  </span>
                                ) : null}
                                {packageDetailsScanEntry.dynamic_findings.coverage ? (
                                  <span className={`inline-flex rounded border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.08em] ${packageDetailsScanEntry.dynamic_findings.coverage === "full" ? "border-teal-400/30 bg-teal-500/15 text-teal-200" : "border-slate-600 bg-slate-800 text-slate-400"}`}>
                                    Coverage: {packageDetailsScanEntry.dynamic_findings.coverage}
                                  </span>
                                ) : null}
                              </div>

                              {packageDetailsScanEntry.dynamic_findings.vm_evasion_observed ? (
                                <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2.5 text-sm text-rose-200">
                                  ⚠ VM Evasion Detected — package actively attempted to detect the sandbox environment
                                </div>
                              ) : null}

                              {packageDetailsScanEntry.dynamic_findings.ioc_detail ? (() => {
                                const ioc = packageDetailsScanEntry.dynamic_findings!.ioc_detail!;
                                const verdictColor = ioc.verdict === "malicious" ? "border-rose-400/30 bg-rose-500/15 text-rose-200" : ioc.verdict === "suspicious" ? "border-amber-400/30 bg-amber-500/15 text-amber-200" : "border-emerald-400/30 bg-emerald-500/15 text-emerald-200";
                                const iocGroups: [string, string[] | undefined][] = [["Network", ioc.network_iocs], ["Process", ioc.process_iocs], ["File", ioc.file_iocs], ["DNS", ioc.dns_iocs], ["Crypto", ioc.crypto_iocs]];
                                return (
                                  <div className="space-y-3">
                                    <div className="flex items-center gap-2.5">
                                      <p className="text-xs uppercase tracking-[0.08em] text-slate-400">IOC Verdict</p>
                                      {ioc.verdict ? <span className={`inline-flex rounded border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-[0.08em] ${verdictColor}`}>{ioc.verdict}</span> : null}
                                    </div>
                                    {iocGroups.filter(([, items]) => items && items.length > 0).map(([label, items]) => (
                                      <div key={label}>
                                        <p className="mb-1.5 text-xs uppercase tracking-[0.08em] text-slate-400">{label} IOCs</p>
                                        <div className="flex flex-wrap gap-1.5">
                                          {items!.map((item, idx) => <span key={idx} className="inline-flex rounded border border-slate-700 bg-slate-950/60 px-2 py-0.5 font-mono text-xs text-slate-300">{item}</span>)}
                                        </div>
                                      </div>
                                    ))}
                                    {ioc.flagged_lines && ioc.flagged_lines.length > 0 ? (
                                      <div>
                                        <p className="mb-1.5 text-xs uppercase tracking-[0.08em] text-slate-400">Flagged Syscalls</p>
                                        <div className="space-y-1 overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60 p-3 font-mono text-xs text-slate-400">
                                          {ioc.flagged_lines.slice(0, 5).map((line, idx) => <div key={idx} className="truncate">{line}</div>)}
                                          {ioc.flagged_lines.length > 5 ? <p className="text-slate-500">+{ioc.flagged_lines.length - 5} more lines</p> : null}
                                        </div>
                                      </div>
                                    ) : null}
                                  </div>
                                );
                              })() : null}

                              {packageDetailsScanEntry.dynamic_findings.syscall_trace ? (
                                <div>
                                  <p className="mb-1.5 text-xs uppercase tracking-[0.08em] text-slate-400">Syscall Trace</p>
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="font-mono text-sm text-slate-300">{packageDetailsScanEntry.dynamic_findings.syscall_trace.suspicious_count ?? 0} suspicious calls</span>
                                    {packageDetailsScanEntry.dynamic_findings.syscall_trace.categories?.map((cat) => (
                                      <span key={cat} className="inline-flex rounded border border-slate-700 bg-slate-800/60 px-2 py-0.5 font-mono text-xs text-slate-400">{cat}</span>
                                    ))}
                                  </div>
                                </div>
                              ) : null}

                              {packageDetailsScanEntry.dynamic_findings.network_activity ? (
                                <div>
                                  <p className="mb-1.5 text-xs uppercase tracking-[0.08em] text-slate-400">Network Activity</p>
                                  <p className="mb-1.5 font-mono text-sm text-slate-300">{packageDetailsScanEntry.dynamic_findings.network_activity.outbound_connections ?? 0} outbound connection{(packageDetailsScanEntry.dynamic_findings.network_activity.outbound_connections ?? 0) !== 1 ? "s" : ""}</p>
                                  {packageDetailsScanEntry.dynamic_findings.network_activity.destinations && packageDetailsScanEntry.dynamic_findings.network_activity.destinations.length > 0 ? (
                                    <div className="flex flex-wrap gap-1.5">
                                      {packageDetailsScanEntry.dynamic_findings.network_activity.destinations.map((dest, idx) => <span key={idx} className="inline-flex rounded border border-slate-700 bg-slate-950/60 px-2 py-0.5 font-mono text-xs text-slate-300">{dest}</span>)}
                                    </div>
                                  ) : null}
                                </div>
                              ) : null}

                              {packageDetailsScanEntry.dynamic_findings.filesystem_changes ? (
                                <div>
                                  <p className="mb-1.5 text-xs uppercase tracking-[0.08em] text-slate-400">Filesystem Changes</p>
                                  <p className="mb-1.5 font-mono text-sm text-slate-300">{packageDetailsScanEntry.dynamic_findings.filesystem_changes.sensitive_path_writes ?? 0} sensitive path write{(packageDetailsScanEntry.dynamic_findings.filesystem_changes.sensitive_path_writes ?? 0) !== 1 ? "s" : ""}</p>
                                  {packageDetailsScanEntry.dynamic_findings.filesystem_changes.paths && packageDetailsScanEntry.dynamic_findings.filesystem_changes.paths.length > 0 ? (
                                    <div className="flex flex-wrap gap-1.5">
                                      {packageDetailsScanEntry.dynamic_findings.filesystem_changes.paths.map((path, idx) => <span key={idx} className="inline-flex rounded border border-slate-700 bg-slate-950/60 px-2 py-0.5 font-mono text-xs text-slate-300">{path}</span>)}
                                    </div>
                                  ) : null}
                                </div>
                              ) : null}

                              {packageDetailsScanEntry.dynamic_findings.sandbox_timed_out ? (
                                <div className="rounded-lg border border-amber-400/25 bg-amber-500/10 px-3 py-2.5 text-sm text-amber-200">
                                  Sandbox timed out — coverage may be incomplete
                                </div>
                              ) : null}
                            </div>
                          ) : null}
                        </>
                      )}
                    </div>
                  ) : (
                    <div className="rounded-2xl border border-slate-700 bg-slate-950/70 p-4 text-center">
                      <p className="text-sm text-slate-400">Select a package from the list to view details</p>
                    </div>
                  )}
                </div>
                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div>
                    <label className="block text-xs uppercase tracking-[0.14em] text-slate-400">Search Packages</label>
                    <input
                      type="text"
                      value={detailsPackageSearch}
                      onChange={(event) => setDetailsPackageSearch(event.target.value)}
                      placeholder="Filter packages..."
                      className="mt-2 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-teal-400/60"
                    />
                  </div>
                  <div className="space-y-2">
                    <p className="text-xs uppercase tracking-[0.12em] text-slate-400">Installed Packages ({availablePackagesForAnalysis.length})</p>
                    <div className="max-h-[60vh] space-y-1 overflow-auto rounded-lg border border-slate-800 bg-slate-950/40 p-2">
                      {availablePackagesForAnalysis
                        .filter((pkg) => pkg.toLowerCase().includes(detailsPackageSearch.toLowerCase()))
                        .map((pkg) => (
                          <button
                            key={pkg}
                            type="button"
                            onClick={() => setSelectedDetailsPackage(pkg)}
                            className={`w-full rounded-md border px-3 py-2 text-left text-xs transition ${
                              selectedDetailsPackage === pkg
                                ? "border-teal-400/60 bg-teal-500/20 text-teal-100 font-medium"
                                : "border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-600 hover:bg-slate-900/50"
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="truncate font-mono text-xs">{pkg}</span>
                              {selectedDetailsPackage === pkg ? <span className="ml-2 text-teal-400">▶</span> : null}
                            </div>
                          </button>
                        ))}
                      {availablePackagesForAnalysis.filter((pkg) => pkg.toLowerCase().includes(detailsPackageSearch.toLowerCase())).length === 0 ? (
                        <p className="p-2 text-xs text-slate-400">No packages match your search.</p>
                      ) : null}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : null}

          {activeSection === "sbom" ? (
            <div className="h-full overflow-y-auto px-4 pb-6 pt-4">
              <div className="space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-violet-300">Software Bill of Materials</p>
                    <p className="mt-1 text-sm text-slate-300">
                      {sbomDocument
                        ? `${sbomDocument.components.length} component${sbomDocument.components.length !== 1 ? "s" : ""} · generated ${new Date(sbomDocument.metadata.timestamp).toLocaleString()}`
                        : "Generate a complete inventory of all packages in this project."}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => { void generateSbomHandler(); }}
                      disabled={isSbomLoading}
                      className="rounded-lg border border-violet-400/40 bg-violet-500/15 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-violet-100 transition hover:bg-violet-500/25 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {isSbomLoading ? "Generating..." : sbomDocument ? "Regenerate SBOM" : "Generate SBOM"}
                    </button>
                    {sbomDocument ? (
                      <>
                        <button
                          type="button"
                          onClick={downloadSbomSentinelFlow}
                          className="rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-slate-200 transition hover:bg-slate-700"
                        >
                          Download JSON
                        </button>
                        <button
                          type="button"
                          onClick={() => { void downloadSbomCycloneDx(); }}
                          disabled={isSbomCdxLoading}
                          className="rounded-lg border border-slate-600 bg-slate-800 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-slate-200 transition hover:bg-slate-700 disabled:opacity-50"
                        >
                          {isSbomCdxLoading ? "Exporting..." : "Download CycloneDX 1.5"}
                        </button>
                      </>
                    ) : null}
                  </div>
                </div>

                {sbomError ? (
                  <div className="rounded-xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-xs text-rose-100">{sbomError}</div>
                ) : null}

                {sbomDocument ? (
                  <div className="space-y-3 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                    <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
                      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                        <p className="uppercase tracking-[0.1em] text-slate-500">Tool</p>
                        <p className="mt-1 font-medium text-slate-200">{sbomDocument.metadata.tool.name} {sbomDocument.metadata.tool.version}</p>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                        <p className="uppercase tracking-[0.1em] text-slate-500">Ecosystem</p>
                        <p className="mt-1 font-medium uppercase text-slate-200">{sbomDocument.metadata.ecosystem}</p>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                        <p className="uppercase tracking-[0.1em] text-slate-500">Components</p>
                        <p className="mt-1 font-medium text-violet-300">{sbomDocument.components.length}</p>
                      </div>
                      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                        <p className="uppercase tracking-[0.1em] text-slate-500">Schema</p>
                        <p className="mt-1 font-mono text-xs text-slate-300">{sbomDocument.schema_version}</p>
                      </div>
                    </div>
                    <div className="overflow-hidden rounded-xl border border-slate-800">
                      <div className="max-h-[55vh] overflow-auto">
                        <table className="w-full text-left text-xs text-slate-200">
                          <thead className="sticky top-0 border-b border-slate-800 bg-slate-900/95 text-slate-400">
                            <tr>
                              <th className="px-4 py-2.5 font-medium">Package</th>
                              <th className="px-4 py-2.5 font-medium">Version</th>
                              <th className="px-4 py-2.5 font-medium">PURL</th>
                              <th className="px-4 py-2.5 font-medium">License</th>
                              <th className="px-4 py-2.5 font-medium">Risk</th>
                              <th className="px-4 py-2.5 font-medium">Direct</th>
                            </tr>
                          </thead>
                          <tbody>
                            {sbomDocument.components.map((component, idx) => {
                              const riskClass = component.risk_status === "malicious"
                                ? "text-rose-300"
                                : component.risk_status === "suspicious"
                                  ? "text-amber-300"
                                  : "text-emerald-400";
                              return (
                                <tr key={`${component.purl}-${idx}`} className="border-t border-slate-800/60 hover:bg-slate-900/30">
                                  <td className="px-4 py-2 font-medium text-slate-100">{component.name}</td>
                                  <td className="px-4 py-2 font-mono text-slate-400">{component.version}</td>
                                  <td className="max-w-[180px] truncate px-4 py-2 font-mono text-[10px] text-slate-500" title={component.purl}>{component.purl}</td>
                                  <td className="px-4 py-2 text-slate-300">{component.licenses.map((l) => l.id).join(", ") || "-"}</td>
                                  <td className={`px-4 py-2 font-semibold uppercase ${riskClass}`}>
                                    {component.risk_status ?? "—"} <span className="font-normal text-slate-500">({((component.risk_score ?? 0) * 100).toFixed(0)}%)</span>
                                  </td>
                                  <td className="px-4 py-2 text-slate-400">{component.is_direct ? "✓" : "—"}</td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                ) : !isSbomLoading ? (
                  <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-950/40 p-8 text-center">
                    <p className="text-sm text-slate-400">Click <span className="text-violet-300">Generate SBOM</span> to create a full package inventory with risk scores and license data.</p>
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}

          {activeSection === "history" ? (
            <div className="h-full overflow-y-auto px-4 pb-6 pt-4">
              <div className="space-y-4">
                <div className="flex flex-wrap items-end justify-between gap-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div className="space-y-1">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-indigo-300">Scan History</p>
                    <p className="text-sm text-slate-300">
                      Showing {scanHistoryJobs.length} of {scanHistoryTotal} scan job{scanHistoryTotal === 1 ? "" : "s"}.
                    </p>
                  </div>
                  <div className="flex flex-wrap items-end gap-3">
                    <label className="space-y-1 text-xs text-slate-400">
                      <span className="block uppercase tracking-[0.12em]">Scan Type</span>
                      <select
                        value={scanHistoryModeFilter}
                        onChange={(event) => setScanHistoryModeFilter(event.target.value as "all" | ScanMode)}
                        className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 outline-none transition focus:border-indigo-400"
                      >
                        <option value="all">All scans</option>
                        <option value="full">Full</option>
                        <option value="static_enrichment">Static + Enrichment</option>
                        <option value="dynamic">Dynamic</option>
                        <option value="static">Static</option>
                        <option value="lightweight">Lightweight</option>
                      </select>
                    </label>
                    <label className="space-y-1 text-xs text-slate-400">
                      <span className="block uppercase tracking-[0.12em]">Status</span>
                      <select
                        value={scanHistoryStatusFilter}
                        onChange={(event) => setScanHistoryStatusFilter(event.target.value as ScanHistoryStatusFilter)}
                        className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 outline-none transition focus:border-indigo-400"
                      >
                        <option value="all">All statuses</option>
                        <option value="cancelled">Cancelled</option>
                        <option value="completed">Completed</option>
                        <option value="failed">Failed</option>
                        <option value="running">Running</option>
                        <option value="pending">Pending</option>
                      </select>
                    </label>
                    <button
                      type="button"
                      onClick={() => { void loadScanHistory(); }}
                      disabled={isScanHistoryLoading}
                      className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-semibold uppercase tracking-[0.12em] text-slate-300 transition hover:border-slate-500 disabled:opacity-50"
                    >
                      {isScanHistoryLoading ? "Loading..." : "Refresh"}
                    </button>
                  </div>
                </div>

                {isScanHistoryLoading && scanHistoryJobs.length === 0 ? (
                  <div className="space-y-2">
                    {[0, 1, 2].map((i) => (
                      <div key={i} className="h-14 animate-pulse rounded-xl border border-slate-800 bg-slate-900/60" />
                    ))}
                  </div>
                ) : scanHistoryJobs.length === 0 ? (
                  <div className="rounded-2xl border border-slate-700 bg-slate-950/70 p-6 text-center">
                    <p className="text-sm text-slate-400">No scan history yet. Start a scan from the Dependency Graph tab.</p>
                  </div>
                ) : (
                  <div
                    ref={historyScrollRef}
                    onScroll={handleHistoryScroll}
                    className="max-h-[62vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-950/70"
                  >
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs text-slate-200">
                        <thead className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                          <tr>
                            <th className="px-4 py-3 font-medium">Date</th>
                            <th className="px-4 py-3 font-medium">Ecosystem</th>
                            <th className="px-4 py-3 font-medium">Mode</th>
                            <th className="px-4 py-3 font-medium">Status</th>
                            <th className="px-4 py-3 font-medium">Packages</th>
                            <th className="px-4 py-3 font-medium">Duration</th>
                            <th className="px-4 py-3 font-medium" />
                          </tr>
                        </thead>
                        <tbody>
                          {scanHistoryJobs.map((job) => {
                            const duration = job.started_at && job.completed_at
                              ? formatDuration((new Date(job.completed_at).getTime() - new Date(job.started_at).getTime()) / 1000)
                              : "-";
                            const modeBadgeClass = job.scan_mode === "full"
                              ? "border-blue-400/50 bg-blue-500/15 text-blue-100"
                              : job.scan_mode === "static_enrichment"
                                ? "border-purple-400/50 bg-purple-500/15 text-purple-100"
                                : job.scan_mode === "dynamic"
                                  ? "border-orange-400/50 bg-orange-500/15 text-orange-100"
                                  : job.scan_mode === "static"
                                    ? "border-indigo-400/50 bg-indigo-500/15 text-indigo-100"
                                    : job.scan_mode === "lightweight"
                                      ? "border-teal-400/50 bg-teal-500/15 text-teal-100"
                                      : "border-slate-500/50 bg-slate-500/15 text-slate-200";
                            const statusBadgeClass = job.status === "completed"
                              ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-100"
                              : job.status === "running" || job.status === "pending"
                                ? "border-cyan-400/50 bg-cyan-500/15 text-cyan-100"
                                : job.status === "failed"
                                  ? "border-rose-400/50 bg-rose-500/15 text-rose-100"
                                  : "border-slate-500/50 bg-slate-500/15 text-slate-300";
                            const isExpanded = selectedHistoryJobId === job.id;

                            return (
                              <React.Fragment key={job.id}>
                                <tr className="border-t border-slate-800 transition hover:bg-slate-900/40">
                                  <td className="px-4 py-3 text-slate-300">{formatTimestampForDisplay(job.created_at)}</td>
                                  <td className="px-4 py-3 uppercase text-slate-400">{job.ecosystem}</td>
                                  <td className="px-4 py-3">
                                    <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${modeBadgeClass}`}>
                                      {getScanModeLabel(job.scan_mode)}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3">
                                    <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${job.status === "running" ? "animate-pulse" : ""} ${statusBadgeClass} ${job.status === "cancelled" ? "line-through" : ""}`}>
                                      {job.status}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3 text-slate-300">{job.total_packages}</td>
                                  <td className="px-4 py-3 text-slate-400">{duration}</td>
                                  <td className="px-4 py-3">
                                    <button
                                      type="button"
                                      onClick={() => {
                                        if (isExpanded) {
                                          setSelectedHistoryJobId(null);
                                          setSelectedHistoryJob(null);
                                        } else {
                                          void loadHistoryJobDetails(job.id);
                                        }
                                      }}
                                      className="rounded-md border border-indigo-400/40 bg-indigo-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-indigo-100 transition hover:bg-indigo-500/20"
                                    >
                                      {isExpanded ? "Close" : "Details"}
                                    </button>
                                  </td>
                                </tr>
                                {isExpanded ? (
                                  <tr key={`${job.id}-details`} className="border-t border-indigo-500/20 bg-indigo-950/10">
                                    <td colSpan={7} className="px-4 py-4">
                                      {isHistoryJobLoading ? (
                                        <p className="text-xs text-slate-400">Loading job details...</p>
                                      ) : selectedHistoryJob ? (
                                        <div className="space-y-3">
                                          <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
                                            <div><p className="text-slate-500 uppercase tracking-[0.1em]">Scanned</p><p className="mt-1 text-slate-200">{selectedHistoryJob.scanned_packages} / {selectedHistoryJob.total_unique_packages}</p></div>
                                            <div><p className="text-slate-500 uppercase tracking-[0.1em]">Started</p><p className="mt-1 text-slate-200">{formatTimestampForDisplay(selectedHistoryJob.started_at)}</p></div>
                                            <div><p className="text-slate-500 uppercase tracking-[0.1em]">Completed</p><p className="mt-1 text-slate-200">{formatTimestampForDisplay(selectedHistoryJob.completed_at)}</p></div>
                                            {selectedHistoryJob.error_message ? <div><p className="text-slate-500 uppercase tracking-[0.1em]">Error</p><p className="mt-1 text-rose-200">{selectedHistoryJob.error_message}</p></div> : null}
                                          </div>
                                          {selectedHistoryJob.results && selectedHistoryJob.results.length > 0 ? (
                                            <div className="max-h-[480px] overflow-auto rounded-lg border border-slate-800">
                                              <table className="w-full text-left text-[11px] text-slate-300">
                                                <thead className="sticky top-0 bg-slate-900/80 text-slate-500">
                                                  <tr>
                                                    <th className="px-3 py-2">Package</th>
                                                    <th className="px-3 py-2">Status</th>
                                                    <th className="px-3 py-2">Score</th>
                                                    <th className="px-3 py-2">CVEs</th>
                                                    <th className="px-3 py-2">Analysis</th>
                                                    <th className="px-3 py-2">Details</th>
                                                  </tr>
                                                </thead>
                                                <tbody>
                                                  {selectedHistoryJob.results.slice(0, 100).map((result) => {
                                                    const cveCount = Math.max(
                                                      result.advisory_references.length,
                                                      result.vulnerability_details?.length ?? 0,
                                                    );
                                                    const hasDetails =
                                                      (result.static_features && Object.keys(result.static_features).length > 0) ||
                                                      (result.vulnerability_details && result.vulnerability_details.length > 0) ||
                                                      (result.reputation_metadata && Object.keys(result.reputation_metadata).length > 0) ||
                                                      !!(result.dynamic_findings && result.analyzed_by?.includes("dynamic"));
                                                    const isExpRow = expandedResultId === result.id;
                                                    return (
                                                      <React.Fragment key={result.id}>
                                                        <tr className="border-t border-slate-800/60">
                                                          <td className="px-3 py-1.5 font-mono">{result.package_name}@{result.package_version}</td>
                                                          <td className={`px-3 py-1.5 font-semibold uppercase text-[10px] ${verdictBadgeClass(result.risk_overall_status)}`}>{formatVerdict(result.risk_overall_status)}</td>
                                                          <td className="px-3 py-1.5">{(result.risk_overall_score * 100).toFixed(0)}%</td>
                                                          <td className="px-3 py-1.5">{cveCount > 0 ? cveCount : "—"}</td>
                                                          <td className="px-3 py-1.5">
                                                            <div className="flex flex-wrap gap-1">
                                                              {(result.analyzed_by ?? []).map((a) => (
                                                                <span key={a} className="rounded border border-slate-600 bg-slate-800/60 px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-slate-300">{a}</span>
                                                              ))}
                                                              {result.lookup_status ? Object.entries(result.lookup_status).map(([src, st]) => (
                                                                <span key={src} className={`rounded border px-1.5 py-0.5 text-[9px] uppercase tracking-wide ${lookupStatusChipClass(st)}`}>
                                                                  {lookupStatusLabel(src, st)}
                                                                </span>
                                                              )) : null}
                                                            </div>
                                                          </td>
                                                          <td className="px-3 py-1.5">
                                                            {hasDetails ? (
                                                              <button
                                                                type="button"
                                                                onClick={() => setExpandedResultId(isExpRow ? null : result.id)}
                                                                className="text-[10px] text-indigo-300 underline hover:text-indigo-100"
                                                              >
                                                                {isExpRow ? "hide" : "view"}
                                                              </button>
                                                            ) : <span className="text-slate-600">—</span>}
                                                          </td>
                                                        </tr>
                                                        {isExpRow ? (
                                                          <tr key={`${result.id}-detail`} className="bg-slate-900/40">
                                                            <td colSpan={6} className="px-3 pb-4 pt-2">
                                                              <div className="space-y-4">
                                                                {result.static_features && Object.keys(result.static_features).length > 0 ? (
                                                                  <div>
                                                                    <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500">Static Features</p>
                                                                    <FeatureGrid features={result.static_features} />
                                                                  </div>
                                                                ) : null}
                                                                {result.vulnerability_details && result.vulnerability_details.length > 0 ? (
                                                                  <div>
                                                                    <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500">CVE Findings ({result.vulnerability_details.length})</p>
                                                                    <table className="w-full text-[10px]">
                                                                      <thead><tr className="text-slate-500"><th className="pb-1 pr-3 text-left">Advisory</th><th className="pb-1 pr-3 text-left">Source</th><th className="pb-1 pr-3 text-left">CVSS</th><th className="pb-1 text-left">Description</th></tr></thead>
                                                                      <tbody>
                                                                        {result.vulnerability_details.map((v, i) => {
                                                                          const href = v.advisory_id.startsWith("CVE-")
                                                                            ? `https://nvd.nist.gov/vuln/detail/${v.advisory_id}`
                                                                            : v.advisory_id.startsWith("GHSA-")
                                                                              ? `https://github.com/advisories/${v.advisory_id}`
                                                                              : null;
                                                                          return (
                                                                            <tr key={i} className="border-t border-slate-800/40">
                                                                              <td className="py-1 pr-3 font-mono text-indigo-300">
                                                                                {href ? <a href={href} target="_blank" rel="noopener noreferrer" className="underline hover:text-indigo-100">{v.advisory_id}</a> : v.advisory_id}
                                                                              </td>
                                                                              <td className="py-1 pr-3 uppercase text-slate-400">{v.source}</td>
                                                                              <td className="py-1 pr-3 text-slate-300">{v.value != null ? v.value.toFixed(1) : "—"}</td>
                                                                              <td className="py-1 text-slate-400 max-w-xs truncate">{v.details ?? "—"}</td>
                                                                            </tr>
                                                                          );
                                                                        })}
                                                                      </tbody>
                                                                    </table>
                                                                  </div>
                                                                ) : null}
                                                                {result.reputation_metadata && Object.keys(result.reputation_metadata).length > 0 ? (
                                                                  <div>
                                                                    <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500">Reputation (Libraries.io)</p>
                                                                    <div className="grid grid-cols-3 gap-2 sm:grid-cols-4">
                                                                      {(["libraries_io_rank", "stars", "forks", "dependents_count", "monthly_downloads", "trust_score"] as const).map((k) => {
                                                                        const val = result.reputation_metadata?.[k];
                                                                        if (val == null) return null;
                                                                        const label = k === "libraries_io_rank" ? "SourceRank" : k === "monthly_downloads" ? "Monthly DL" : k === "dependents_count" ? "Dependents" : k === "trust_score" ? "Trust Score" : k.replace(/_/g, " ");
                                                                        return (
                                                                          <div key={k} className="rounded border border-slate-700/60 bg-slate-900/60 px-2 py-1.5">
                                                                            <p className="text-[9px] uppercase tracking-wide text-slate-500">{label}</p>
                                                                            <p className="mt-0.5 font-mono text-[11px] text-slate-200">{k === "trust_score" ? `${(Number(val) * 100).toFixed(0)}%` : String(val)}</p>
                                                                          </div>
                                                                        );
                                                                      })}
                                                                    </div>
                                                                  </div>
                                                                ) : null}
                                                                {result.dynamic_findings && result.analyzed_by?.includes("dynamic") ? (() => {
                                                                  const dyn = result.dynamic_findings as DynamicFinding;
                                                                  if (!dyn.status || dyn.status === "skipped") return null;
                                                                  return (
                                                                    <div>
                                                                      <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500">Dynamic Analysis</p>
                                                                      {/* Summary row */}
                                                                      <div className="mb-2 flex flex-wrap items-center gap-2">
                                                                        {dyn.status ? (
                                                                          <span className={`inline-flex rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] ${dyn.status === "completed" ? "border-emerald-400/30 bg-emerald-500/15 text-emerald-200" : dyn.status === "partial" ? "border-amber-400/30 bg-amber-500/15 text-amber-200" : "border-rose-400/30 bg-rose-500/15 text-rose-200"}`}>
                                                                            {dyn.status}
                                                                          </span>
                                                                        ) : null}
                                                                        {dyn.coverage ? (
                                                                          <span className={`inline-flex rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] ${dyn.coverage === "full" ? "border-teal-400/30 bg-teal-500/15 text-teal-200" : "border-slate-600 bg-slate-800 text-slate-400"}`}>
                                                                            Coverage: {dyn.coverage}
                                                                          </span>
                                                                        ) : null}
                                                                        {dyn.ioc_hit !== undefined ? (
                                                                          <span className={`inline-flex rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${dyn.ioc_hit ? "border-rose-400/50 bg-rose-500/15 text-rose-200" : "border-slate-700 bg-slate-800/60 text-slate-400"}`}>
                                                                            IOC: {dyn.ioc_hit ? "HIT" : "clean"}
                                                                          </span>
                                                                        ) : null}
                                                                        {dyn.vm_evasion_observed ? (
                                                                          <span className="inline-flex rounded border border-amber-400/50 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-amber-300">VM Evasion</span>
                                                                        ) : null}
                                                                        {dyn.sandbox_timed_out ? (
                                                                          <span className="inline-flex rounded border border-slate-600 bg-slate-800/60 px-2 py-0.5 text-[10px] uppercase text-slate-400">Timed out</span>
                                                                        ) : null}
                                                                        {dyn.risk_score != null ? (
                                                                          <span className="text-[10px] text-slate-400">Dynamic Risk: <span className="font-mono text-slate-200">{(dyn.risk_score * 100).toFixed(1)}%</span></span>
                                                                        ) : null}
                                                                        {dyn.sandbox_provider ? (
                                                                          <span className="text-[10px] text-slate-500">Sandbox: <span className="text-slate-400">{dyn.sandbox_provider}</span></span>
                                                                        ) : null}
                                                                      </div>
                                                                      {/* IOC detail */}
                                                                      {dyn.ioc_detail ? (
                                                                        <div className="mb-2 rounded border border-slate-700/60 bg-slate-950/40 p-2">
                                                                          <p className="mb-1.5 text-[9px] uppercase tracking-wide text-slate-500">IOC Detail</p>
                                                                          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px]">
                                                                            {dyn.ioc_detail.verdict ? <span className="text-slate-300">Verdict: <span className="font-semibold uppercase text-slate-200">{dyn.ioc_detail.verdict}</span></span> : null}
                                                                            {dyn.ioc_detail.raw_line_count != null ? <span className="text-slate-300">Log lines: <span className="font-mono text-slate-200">{dyn.ioc_detail.raw_line_count}</span></span> : null}
                                                                          </div>
                                                                          {(["network_iocs", "process_iocs", "file_iocs", "dns_iocs", "crypto_iocs"] as const).map((field) => {
                                                                            const items = dyn.ioc_detail?.[field];
                                                                            if (!Array.isArray(items) || items.length === 0) return null;
                                                                            return (
                                                                              <div key={field} className="mt-1.5">
                                                                                <p className="text-[9px] uppercase tracking-wide text-slate-500">{field.replace("_iocs", "").replace("_", " ")} IOCs ({items.length})</p>
                                                                                <div className="mt-0.5 flex flex-wrap gap-1">
                                                                                  {items.slice(0, 8).map((item, i) => <span key={i} className="rounded border border-slate-700 bg-slate-900/80 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">{item}</span>)}
                                                                                  {items.length > 8 ? <span className="text-[9px] text-slate-500">+{items.length - 8} more</span> : null}
                                                                                </div>
                                                                              </div>
                                                                            );
                                                                          })}
                                                                          {dyn.ioc_detail.flagged_lines && dyn.ioc_detail.flagged_lines.length > 0 ? (
                                                                            <div className="mt-1.5">
                                                                              <p className="text-[9px] uppercase tracking-wide text-slate-500">Flagged Lines ({dyn.ioc_detail.flagged_lines.length})</p>
                                                                              <div className="mt-0.5 space-y-0.5">
                                                                                {dyn.ioc_detail.flagged_lines.slice(0, 5).map((line, i) => <p key={i} className="rounded bg-slate-950/60 px-2 py-0.5 font-mono text-[9px] text-slate-400">{line}</p>)}
                                                                                {dyn.ioc_detail.flagged_lines.length > 5 ? <p className="text-[9px] text-slate-500">+{dyn.ioc_detail.flagged_lines.length - 5} more lines</p> : null}
                                                                              </div>
                                                                            </div>
                                                                          ) : null}
                                                                        </div>
                                                                      ) : null}
                                                                      {/* Syscall trace */}
                                                                      {dyn.syscall_trace ? (
                                                                        <div className="mb-2 rounded border border-slate-700/60 bg-slate-950/40 p-2">
                                                                          <p className="mb-1 text-[9px] uppercase tracking-wide text-slate-500">Syscall Trace</p>
                                                                          <p className="text-[10px] text-slate-300"><span className="font-mono text-slate-200">{dyn.syscall_trace.suspicious_count ?? 0}</span> suspicious calls</p>
                                                                          {dyn.syscall_trace.categories && dyn.syscall_trace.categories.length > 0 ? (
                                                                            <div className="mt-1 flex flex-wrap gap-1">
                                                                              {dyn.syscall_trace.categories.map((c, i) => <span key={i} className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 text-[9px] text-slate-300">{c}</span>)}
                                                                            </div>
                                                                          ) : null}
                                                                        </div>
                                                                      ) : null}
                                                                      {/* Network activity */}
                                                                      {dyn.network_activity ? (
                                                                        <div className="mb-2 rounded border border-slate-700/60 bg-slate-950/40 p-2">
                                                                          <p className="mb-1 text-[9px] uppercase tracking-wide text-slate-500">Network Activity</p>
                                                                          <p className="text-[10px] text-slate-300"><span className="font-mono text-slate-200">{dyn.network_activity.outbound_connections ?? 0}</span> outbound connection{(dyn.network_activity.outbound_connections ?? 0) !== 1 ? "s" : ""}</p>
                                                                          {dyn.network_activity.destinations && dyn.network_activity.destinations.length > 0 ? (
                                                                            <div className="mt-1 flex flex-wrap gap-1">
                                                                              {dyn.network_activity.destinations.map((d, i) => <span key={i} className="rounded border border-slate-700 bg-slate-950/60 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">{d}</span>)}
                                                                            </div>
                                                                          ) : null}
                                                                        </div>
                                                                      ) : null}
                                                                      {/* Filesystem changes */}
                                                                      {dyn.filesystem_changes ? (
                                                                        <div className="rounded border border-slate-700/60 bg-slate-950/40 p-2">
                                                                          <p className="mb-1 text-[9px] uppercase tracking-wide text-slate-500">Filesystem Changes</p>
                                                                          <p className={`text-[10px] ${(dyn.filesystem_changes.sensitive_path_writes ?? 0) > 0 ? "text-rose-300" : "text-slate-300"}`}>
                                                                            <span className="font-mono">{dyn.filesystem_changes.sensitive_path_writes ?? 0}</span> sensitive path write{(dyn.filesystem_changes.sensitive_path_writes ?? 0) !== 1 ? "s" : ""}
                                                                          </p>
                                                                          {dyn.filesystem_changes.paths && dyn.filesystem_changes.paths.length > 0 ? (
                                                                            <div className="mt-1 flex flex-wrap gap-1">
                                                                              {dyn.filesystem_changes.paths.map((p, i) => <span key={i} className="rounded border border-slate-700 bg-slate-950/60 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">{p}</span>)}
                                                                            </div>
                                                                          ) : null}
                                                                        </div>
                                                                      ) : null}
                                                                    </div>
                                                                  );
                                                                })() : null}
                                                              </div>
                                                            </td>
                                                          </tr>
                                                        ) : null}
                                                      </React.Fragment>
                                                    );
                                                  })}
                                                </tbody>
                                              </table>
                                            </div>
                                          ) : null}
                                        </div>
                                      ) : null}
                                    </td>
                                  </tr>
                                ) : null}
                              </React.Fragment>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : null}

          {activeSection === "lightweight" ? (
            <div className="flex h-full flex-col overflow-hidden px-4 pb-6 pt-4">
              {/* Header */}
              <div className="mb-4 flex-shrink-0">
                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Lightweight Scan</p>
                <p className="mt-1 text-sm text-slate-400">
                  Queries CVE databases (OSV + NVD) and Libraries.io for known vulnerabilities and package reputation.
                  No ML model — best for quickly checking known packages against published advisories.
                </p>
              </div>

              <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
              {/* Left pane — configuration */}
              <div className="space-y-4 overflow-y-auto">

                {/* Scope selector */}
                <div className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-4">
                  <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">Scan Scope</p>
                  <div className="flex gap-3">
                    {(["partial", "full"] as const).map((scope) => (
                      <button
                        key={scope}
                        type="button"
                        disabled={false}
                        onClick={() => setLightweightScope(scope)}
                        className={`rounded-full border px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] transition ${
                          lightweightScope === scope
                            ? "border-cyan-300/70 bg-cyan-500/20 text-cyan-50"
                            : "border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-500"
                        } disabled:cursor-not-allowed disabled:opacity-50`}
                      >
                        {scope === "partial" ? "Partial — recommended" : `Full — all ${availablePackagesForAnalysis.length} packages`}
                      </button>
                    ))}
                  </div>
                  {lightweightScope === "partial" ? (
                    <div className="mt-3 space-y-2">
                      <p className="text-[11px] text-slate-500">
                        Tip: start with packages you explicitly declared in your manifest — skip deep transitive deps for now.
                      </p>
                      <input
                        type="text"
                        placeholder="Search packages..."
                        value={lightweightPackageSearch}
                        onChange={(e) => setLightweightPackageSearch(e.target.value)}
                        className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
                      />
                      {lightweightSelectedPackages.length > 0 ? (
                        <div className="flex flex-wrap gap-2 rounded-md bg-slate-950/40 p-2">
                          {lightweightSelectedPackages.map((pkg) => (
                            <div
                              key={pkg}
                              className="inline-flex items-center gap-1.5 rounded-full border border-cyan-400/50 bg-cyan-500/20 px-2.5 py-1 text-xs text-cyan-100"
                            >
                              <span className="truncate font-medium">{pkg}</span>
                              <button
                                type="button"
                                onClick={() => setLightweightSelectedPackages((prev) => prev.filter((p) => p !== pkg))}
                                className="ml-0.5 flex h-4 w-4 items-center justify-center rounded-full transition hover:bg-cyan-400/30"
                                title="Remove package"
                              >
                                ✕
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : null}
                      <div className="max-h-60 overflow-auto rounded-md border border-slate-800 bg-slate-950/60 p-2">
                        {(() => {
                          const filtered = availablePackagesForAnalysis.filter(
                            (pkg) => !lightweightPackageSearch || pkg.toLowerCase().includes(lightweightPackageSearch.toLowerCase()),
                          );
                          if (filtered.length === 0) {
                            return <p className="p-2 text-xs text-slate-400">{availablePackagesForAnalysis.length === 0 ? "No packages loaded yet." : "No packages match your search."}</p>;
                          }
                          return (
                            <div className="space-y-1">
                              {filtered.map((pkg) => {
                                const isSelected = lightweightSelectedPackages.includes(pkg);
                                return (
                                  <button
                                    key={pkg}
                                    type="button"
                                    onClick={() =>
                                      setLightweightSelectedPackages((prev) =>
                                        isSelected ? prev.filter((p) => p !== pkg) : [...prev, pkg],
                                      )
                                    }
                                    className={`w-full rounded-md border px-3 py-2 text-left text-xs transition ${
                                      isSelected
                                        ? "border-cyan-400/60 bg-cyan-500/20 font-medium text-cyan-100"
                                        : "border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-600 hover:bg-slate-900/50"
                                    }`}
                                  >
                                    <div className="flex items-center justify-between">
                                      <span className="truncate">{pkg}</span>
                                      {isSelected ? <span className="ml-2 text-cyan-400">✓</span> : null}
                                    </div>
                                  </button>
                                );
                              })}
                            </div>
                          );
                        })()}
                      </div>
                    </div>
                  ) : null}
                  {lightweightSources.librariesio ? (
                    <div className="mt-3 rounded-lg border border-slate-700/40 bg-slate-900/60 px-3 py-2">
                      <p className="text-[11px] text-slate-400">
                        Libraries.io is rate-limited to <strong className="text-amber-300">60 packages/min</strong>.
                        {(() => {
                          const count = lightweightScope === "full" ? availablePackagesForAnalysis.length : lightweightSelectedPackages.length;
                          return count > 0 ? (
                            <span> Scanning <strong className="text-slate-200">{count}</strong> package{count === 1 ? "" : "s"}{count > 60 ? <span> will take ~<strong className="text-amber-300">{Math.ceil(count / 60)} min</strong></span> : null} for Libraries.io data.</span>
                          ) : null;
                        })()}
                        {" "}CVE lookups are fetched live from OSV and NVD.
                      </p>
                    </div>
                  ) : null}
                </div>

                {/* Data sources */}
                <div className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-4">
                  <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">Data Sources</p>
                  <div className="flex flex-wrap gap-5">
                    {(["cve", "librariesio"] as const).map((src) => {
                      const label = src === "cve" ? "CVE" : "Libraries.io";
                      const tooltip = src === "cve"
                        ? "Queries OSV and NVD databases for known CVEs affecting each package. Results are cached — fast regardless of package count."
                        : "Queries Libraries.io for SourceRank, stars, forks, and dependents. Rate-limited to 60 packages/min — large scopes may take several minutes.";
                      const checked = lightweightSources[src];
                      return (
                        <label
                          key={src}
                          title={tooltip}
                          className="flex cursor-pointer items-center gap-2 text-[12px] font-medium text-slate-200 select-none"
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={false}
                            onChange={() => setLightweightSources((prev) => ({ ...prev, [src]: !prev[src] }))}
                            className="accent-cyan-400 h-3.5 w-3.5"
                          />
                          {label}
                          <span className="text-[10px] text-slate-500">{src === "cve" ? "OSV + NVD" : "SourceRank"}</span>
                        </label>
                      );
                    })}
                  </div>
                  {!lightweightSources.cve && !lightweightSources.librariesio ? (
                    <p className="mt-2 text-[11px] text-amber-300">Select at least one data source.</p>
                  ) : null}
                </div>

                {/* Start button */}
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    disabled={
                      (!lightweightSources.cve && !lightweightSources.librariesio) ||
                      (lightweightScope === "partial" && lightweightSelectedPackages.length === 0)
                    }
                    onClick={() => { void triggerLightweightScan(); }}
                    className="inline-flex items-center rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200 transition hover:border-cyan-300 hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Start Lightweight Scan
                  </button>
                </div>
                {/* Active lightweight jobs */}
                {Array.from(activeScanJobs.values()).filter(j => j.sourceTab === "lightweight").length > 0 ? (
                  <div className="mt-1 space-y-1">
                    {Array.from(activeScanJobs.values()).filter(j => j.sourceTab === "lightweight").map(job => (
                      <div
                        key={job.jobId}
                        onClick={() => setSelectedLightweightJobId(job.jobId)}
                        className={`flex items-center justify-between gap-2 rounded-lg border px-2 py-1.5 cursor-pointer transition ${selectedLightweightJobId === job.jobId ? "border-cyan-500/50 bg-cyan-500/10" : "border-slate-700/60 bg-slate-900/60 hover:bg-slate-800/60"}`}
                      >
                        <div className="flex items-center gap-2">
                          {(job.status === "pending" || job.status === "running") ? (
                            <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />
                          ) : (
                            <span className={`h-2 w-2 rounded-full ${
                              SCAN_TERMINAL_DONE.has(job.status) ? "bg-emerald-400"
                              : SCAN_TERMINAL_FAILED.has(job.status) ? "bg-rose-400"
                              : "bg-slate-500"
                            }`} />
                          )}
                          <span className="text-[10px] uppercase tracking-[0.1em] text-slate-300">
                            {job.progress > 0 ? `${job.progress.toFixed(0)}%` : job.status}
                          </span>
                          {(job.details as {total_unique_packages?: number} | null)?.total_unique_packages ? (
                            <span className="text-[10px] text-slate-500">
                              {(job.details as {scanned_packages?: number} | null)?.scanned_packages ?? 0} / {(job.details as {total_unique_packages?: number} | null)?.total_unique_packages}
                            </span>
                          ) : null}
                          {job.elapsedSeconds > 0 ? (
                            <span className="text-[10px] text-slate-600">{formatDuration(job.elapsedSeconds)}</span>
                          ) : null}
                        </div>
                        {(job.status === "pending" || job.status === "running") ? (
                          <button
                            type="button"
                            onClick={() => { void cancelScanJob(job.jobId); }}
                            disabled={isCancellingScan}
                            className="text-[9px] uppercase tracking-wide text-rose-300 hover:text-rose-100"
                          >
                            Stop
                          </button>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : null}

              </div>
              {/* Right pane — selected-job progress + results */}
              <div className="flex flex-col gap-4 overflow-y-auto">
                {!selectedLightweightJobId ? (
                  <div className="rounded-xl border border-slate-700/60 bg-slate-900/40 p-6 text-center">
                    <p className="text-sm text-slate-400">
                      {Array.from(activeScanJobs.values()).some(j => j.sourceTab === "lightweight")
                        ? "Select a scan from the list to view results."
                        : "Start a lightweight scan to see results here."}
                    </p>
                  </div>
                ) : (() => {
                  const job = activeScanJobs.get(selectedLightweightJobId);
                  if (!job) return null;
                  const lwDetails = job.details as (typeof job.details & { results?: ScanResultResponse[] }) | null;
                  const lwResults = lightweightTabResults;
                  const isRunning = job.status === "pending" || job.status === "running";
                  const isFailed = job.status === "failed";
                  const isCompleted = job.status === "completed";
                  return (
                    <div className="space-y-3">
                      {/* Status block */}
                      <div className={`rounded-xl border p-4 ${
                        isFailed ? "border-rose-400/40 bg-rose-500/10"
                        : isCompleted ? "border-emerald-400/40 bg-emerald-500/10"
                        : "border-slate-700/60 bg-slate-900/60"
                      }`}>
                        <div className="flex items-center justify-between gap-4">
                          <p className={`text-[11px] font-semibold uppercase tracking-[0.14em] ${
                            isFailed ? "text-rose-300"
                            : isCompleted ? "text-emerald-300"
                            : "text-cyan-300"
                          }`}>
                            {isFailed ? "Scan failed"
                              : isCompleted ? `Completed — ${lwResults?.length ?? 0} package${(lwResults?.length ?? 0) === 1 ? "" : "s"}`
                              : job.status === "running" ? "Scanning…"
                              : "Starting…"}
                          </p>
                          {isRunning && (lwDetails?.total_unique_packages ?? 0) > 0 ? (
                            <span className="text-[11px] text-slate-400">
                              {lwDetails?.scanned_packages ?? 0} / {lwDetails?.total_unique_packages} ({job.progress.toFixed(0)}%)
                            </span>
                          ) : isRunning ? (
                            <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-cyan-400/40 border-t-cyan-400" />
                          ) : null}
                        </div>
                        {(lwDetails?.total_unique_packages ?? 0) > 0 ? (
                          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-800">
                            <div
                              className={`h-full rounded-full transition-all duration-500 ${isCompleted ? "bg-emerald-500" : "bg-cyan-500"}`}
                              style={{ width: `${job.progress}%` }}
                            />
                          </div>
                        ) : null}
                        {isFailed && lwDetails?.error_message ? (
                          <p className="mt-1 text-[11px] text-rose-300">{lwDetails.error_message}</p>
                        ) : null}
                        {job.elapsedSeconds > 0 ? (
                          <p className="mt-1 text-[10px] text-slate-500">Elapsed {formatDuration(job.elapsedSeconds)}</p>
                        ) : null}
                      </div>

                      {/* Results panel */}
                      <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">Scan Results</p>
                          <span className="rounded-full border border-cyan-400/30 bg-cyan-500/10 px-2.5 py-0.5 text-[10px] font-medium text-cyan-300">
                            {job.status}
                          </span>
                        </div>
                        {isCompleted && lwResults && lwResults.length > 0 ? (
                          <div className="space-y-2">
                            {lwResults.map((result) => {
                              const cveCount = Math.max(
                                result.advisory_references.length,
                                result.vulnerability_details?.length ?? 0,
                              );
                              const cveStatus = result.lookup_status?.cve;
                              const libStatus = result.lookup_status?.librariesio;
                              const isExpRow = lightweightExpandedId === result.id;
                              const isErrorRow = !!result.error_message;
                              const riskBadgeClass = result.risk_overall_status === "malicious"
                                ? "border-rose-400/50 bg-rose-500/15 text-rose-200"
                                : result.risk_overall_status === "suspicious"
                                  ? "border-amber-400/50 bg-amber-500/15 text-amber-200"
                                  : result.risk_overall_status === "clean"
                                    ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-200"
                                    : "border-slate-600 bg-slate-800/60 text-slate-400";
                              return (
                                <div
                                  key={result.id}
                                  className={`rounded-lg border text-sm ${isErrorRow ? "border-rose-400/30 bg-rose-500/10 text-rose-100" : "border-slate-700 bg-slate-950/60 text-slate-200"}`}
                                >
                                  <button
                                    type="button"
                                    onClick={() => setLightweightExpandedId(isExpRow ? null : result.id)}
                                    className="w-full p-3 text-left"
                                  >
                                    <div className="flex flex-wrap items-center justify-between gap-2">
                                      <p className="font-medium">
                                        {result.package_name} <span className="text-slate-400">@</span> {result.package_version}
                                      </p>
                                      <div className="flex items-center gap-2">
                                        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${riskBadgeClass}`}>
                                          {formatVerdict(result.risk_overall_status)}
                                        </span>
                                        <span className="text-[11px] text-slate-500">{isExpRow ? "▲" : "▼"}</span>
                                      </div>
                                    </div>
                                    <div className="mt-1 flex flex-wrap gap-4 text-xs text-slate-400">
                                      <span>Risk: {(result.risk_overall_score * 100).toFixed(1)}%</span>
                                      {cveCount > 0 ? <span>CVEs: {cveCount}</span> : null}
                                      {cveStatus ? (
                                        <span>CVE src: <span className={`rounded border px-1 py-0.5 text-[9px] uppercase tracking-wide ${lookupStatusChipClass(cveStatus)}`}>{lookupStatusLabel("cve", cveStatus)}</span></span>
                                      ) : null}
                                      {libStatus ? (
                                        <span>Libraries.io: <span className={`rounded border px-1 py-0.5 text-[9px] uppercase tracking-wide ${lookupStatusChipClass(libStatus)}`}>{lookupStatusLabel("librariesio", libStatus)}</span></span>
                                      ) : null}
                                    </div>
                                    {result.advisory_references.length > 0 ? (
                                      <div className="mt-2 flex flex-wrap gap-1.5">
                                        {result.advisory_references.map((ref) => {
                                          const isCve = ref.toUpperCase().startsWith("CVE-");
                                          const isGhsa = ref.toUpperCase().startsWith("GHSA-");
                                          const href = isCve
                                            ? `https://nvd.nist.gov/vuln/detail/${ref}`
                                            : isGhsa ? `https://github.com/advisories/${ref}` : null;
                                          return href ? (
                                            <a
                                              key={ref}
                                              href={href}
                                              target="_blank"
                                              rel="noopener noreferrer"
                                              onClick={(e) => e.stopPropagation()}
                                              className="rounded border border-amber-400/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-200 hover:bg-amber-500/20 transition"
                                            >
                                              {ref}
                                            </a>
                                          ) : (
                                            <span key={ref} className="rounded border border-slate-700 bg-slate-800/60 px-1.5 py-0.5 text-[10px] text-slate-400">{ref}</span>
                                          );
                                        })}
                                      </div>
                                    ) : null}
                                    {result.error_message ? <p className="mt-1 text-xs text-rose-200">{result.error_message}</p> : null}
                                  </button>
                                  {isExpRow ? (
                                    <div className="border-t border-slate-700/60 px-3 pb-3 pt-2 space-y-3">
                                      <div className="flex flex-wrap gap-3 text-xs">
                                        <div>
                                          <p className="text-[10px] uppercase tracking-wide text-slate-500">Risk Status</p>
                                          <p className="mt-0.5 font-medium uppercase text-slate-200">{result.risk_overall_status ?? "—"}</p>
                                        </div>
                                        <div>
                                          <p className="text-[10px] uppercase tracking-wide text-slate-500">Risk Score</p>
                                          <p className="mt-0.5 font-mono font-medium text-slate-200">{(result.risk_overall_score * 100).toFixed(2)}%</p>
                                        </div>
                                        {result.scan_timestamp ? (
                                          <div>
                                            <p className="text-[10px] uppercase tracking-wide text-slate-500">Scanned At</p>
                                            <p className="mt-0.5 text-slate-300">{formatTimestampForDisplay(result.scan_timestamp)}</p>
                                          </div>
                                        ) : null}
                                      </div>
                                      {result.vulnerability_details && result.vulnerability_details.length > 0 ? (
                                        <div>
                                          <p className="mb-1.5 text-[10px] uppercase tracking-wide text-slate-500">CVE Findings ({result.vulnerability_details.length})</p>
                                          <table className="w-full text-[10px]">
                                            <thead>
                                              <tr className="text-slate-500">
                                                <th className="pb-1 pr-3 text-left font-medium">Advisory</th>
                                                <th className="pb-1 pr-3 text-left font-medium">Source</th>
                                                <th className="pb-1 pr-3 text-left font-medium">CVSS</th>
                                                <th className="pb-1 text-left font-medium">Description</th>
                                              </tr>
                                            </thead>
                                            <tbody>
                                              {result.vulnerability_details.map((v, i) => {
                                                const href = v.advisory_id.startsWith("CVE-")
                                                  ? `https://nvd.nist.gov/vuln/detail/${v.advisory_id}`
                                                  : v.advisory_id.startsWith("GHSA-")
                                                    ? `https://github.com/advisories/${v.advisory_id}`
                                                    : null;
                                                return (
                                                  <tr key={i} className="border-t border-slate-800/40">
                                                    <td className="py-1 pr-3 font-mono text-indigo-300">
                                                      {href ? <a href={href} target="_blank" rel="noopener noreferrer" className="underline hover:text-indigo-100">{v.advisory_id}</a> : v.advisory_id}
                                                    </td>
                                                    <td className="py-1 pr-3 uppercase text-slate-400">{v.source}</td>
                                                    <td className="py-1 pr-3 text-slate-300">{v.value != null ? v.value.toFixed(1) : "—"}</td>
                                                    <td className="py-1 text-slate-400 max-w-xs truncate">{v.details ?? "—"}</td>
                                                  </tr>
                                                );
                                              })}
                                            </tbody>
                                          </table>
                                        </div>
                                      ) : null}
                                      {result.reputation_metadata && Object.keys(result.reputation_metadata).length > 0 ? (
                                        <div>
                                          <p className="mb-1.5 text-[10px] uppercase tracking-wide text-slate-500">Reputation (Libraries.io)</p>
                                          <div className="grid grid-cols-3 gap-2 sm:grid-cols-4">
                                            {(["libraries_io_rank", "stars", "forks", "dependents_count", "monthly_downloads", "trust_score", "package_age_days", "maintainer_count"] as const).map((k) => {
                                              const val = result.reputation_metadata?.[k];
                                              if (val == null) return null;
                                              const label = k === "libraries_io_rank" ? "SourceRank" : k === "monthly_downloads" ? "Monthly DL" : k === "dependents_count" ? "Dependents" : k === "trust_score" ? "Trust Score" : k === "package_age_days" ? "Age (days)" : k === "maintainer_count" ? "Maintainers" : k.replace(/_/g, " ");
                                              return (
                                                <div key={k} className="rounded border border-slate-700/60 bg-slate-900/60 px-2 py-1.5">
                                                  <p className="text-[9px] uppercase tracking-wide text-slate-500">{label}</p>
                                                  <p className="mt-0.5 font-mono text-[11px] text-slate-200">{k === "trust_score" ? `${(Number(val) * 100).toFixed(0)}%` : String(val)}</p>
                                                </div>
                                              );
                                            })}
                                          </div>
                                        </div>
                                      ) : null}
                                    </div>
                                  ) : null}
                                </div>
                              );
                            })}
                          </div>
                        ) : isCompleted ? (
                          <p className="text-sm text-slate-400">No results returned for this scan.</p>
                        ) : null}
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          </div>
          ) : null}

          {activeSection === "add" ? (
            <div className="h-full overflow-y-auto px-4 pb-6 pt-4">
              <AddDependencyPanel
                apiBaseUrl={API_BASE_URL}
                initialEcosystem={addDependencyEcosystems[0] ?? repositoryEcosystem ?? "npm"}
                allowedEcosystems={addDependencyEcosystems}
                resolveRepoCoordinates={resolveRepoCoordinates}
              />
            </div>
          ) : null}
          </main>
        </div>
      </div>

      <div className="pointer-events-none absolute inset-y-0 right-0 z-40 overflow-visible">
        {!isAgentChatOpen ? (
          <button
            type="button"
            onClick={() => setIsAgentChatOpen(true)}
            className="pointer-events-auto absolute right-4 top-6 z-50 grid h-14 w-14 place-items-center rounded-full border border-cyan-300/70 bg-gradient-to-br from-slate-950/95 via-slate-900/95 to-cyan-950/75 text-cyan-100 shadow-[0_16px_42px_-18px_rgba(8,145,178,0.95)] ring-1 ring-cyan-400/25 backdrop-blur transition duration-200 hover:scale-105 hover:from-slate-900 hover:to-cyan-900/70"
            aria-label="Show AI chat"
            title="Show AI chat"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true" className="h-6 w-6" fill="none">
              <rect x="5" y="7" width="14" height="12" rx="4" stroke="currentColor" strokeWidth="1.6" />
              <path d="M9 7V5.5C9 4.12 10.12 3 11.5 3h1C13.88 3 15 4.12 15 5.5V7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
              <path d="M9 12h.01M15 12h.01" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
              <path d="M8 15.2c1.2 1 2.6 1.5 4 1.5s2.8-.5 4-1.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        ) : null}

        <aside
          className={`pointer-events-auto absolute inset-y-0 right-0 flex h-full flex-col border-l-4 border-cyan-400/20 bg-gray-950/90 shadow-[0_28px_72px_-34px_rgba(2,6,23,0.95)] transition-transform duration-300 ${
            isAgentChatOpen ? "translate-x-0" : "translate-x-full"
          }`}
          style={{ width: agentChatWidth }}
        >
          <div
            className="absolute inset-y-0 left-0 z-10 w-1.5 cursor-col-resize transition-colors hover:bg-cyan-400/30 active:bg-cyan-400/50"
            onMouseDown={handleSidebarResizeMouseDown}
          />
          <div className="flex items-start justify-between gap-3 border-b border-gray-800 p-4">
            <div>
              <p className="text-sm font-semibold text-slate-100">SentinelFlow Agent</p>
              <p className="mt-1 text-xs text-slate-400">Repository assistant</p>
            </div>
            <button
              type="button"
              onClick={() => setIsAgentChatOpen(false)}
              className="grid h-9 w-9 place-items-center rounded-full border border-cyan-400/40 bg-cyan-500/15 text-cyan-100 transition hover:bg-cyan-500/25"
              aria-label="Close AI chat"
              title="Close AI chat"
            >
              <span className="text-sm font-semibold leading-none">✕</span>
            </button>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto p-4">
            <div className="rounded-xl border border-cyan-400/25 bg-cyan-500/10 p-3 text-sm text-cyan-100">
              Ask me about dependencies, risk signals, or what to patch first.
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm text-slate-300">
              Tip: &quot;Highlight outdated transitive packages with known CVEs.&quot;
            </div>
          </div>

          <div className="border-t border-gray-800 p-4">
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Message SentinelFlow Agent..."
                className="w-full rounded-lg border border-slate-700 bg-slate-900/90 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
              />
              <button
                type="button"
                className="rounded-lg border border-cyan-400/60 bg-cyan-500/20 px-3 py-2 text-sm font-medium text-cyan-100 transition hover:bg-cyan-500/30"
              >
                Send
              </button>
            </div>
          </div>
        </aside>
      </div>

    </section>
  );
}
