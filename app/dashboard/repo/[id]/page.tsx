"use client";

import React, { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AddDependencyPanel } from "@/app/components/add-dependency-panel";
import { DependencyTree } from "@/app/components/dependency-tree";
import { DependencyNode, Ecosystem } from "@/app/types/dashboard";
import { clientSessionStorage } from "@/app/lib/auth/client-session";
import { createCacheKey, getCachedValue, hashString, setCachedValue } from "@/app/lib/browser-cache";
import { triggerScan, pollScanJob as apiPollScanJob, cancelScan as apiCancelScan, getLatestScan, getLatestScanResults, getScanHistory, generateSbom, generateCycloneDxSbom, downloadSbom, ScanJobResponse, ScanHistoryItem, SbomDocument, ScanApiContext } from "@/app/lib/api/scan-api";
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
  scan_timestamp?: string | null;
  scanner_version?: string | null;
};

type ScanResultRow = {
  id: string;
  packageName: string;
  version: string;
  status: string;
  malwareStatus: string;
  malwareScore: number | null;
  errorMessage: string | null;
  scanTimestamp: string | null;
};

type LatestScanSummary = {
  status: string | null;
  processed: number | null;
  total: number | null;
  completedAt: string | null;
};

type ScanScope = "full" | "partial";

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

function buildResultDedupKey(row: ScanResultRow): string {
  return `${row.packageName}|${row.version}|${row.scanTimestamp ?? "-"}|${row.status}|${row.errorMessage ?? "-"}`;
}

function normalizeResultMapFromRows(rows: ScanResultRow[]): Record<string, ScanResultMapEntry> {
  return rows.reduce<Record<string, ScanResultMapEntry>>((accumulator, row) => {
    const key = `${row.packageName}@${row.version}`;
    accumulator[key] = {
      malware_status: row.malwareStatus,
      malware_score: row.malwareScore,
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
  const errorMessage =
    coerceString(record.error_message) ?? coerceString(record.error) ?? coerceString(record.failure_reason);
  const scanTimestamp = coerceString(record.scan_timestamp);

  return {
    id: coerceString(record.id) ?? `${packageName}@${version}:${index}`,
    packageName,
    version,
    status,
    malwareStatus,
    malwareScore,
    errorMessage,
    scanTimestamp,
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
          errorMessage: null,
          scanTimestamp: coerceString(entryRecord.scan_timestamp),
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
  const [isScanRunning, setIsScanRunning] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState("Waiting to start malware scan.");
  const [scanDetails, setScanDetails] = useState<InternalScanJobResponse | null>(null);
  const [activeSection, setActiveSection] = useState("graph");
  const [graphScanView, setGraphScanView] = useState<"progress" | "results">("progress");
  const [isHydrated, setIsHydrated] = useState(false);
  const [scanScope, setScanScope] = useState<ScanScope>("full");
  const [selectedScanPackages, setSelectedScanPackages] = useState<string[]>([]);
  const [isAgentChatOpen, setIsAgentChatOpen] = useState(true);
  const [isCancellingScan, setIsCancellingScan] = useState(false);
  const [liveElapsedSeconds, setLiveElapsedSeconds] = useState(0);
  const [analysisPackageSearch, setAnalysisPackageSearch] = useState("");
  const [selectedAnalysisPackages, setSelectedAnalysisPackages] = useState<string[]>([]);
  const [detailsPackageSearch, setDetailsPackageSearch] = useState("");
  const [selectedDetailsPackage, setSelectedDetailsPackage] = useState<string | null>(null);
  // Scan history
  const [scanHistoryJobs, setScanHistoryJobs] = useState<ScanHistoryItem[]>([]);
  const [isScanHistoryLoading, setIsScanHistoryLoading] = useState(false);
  const [scanHistoryTotal, setScanHistoryTotal] = useState(0);
  const [selectedHistoryJobId, setSelectedHistoryJobId] = useState<string | null>(null);
  const [selectedHistoryJob, setSelectedHistoryJob] = useState<ScanJobResponse | null>(null);
  const [isHistoryJobLoading, setIsHistoryJobLoading] = useState(false);
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
  const [packageDetailsScanEntry, setPackageDetailsScanEntry] = useState<{ advisory_references?: string[]; risk_overall_status?: string; risk_overall_score?: number; risk_allowlisted?: boolean; static_features?: Record<string, number | null> } | null>(null);
  // Scan mode
  const [activeScanMode, setActiveScanMode] = useState<"full" | "static_only" | "static_dynamic" | "dynamic_only">("full");
  const isMountedRef = useRef(true);
  const scanPollTimerRef = useRef<number | null>(null);
  const elapsedTickerRef = useRef<number | null>(null);
  const scanRetryAttemptRef = useRef(0);
  const liveResultKeysRef = useRef<Set<string>>(new Set());
  const repoContextRef = useRef<RepoContext | null>(null);
  const repoContextPromiseRef = useRef<Promise<RepoContext> | null>(null);
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
  const canCancelScan = scanJobId !== null && (scanDisplay.phase === "pending" || scanDisplay.phase === "running");
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
  const canStartScan = !isScanRunning && (scanScope === "full" || selectedScanPackages.length > 0);
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
  const canStartPartialAnalysisScan = !isScanRunning && selectedAnalysisPackages.length > 0;
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
  const scanStartLabel = isScanRunning ? "Scanning packages..." : isPartialScan ? "Start Partial Scan" : "Start Scan";
  const runtimeElapsedLabel = useMemo(() => {
    if (scanDisplay.phase === "pending" || scanDisplay.phase === "running") {
      return `Elapsed ${formatDuration(liveElapsedSeconds)}`;
    }

    return scanDisplay.elapsedLabel;
  }, [liveElapsedSeconds, scanDisplay.elapsedLabel, scanDisplay.phase]);

  const sections = [
    { key: "graph", label: "Dependency Graph" },
    { key: "static-analysis", label: "Static Analysis" },
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
      if (scanPollTimerRef.current !== null) {
        window.clearTimeout(scanPollTimerRef.current);
      }
      if (elapsedTickerRef.current !== null) {
        window.clearInterval(elapsedTickerRef.current);
      }
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
    setIsScanRunning(false);
    setScanJobId(null);
    setScanProgress(0);
    setScanDetails(null);
    setScanStatus("Waiting to start malware scan.");
    setHasScanned(false);
    setScanScope("full");
    setSelectedScanPackages([]);
    setLiveElapsedSeconds(0);
    setScanHistoryJobs([]);
    setIsScanHistoryLoading(false);
    setScanHistoryTotal(0);
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
    if (scanPollTimerRef.current !== null) {
      window.clearTimeout(scanPollTimerRef.current);
      scanPollTimerRef.current = null;
    }
    if (elapsedTickerRef.current !== null) {
      window.clearInterval(elapsedTickerRef.current);
      elapsedTickerRef.current = null;
    }
    scanRetryAttemptRef.current = 0;
  }, [decodedId]);

  useEffect(() => {
    if (!isScanRunning || !scanDetails?.started_at) {
      if (elapsedTickerRef.current !== null) {
        window.clearInterval(elapsedTickerRef.current);
        elapsedTickerRef.current = null;
      }
      return;
    }

    setLiveElapsedSeconds(scanDetails ? normalizeLiveElapsedSeconds(scanDetails as ScanJobResponse) : 0);

    if (elapsedTickerRef.current !== null) {
      window.clearInterval(elapsedTickerRef.current);
    }

    elapsedTickerRef.current = window.setInterval(() => {
      setLiveElapsedSeconds((current) => current + 1);
    }, 1000);

    return () => {
      if (elapsedTickerRef.current !== null) {
        window.clearInterval(elapsedTickerRef.current);
        elapsedTickerRef.current = null;
      }
    };
  }, [isScanRunning, scanDetails?.started_at, scanDetails?.elapsed_seconds]);

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

        if (!isMountedRef.current) {
          return;
        }

        setScanError(null);
        setScanDetails(payload);
        setScanStatus(statusValue);
        setScanProgress(computeScanProgress(payload, phase, 0));
        setLiveElapsedSeconds(normalizeLiveElapsedSeconds(payload));

        if (Array.isArray(payload.results)) {
          const liveResults = normalizeScanResultsPayload({ results: payload.results });
          appendLiveResultRows(liveResults.rows);
        }

        scanRetryAttemptRef.current = 0;

        if (SCAN_TERMINAL_DONE.has(statusValue)) {
          setIsScanRunning(false);
          setScanStatus("Scan completed. Applying latest highlights.");
          setScanProgress(100);
          setHasScanned(true);
          await loadLatestScanResults();
          setScanStatus("Latest malware scan results loaded.");
          return;
        }

        if (SCAN_TERMINAL_CANCELLED.has(statusValue)) {
          setIsScanRunning(false);
          setScanStatus("Scan cancelled by user.");
          return;
        }

        if (SCAN_TERMINAL_FAILED.has(statusValue)) {
          setIsScanRunning(false);
          setScanError(`Package scan failed with status: ${statusValue}`);
          await loadLatestScanResults();
          return;
        }

        if (isPollingStatus(statusValue)) {
          if (scanPollTimerRef.current !== null) {
            window.clearTimeout(scanPollTimerRef.current);
          }

          scanPollTimerRef.current = window.setTimeout(() => {
            void pollScanJob(owner, repoName, jobId, headers);
          }, SCAN_POLL_INTERVAL_MS);
        }
      } catch (pollError) {
        if (!isMountedRef.current) {
          return;
        }

        const errorMeta = resolvePollErrorMeta(pollError);
        const timestamp = new Date().toISOString();
        console.error(`[${timestamp}] scan polling error`, {
          kind: errorMeta.kind,
          status: errorMeta.status,
          message: errorMeta.message,
          error: pollError,
        });

        if (errorMeta.kind === "auth") {
          setScanError(errorMeta.message);
          setIsScanRunning(false);
          window.location.href = "/login";
          return;
        }

        if (errorMeta.kind === "not-found") {
          setScanError(errorMeta.message);
          setIsScanRunning(false);
          return;
        }

        scanRetryAttemptRef.current += 1;
        const retryAttempt = scanRetryAttemptRef.current;

        if (retryAttempt > POLL_RETRY_SILENT_ATTEMPTS || errorMeta.kind === "other") {
          setScanError(`${errorMeta.message} Retrying shortly...`);
        }

        if (scanPollTimerRef.current !== null) {
          window.clearTimeout(scanPollTimerRef.current);
        }

        const backoffMultiplier = Math.max(0, retryAttempt - POLL_RETRY_SILENT_ATTEMPTS);
        const exponentialDelay = Math.min(
          SCAN_RETRY_MAX_DELAY_MS,
          SCAN_POLL_INTERVAL_MS * Math.max(1, 2 ** backoffMultiplier),
        );
        const retryDelay =
          errorMeta.kind === "other"
            ? Math.max(POLL_ERROR_VISIBLE_RETRY_DELAY_MS, exponentialDelay)
            : retryAttempt > POLL_RETRY_SILENT_ATTEMPTS
              ? Math.max(POLL_ERROR_VISIBLE_RETRY_DELAY_MS, exponentialDelay)
              : SCAN_POLL_INTERVAL_MS;

        scanPollTimerRef.current = window.setTimeout(() => {
          void pollScanJob(owner, repoName, jobId, headers);
        }, retryDelay);
      }
    },
    [appendLiveResultRows, loadLatestScanResults],
  );

  const triggerPackageScan = useCallback(async () => {
    setScanError(null);
    setIsScanRunning(true);
    setScanStatus("pending");
    setScanProgress(0);
    setLiveElapsedSeconds(0);
    setScanResultRows([]);
    setGraphScanView("progress");
    liveResultKeysRef.current = new Set();
    scanRetryAttemptRef.current = 0;

    try {
      const { owner, repoName, headers, ecosystem } = await resolveRepoCoordinates();
      const token = clientSessionStorage.readToken();
      const scanResultsCacheKey = token ? buildScanResultsCacheKey(token, owner, repoName) : null;
      const selectedPackagesPayload = isPartialScan ? selectedScanPackages : undefined;
      const triggerBody: Record<string, unknown> = { ecosystem, scan_mode: activeScanMode };

      if (selectedPackagesPayload && selectedPackagesPayload.length > 0) {
        triggerBody.selected_packages = selectedPackagesPayload;
      }

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
        scan_mode: activeScanMode,
        selected_packages: isPartialScan && selectedScanPackages.length > 0 ? selectedScanPackages : undefined,
      });

      if (!triggerPayload.job_id) {
        throw new Error("Scan trigger did not return a job id.");
      }

      setHasScanned(true);
      setScanJobId(triggerPayload.job_id);
      setScanStatus("pending");
      setScanDetails({ status: "pending", scanned_packages: 0, total_unique_packages: 0, progress_percent: 0 });

      if (scanPollTimerRef.current !== null) {
        window.clearTimeout(scanPollTimerRef.current);
      }

      scanPollTimerRef.current = window.setTimeout(() => {
        void pollScanJob(owner, repoName, triggerPayload.job_id, headers);
      }, SCAN_POLL_INTERVAL_MS);

    } catch (scanError) {
      const message = scanError instanceof Error ? scanError.message : "Unexpected error while running package scan.";
      setScanError(message);
      setScanStatus("failed");
      setHasScanned(false);
    } finally {
      if (!scanPollTimerRef.current) {
        setIsScanRunning(false);
      }
    }
  }, [isPartialScan, pollScanJob, resolveRepoCoordinates, selectedScanPackages, activeScanMode]);

  const triggerPartialAnalysisScan = useCallback(async () => {
    if (selectedAnalysisPackages.length === 0 || isScanRunning) {
      return;
    }
    setScanError(null);
    setIsScanRunning(true);
    setScanStatus("pending");
    setScanProgress(0);
    setLiveElapsedSeconds(0);
    setScanResultRows([]);
    setGraphScanView("progress");
    liveResultKeysRef.current = new Set();
    scanRetryAttemptRef.current = 0;

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
        scan_mode: "dynamic_only",
        selected_packages: selectedAnalysisPackages,
      });

      if (!triggerPayload.job_id) {
        throw new Error("Scan trigger did not return a job id.");
      }

      setHasScanned(true);
      setScanJobId(triggerPayload.job_id);
      setScanStatus("pending");
      setScanDetails({ status: "pending", scanned_packages: 0, total_unique_packages: 0, progress_percent: 0 });

      if (scanPollTimerRef.current !== null) {
        window.clearTimeout(scanPollTimerRef.current);
      }

      scanPollTimerRef.current = window.setTimeout(() => {
        void pollScanJob(owner, repoName, triggerPayload.job_id, headers);
      }, SCAN_POLL_INTERVAL_MS);

    } catch (scanError) {
      const message = scanError instanceof Error ? scanError.message : "Unexpected error while running package scan.";
      setScanError(message);
      setScanStatus("failed");
      setHasScanned(false);
    } finally {
      if (!scanPollTimerRef.current) {
        setIsScanRunning(false);
      }
    }
  }, [pollScanJob, resolveRepoCoordinates, selectedAnalysisPackages, isScanRunning, activeScanMode]);

  const cancelScanJob = useCallback(async () => {
    if (!scanJobId || isCancellingScan) {
      return;
    }

    setIsCancellingScan(true);
    setScanError(null);

    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL!, authHeaders: headers, owner, repoName };
      const result = await apiCancelScan(scanContext, scanJobId);
      const cancelledStatus = result.status;

      if (scanPollTimerRef.current !== null) {
        window.clearTimeout(scanPollTimerRef.current);
        scanPollTimerRef.current = null;
      }

      if (elapsedTickerRef.current !== null) {
        window.clearInterval(elapsedTickerRef.current);
        elapsedTickerRef.current = null;
      }

      setIsScanRunning(false);
      setScanStatus(cancelledStatus === "cancelled" ? "Scan cancelled by user." : "Scan cancellation acknowledged.");
      setScanDetails((current) => ({
        ...(current ?? {}),
        status: "cancelled",
      }));
      setScanError(null);
      setGraphScanView("progress");
    } catch (cancelError) {
      const status =
        typeof cancelError === "object" && cancelError !== null && "status" in cancelError && typeof (cancelError as { status?: unknown }).status === "number"
          ? ((cancelError as { status: number }).status)
          : null;

      if (status === 400) {
        setScanError("Cannot stop: job already completed.");
      } else if (status === 404) {
        setScanError("Scan job not found.");
      } else {
        setScanError(cancelError instanceof Error ? cancelError.message : "Unable to stop scan. Please try again.");
      }
    } finally {
      setIsCancellingScan(false);
    }
  }, [isCancellingScan, resolveRepoCoordinates, scanJobId]);

  const loadScanHistory = useCallback(async () => {
    if (!API_BASE_URL) return;
    setIsScanHistoryLoading(true);
    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const scanContext: ScanApiContext = { baseUrl: API_BASE_URL, authHeaders: headers, owner, repoName };
      const result = await getScanHistory(scanContext, 1, 20);
      if (isMountedRef.current) {
        setScanHistoryJobs(result.jobs);
        setScanHistoryTotal(result.total);
      }
    } catch { /* silent */ } finally {
      if (isMountedRef.current) setIsScanHistoryLoading(false);
    }
  }, [resolveRepoCoordinates]);

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
      void loadScanHistory();
    }
    // Only re-run when the active section changes, not every loadScanHistory recreation
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSection, decodedId]);

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
          `${API_BASE_URL}/api/repos/${encodeURIComponent(repoCtx.owner)}/${encodeURIComponent(repoCtx.repoName)}/scan/latest/results`,
          { method: "GET", headers: repoCtx.headers, credentials: "include", cache: "no-store" },
        );
        if (scanRes.ok && !cancelled) {
          const scanData = await scanRes.json() as Record<string, { advisory_references?: string[]; risk_overall_status?: string; risk_overall_score?: number; risk_allowlisted?: boolean; static_features?: Record<string, number | null> }>;
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

  return (
    <section className="relative flex h-[100dvh] w-full overflow-hidden bg-black">
      <div
        className={`flex h-full min-w-0 flex-1 flex-col transition-[padding-right] duration-300 ${
          isAgentChatOpen ? "pr-80" : "pr-0"
        }`}
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
                    {canShowGraphScanResults ? (
                      <button
                        type="button"
                        onClick={() => setGraphScanView((current) => (current === "progress" ? "results" : "progress"))}
                        className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] transition ${
                          graphScanView === "results"
                            ? "border-cyan-300/70 bg-cyan-500/20 text-cyan-50"
                            : "border-gray-700 bg-gray-900 text-slate-300 hover:border-gray-500"
                        }`}
                      >
                        {graphScanView === "results" ? "Show Progress" : "View Results"}
                      </button>
                    ) : null}
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
                            <div
                              className={`h-full rounded-full transition-all duration-300 ${scanError ? "bg-rose-400" : scanDisplay.phase === "pending" ? "animate-pulse bg-cyan-300/90" : "bg-cyan-400"}`}
                              style={{ width: `${Math.max(0, Math.min(100, scanDisplay.progressPercent))}%` }}
                            />
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

                      <div className="pt-1 space-y-2">
                        <div className="flex flex-wrap gap-1">
                          {(["full", "static_only", "static_dynamic", "dynamic_only"] as const).map((mode) => (
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
                              {mode === "full" ? "Full" : mode === "static_only" ? "Static" : mode === "static_dynamic" ? "S+D" : "Dynamic"}
                            </button>
                          ))}
                        </div>
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
                  />
                </div>

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
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-cyan-300">Static Analysis</p>
                    <p className="mt-1 text-sm text-slate-300">Review the latest completed scan snapshot and package findings.</p>
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
                          void triggerPartialAnalysisScan();
                        }}
                        disabled={!canStartPartialAnalysisScan}
                        className="w-full rounded-md border border-cyan-400/40 bg-cyan-500/15 py-2 text-xs font-semibold uppercase tracking-[0.12em] text-cyan-100 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Run Analysis on {selectedAnalysisPackages.length} Package{selectedAnalysisPackages.length === 1 ? "" : "s"}
                      </button>
                    ) : null}
                  </div>

                  <div className="grid gap-3 sm:grid-cols-3">
                    <div className="rounded-xl border border-slate-700 bg-slate-900/60 p-3">
                      <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Status</p>
                      <p className="mt-1 text-sm font-medium text-slate-100">{latestScanSummary.status ?? "No completed scans yet"}</p>
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

                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Static findings</p>
                    <div className="mt-3 space-y-2">
                      {scanResultRows.length > 0 ? (
                        scanResultRows.map((row) => {
                          const isErrorRow = row.errorMessage !== null || row.status === "failed";

                          return (
                            <div
                              key={row.id}
                              className={`rounded-lg border p-3 text-sm ${isErrorRow ? "border-rose-400/30 bg-rose-500/10 text-rose-100" : "border-slate-700 bg-slate-950/60 text-slate-200"}`}
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <p className="font-medium">
                                  {row.packageName} <span className="text-slate-400">@</span> {row.version}
                                </p>
                                <span className="text-[11px] uppercase tracking-[0.14em] text-slate-400">{row.status}</span>
                              </div>
                              <p className="mt-1 text-xs text-slate-400">
                                Malware score: {row.malwareScore !== null ? `${(row.malwareScore * 100).toFixed(1)}%` : "-"}
                              </p>
                              {row.errorMessage ? <p className="mt-1 text-xs text-rose-200">{row.errorMessage}</p> : null}
                            </div>
                          );
                        })
                      ) : (
                        <p className="text-sm text-slate-400">No static findings are available yet.</p>
                      )}
                    </div>
                  </div>
                </div>

                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Latest completed scan summary</p>
                  {latestScanSummary.status === null ? (
                    <p className="mt-2 text-sm text-slate-300">Run a scan to populate the static analysis summary.</p>
                  ) : (
                    <>
                      <p className="mt-2 text-sm text-slate-200">Status: {latestScanSummary.status}</p>
                      <p className="mt-1 text-sm text-slate-200">
                        Processed: {latestScanSummary.processed ?? "-"} / {latestScanSummary.total ?? "-"}
                      </p>
                      <p className="mt-1 text-sm text-slate-200">Completed: {formatTimestampForDisplay(latestScanSummary.completedAt)}</p>
                    </>
                  )}

                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">API</p>
                    <p className="mt-2 text-sm text-slate-200">{scanJobId ? "/scan/{job_id}" : "Completed scan summaries appear here after a run."}</p>
                  </div>
                </div>
              </div>
            </div>
          ) : null}

          {activeSection === "dynamic-analysis" ? (
            <div className="h-full overflow-y-auto px-4 pb-6 pt-4">
              <div className="grid gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
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
                          void triggerPartialAnalysisScan();
                        }}
                        disabled={!canStartPartialAnalysisScan}
                        className="w-full rounded-md border border-cyan-400/40 bg-cyan-500/15 py-2 text-xs font-semibold uppercase tracking-[0.12em] text-cyan-100 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Run Analysis on {selectedAnalysisPackages.length} Package{selectedAnalysisPackages.length === 1 ? "" : "s"}
                      </button>
                    ) : null}
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Current status</p>
                    <p className="mt-2 text-sm text-slate-200">{shouldShowScanRuntime ? scanDisplay.statusLabel : "Ready to start"}</p>
                    {scanJobId ? <p className="mt-1 text-xs text-slate-400">Job ID: {scanJobId}</p> : null}
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-900/50 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</p>
                    {shouldShowScanRuntime ? (
                      <>
                        <p className="mt-2 text-sm text-slate-200">{scanDisplay.primaryCountLabel}</p>
                        <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                          <div
                            className={`h-full rounded-full transition-all duration-300 ${scanError ? "bg-rose-400" : scanDisplay.phase === "pending" ? "animate-pulse bg-cyan-300/90" : "bg-cyan-400"}`}
                            style={{ width: `${Math.max(0, Math.min(100, scanDisplay.progressPercent))}%` }}
                          />
                        </div>
                        <p className="mt-2 text-xs text-slate-400">{scanDisplay.progressLabel}</p>
                        <div className="mt-2 flex flex-wrap gap-3 text-xs text-slate-400">
                          {scanDisplay.etaLabel ? <span>{scanDisplay.etaLabel}</span> : null}
                          {scanDisplay.speedLabel ? <span>{scanDisplay.speedLabel}</span> : null}
                          {runtimeElapsedLabel ? <span>{runtimeElapsedLabel}</span> : null}
                        </div>
                      </>
                    ) : (
                      <p className="mt-2 text-sm text-slate-300">Start a scan to stream dynamic results here.</p>
                    )}
                  </div>
                </div>

                <div className="space-y-4 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Current job package results</p>
                      {scanJobId ? (
                        <p className="mt-2 text-xs text-slate-400">
                          Rows: {scanResultRows.length} · Failed rows: {liveFailedRowsCount}
                        </p>
                      ) : (
                        <p className="mt-2 text-xs text-slate-400">Start a scan to stream live package rows from /scan/{'{'}job_id{'}'}.</p>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        void triggerPackageScan();
                      }}
                      disabled={!canStartScan}
                      className="inline-flex items-center rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-cyan-100 transition hover:border-cyan-300 hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {scanStartLabel}
                    </button>
                  </div>

                  {scanJobId && scanResultRows.length === 0 ? (
                    <p className="text-xs text-slate-400">Waiting for first package rows from the current job...</p>
                  ) : null}

                  {scanJobId && scanResultRows.length > 0 ? (
                    <div className="max-h-[52vh] overflow-auto rounded-lg border border-slate-800">
                      <table className="w-full text-left text-xs text-slate-200">
                        <thead className="bg-slate-900/90 text-slate-400">
                          <tr>
                            <th className="px-3 py-2 font-medium">Package</th>
                            <th className="px-3 py-2 font-medium">Version</th>
                            <th className="px-3 py-2 font-medium">Status</th>
                            <th className="px-3 py-2 font-medium">Score</th>
                            <th className="px-3 py-2 font-medium">Error</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanResultRows.map((row) => {
                            const isErrorRow = row.errorMessage !== null || row.status === "failed";

                            return (
                              <tr key={row.id} className={isErrorRow ? "border-t border-rose-500/30 bg-rose-500/10" : "border-t border-slate-800"}>
                                <td className="px-3 py-2">{row.packageName}</td>
                                <td className="px-3 py-2">{row.version}</td>
                                <td className="px-3 py-2 uppercase">{row.status}</td>
                                <td className="px-3 py-2">{row.malwareScore !== null ? `${(row.malwareScore * 100).toFixed(1)}%` : "-"}</td>
                                <td className="px-3 py-2 text-rose-200">{row.errorMessage ?? "-"}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="text-sm text-slate-300">No dynamic rows are available yet.</p>
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
                    <div className="space-y-3 rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                      {isPackageDetailsLoading ? (
                        <div className="space-y-3">
                          <div className="h-6 w-48 animate-pulse rounded bg-slate-700/60" />
                          <div className="h-4 w-full animate-pulse rounded bg-slate-800/80" />
                          <div className="h-4 w-3/4 animate-pulse rounded bg-slate-800/80" />
                        </div>
                      ) : (
                        <>
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                              <h3 className="text-lg font-semibold text-slate-100">
                                {selectedDetailsPackage.slice(0, selectedDetailsPackage.lastIndexOf("@")) || selectedDetailsPackage}
                              </h3>
                              <p className="font-mono text-sm text-teal-300">
                                v{selectedDetailsPackage.slice(selectedDetailsPackage.lastIndexOf("@") + 1) || "unknown"}
                              </p>
                            </div>
                            {(() => {
                              const entry = scanResultsMap[selectedDetailsPackage] as { malware_status?: string } | undefined;
                              const status = packageDetailsScanEntry?.risk_overall_status ?? entry?.malware_status;
                              if (!status) return null;
                              const cls = status === "malicious" ? "border-rose-400/50 bg-rose-500/15 text-rose-100"
                                : status === "suspicious" ? "border-amber-400/50 bg-amber-500/15 text-amber-100"
                                : status === "clean" ? "border-emerald-400/50 bg-emerald-500/15 text-emerald-100"
                                : "border-slate-400/50 bg-slate-500/15 text-slate-300";
                              return (
                                <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${cls}`}>
                                  {status}
                                </span>
                              );
                            })()}
                          </div>

                          {packageDetailsData?.description ? (
                            <p className="text-sm text-slate-300">{packageDetailsData.description}</p>
                          ) : null}

                          <div className="grid grid-cols-2 gap-2 text-xs">
                            {packageDetailsData?.monthly_downloads != null ? (
                              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-2.5">
                                <p className="uppercase tracking-[0.1em] text-slate-500">Monthly downloads</p>
                                <p className="mt-1 font-medium text-slate-200">
                                  {packageDetailsData.monthly_downloads >= 1_000_000
                                    ? `${(packageDetailsData.monthly_downloads / 1_000_000).toFixed(1)}M`
                                    : packageDetailsData.monthly_downloads >= 1_000
                                      ? `${(packageDetailsData.monthly_downloads / 1_000).toFixed(0)}K`
                                      : String(packageDetailsData.monthly_downloads)}
                                </p>
                              </div>
                            ) : null}
                            {packageDetailsScanEntry?.risk_overall_score != null ? (
                              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-2.5">
                                <p className="uppercase tracking-[0.1em] text-slate-500">Risk score</p>
                                <div className="mt-1">
                                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-700">
                                    <div
                                      className={`h-full rounded-full ${packageDetailsScanEntry.risk_overall_score > 0.5 ? "bg-rose-400" : packageDetailsScanEntry.risk_overall_score > 0.2 ? "bg-amber-400" : "bg-emerald-400"}`}
                                      style={{ width: `${(packageDetailsScanEntry.risk_overall_score * 100).toFixed(0)}%` }}
                                    />
                                  </div>
                                  <p className="mt-0.5 text-slate-300">{(packageDetailsScanEntry.risk_overall_score * 100).toFixed(0)}%</p>
                                </div>
                              </div>
                            ) : null}
                          </div>

                          {packageDetailsData?.homepage || packageDetailsData?.registry_url ? (
                            <div className="flex flex-wrap gap-3 text-xs">
                              {packageDetailsData.homepage ? (
                                <a href={packageDetailsData.homepage} target="_blank" rel="noreferrer" className="text-teal-300 underline decoration-teal-400/50 underline-offset-2">
                                  Homepage ↗
                                </a>
                              ) : null}
                              {packageDetailsData.registry_url ? (
                                <a href={packageDetailsData.registry_url} target="_blank" rel="noreferrer" className="text-teal-300 underline decoration-teal-400/50 underline-offset-2">
                                  Registry ↗
                                </a>
                              ) : null}
                            </div>
                          ) : null}

                          {packageDetailsLatestVersion ? (
                            <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-2.5 text-xs">
                              <p className="uppercase tracking-[0.1em] text-slate-500">Latest version</p>
                              <p className="mt-1 font-mono text-teal-200">{packageDetailsLatestVersion}</p>
                              {packageDetailsVersions.length > 1 ? (
                                <p className="mt-0.5 text-slate-500">{packageDetailsVersions.length} versions available</p>
                              ) : null}
                            </div>
                          ) : null}

                          {packageDetailsScanEntry?.advisory_references && packageDetailsScanEntry.advisory_references.length > 0 ? (
                            <div className="rounded-lg border border-amber-400/25 bg-amber-500/10 p-3">
                              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-amber-200">
                                {packageDetailsScanEntry.advisory_references.length} CVE / Advisory Reference{packageDetailsScanEntry.advisory_references.length !== 1 ? "s" : ""}
                              </p>
                              <div className="mt-2 flex flex-wrap gap-1.5">
                                {packageDetailsScanEntry.advisory_references.map((ref) => (
                                  <span key={ref} className="inline-flex rounded border border-amber-400/30 bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] text-amber-100">{ref}</span>
                                ))}
                              </div>
                            </div>
                          ) : packageDetailsScanEntry ? (
                            <p className="text-xs text-slate-500">No CVE advisories found for this package.</p>
                          ) : null}

                          {packageDetailsScanEntry?.static_features ? (
                            <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-3 text-xs">
                              <p className="mb-2 font-semibold uppercase tracking-[0.12em] text-slate-400">Static Features</p>
                              <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
                                {Object.entries(packageDetailsScanEntry.static_features).map(([key, val]) => (
                                  <div key={key} className="rounded border border-slate-800 bg-slate-950/40 px-2 py-1">
                                    <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">{key.replace(/_/g, " ")}</p>
                                    <p className="mt-0.5 font-mono text-slate-300">{val != null ? (typeof val === "number" && val < 1 && val > 0 ? `${(val * 100).toFixed(0)}%` : String(val)) : "-"}</p>
                                  </div>
                                ))}
                              </div>
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
                        ? `${sbomDocument.metadata.component_count} component${sbomDocument.metadata.component_count !== 1 ? "s" : ""} · generated ${new Date(sbomDocument.metadata.timestamp).toLocaleString()}`
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
                        <p className="mt-1 font-medium text-violet-300">{sbomDocument.metadata.component_count}</p>
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
                                    {component.risk_status} <span className="font-normal text-slate-500">({(component.risk_score * 100).toFixed(0)}%)</span>
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
                <div className="flex items-center justify-between rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-indigo-300">Scan History</p>
                    <p className="mt-1 text-sm text-slate-300">
                      {scanHistoryTotal > 0 ? `${scanHistoryTotal} scan job${scanHistoryTotal !== 1 ? "s" : ""} found.` : "View all scans performed on this repository."}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => { void loadScanHistory(); }}
                    disabled={isScanHistoryLoading}
                    className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-slate-300 transition hover:border-slate-500 disabled:opacity-50"
                  >
                    {isScanHistoryLoading ? "Loading..." : "Refresh"}
                  </button>
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
                  <div className="overflow-hidden rounded-2xl border border-slate-700 bg-slate-950/70">
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
                              : job.scan_mode === "static_only"
                                ? "border-purple-400/50 bg-purple-500/15 text-purple-100"
                                : job.scan_mode === "static_dynamic"
                                  ? "border-teal-400/50 bg-teal-500/15 text-teal-100"
                                  : "border-orange-400/50 bg-orange-500/15 text-orange-100";
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
                                      {job.scan_mode === "full" ? "Full" : job.scan_mode === "static_only" ? "Static" : job.scan_mode === "static_dynamic" ? "S+D" : "Dynamic"}
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
                                            <div className="max-h-48 overflow-auto rounded-lg border border-slate-800">
                                              <table className="w-full text-left text-[11px] text-slate-300">
                                                <thead className="bg-slate-900/80 text-slate-500">
                                                  <tr>
                                                    <th className="px-3 py-2">Package</th>
                                                    <th className="px-3 py-2">Status</th>
                                                    <th className="px-3 py-2">Score</th>
                                                    <th className="px-3 py-2">CVEs</th>
                                                  </tr>
                                                </thead>
                                                <tbody>
                                                  {selectedHistoryJob.results.slice(0, 100).map((result) => (
                                                    <tr key={result.id} className="border-t border-slate-800/60">
                                                      <td className="px-3 py-1.5">{result.package_name}@{result.package_version}</td>
                                                      <td className="px-3 py-1.5 uppercase">{result.malware_status}</td>
                                                      <td className="px-3 py-1.5">{(result.risk_overall_score * 100).toFixed(0)}%</td>
                                                      <td className="px-3 py-1.5">{result.advisory_references.length > 0 ? result.advisory_references.length : "-"}</td>
                                                    </tr>
                                                  ))}
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

          {activeSection === "add" ? (
            <div className="h-full overflow-hidden px-4 pb-6 pt-4">
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
          className={`pointer-events-auto absolute inset-y-0 right-0 flex h-full w-80 flex-col border-l-4 border-cyan-400/20 bg-gray-950/90 shadow-[0_28px_72px_-34px_rgba(2,6,23,0.95)] transition-transform duration-300 ${
            isAgentChatOpen ? "translate-x-0" : "translate-x-full"
          }`}
        >
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
              <span className="text-sm font-semibold leading-none">×</span>
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
