"use client";

import { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AddDependencyPanel } from "@/app/components/add-dependency-panel";
import { DependencyTree } from "@/app/components/dependency-tree";
import { DependencyNode, Ecosystem } from "@/app/types/dashboard";
import { clientSessionStorage } from "@/app/lib/auth/client-session";
import { createCacheKey, getCachedValue, hashString, setCachedValue } from "@/app/lib/browser-cache";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL;
const DASHBOARD_CACHE_TTL_MS = 1000 * 60 * 20;
const TREE_CACHE_TTL_MS = 1000 * 60 * 10;
const SCAN_RESULTS_CACHE_TTL_MS = 1000 * 60 * 3;
const MAX_CACHE_BYTES = 1_500_000;

type RepoDetailsPageProps = {
  params: Promise<{ id: string }>;
};

type UserPayload = {
  username?: unknown;
  login?: unknown;
  user?: {
    username?: unknown;
    login?: unknown;
  };
};

type ScanTriggerResponse = {
  job_id: string;
  status: string;
};

type ScanJobResponse = {
  status?: string;
  processed_packages?: number | null;
  progress?: number;
  completed_packages?: number;
  total_packages?: number;
  total_dependency_nodes?: number | null;
  total_unique_packages?: number | null;
  scanned_packages?: number | null;
  progress_percent?: number | null;
  elapsed_seconds?: number | null;
  packages_per_minute?: number | null;
  estimated_seconds_remaining?: number | null;
  started_at?: string | null;
  completed_at?: string | null;
  results?: unknown;
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

const SCAN_TERMINAL_DONE = new Set(["completed", "success", "succeeded", "done"]);
const SCAN_TERMINAL_FAILED = new Set(["failed", "error"]);
const SCAN_TERMINAL_CANCELLED = new Set(["cancelled"]);
const ALL_ECOSYSTEMS: Ecosystem[] = ["npm", "pypi"];
const SCAN_POLL_INTERVAL_MS = 1500;
const SCAN_RETRY_MAX_DELAY_MS = 12000;

const POLL_RETRY_SILENT_ATTEMPTS = 3;
const POLL_ERROR_VISIBLE_RETRY_DELAY_MS = 5000;

type ScanPhase = "pending" | "running" | "completed" | "cancelled" | "failed";

type ScanDisplay = {
  phase: ScanPhase;
  progressPercent: number;
  progressLabel: string;
  primaryCountLabel: string;
  secondaryCountLabel: string | null;
  etaLabel: string | null;
  speedLabel: string | null;
  elapsedLabel: string | null;
  statusLabel: string;
};

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

function normalizeLegacyProgress(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return null;
  }

  if (value <= 1) {
    return Math.max(0, Math.min(100, value * 100));
  }

  return Math.max(0, Math.min(100, value));
}

function normalizeStatusValue(status: unknown): string {
  return typeof status === "string" && status.trim().length > 0 ? status.trim().toLowerCase() : "pending";
}

function isPollingStatus(status: string): boolean {
  return status === "pending" || status === "queued" || status === "running" || status === "in_progress";
}

function coerceString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
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

function normalizeLatestCompletedScan(payload: unknown): LatestScanSummary {
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
    status: coerceString(record.status),
    processed: coerceNonNegativeNumber(record.scanned_packages),
    total: coerceNonNegativeNumber(record.total_unique_packages),
    completedAt: coerceString(record.completed_at),
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

type PollErrorKind = "transient" | "auth" | "not-found" | "other";

type PollErrorMeta = {
  kind: PollErrorKind;
  status: number | null;
  message: string;
};

function resolvePollErrorMeta(error: unknown): PollErrorMeta {
  const unknownMessage = error instanceof Error ? error.message : "Unexpected polling error";
  const maybeStatus =
    typeof error === "object" && error !== null && "status" in error && typeof (error as { status?: unknown }).status === "number"
      ? ((error as { status: number }).status)
      : null;

  if (maybeStatus === 401) {
    return { kind: "auth", status: maybeStatus, message: "Authentication expired. Redirecting to login." };
  }

  if (maybeStatus === 404) {
    return { kind: "not-found", status: maybeStatus, message: "Scan job not found or expired." };
  }

  if (maybeStatus === 503 || unknownMessage.toLowerCase().includes("network")) {
    return { kind: "transient", status: maybeStatus, message: "Temporary network issue while polling scan status." };
  }

  if (maybeStatus === null) {
    return { kind: "transient", status: null, message: "Temporary polling error." };
  }

  return { kind: "other", status: maybeStatus, message: `Polling failed with status ${maybeStatus}.` };
}

function buildResultDedupKey(row: ScanResultRow): string {
  return `${row.packageName}|${row.version}|${row.scanTimestamp ?? "-"}|${row.status}|${row.errorMessage ?? "-"}`;
}

function normalizeLiveElapsedSeconds(scanDetails: ScanJobResponse | null): number {
  if (!scanDetails) {
    return 0;
  }

  const directElapsed = coerceNonNegativeNumber(scanDetails.elapsed_seconds);
  if (directElapsed !== null) {
    return Math.floor(directElapsed);
  }

  const startedAtRaw = coerceString(scanDetails.started_at);
  if (!startedAtRaw) {
    return 0;
  }

  const startedAtMs = Date.parse(startedAtRaw);
  if (!Number.isFinite(startedAtMs)) {
    return 0;
  }

  return Math.max(0, Math.floor((Date.now() - startedAtMs) / 1000));
}

function normalizeScanPhase(status: string | undefined, isScanRunning: boolean, hasError: boolean): ScanPhase {
  if (hasError) {
    return "failed";
  }

  const normalized = typeof status === "string" ? status.trim().toLowerCase() : "";

  if (SCAN_TERMINAL_DONE.has(normalized)) {
    return "completed";
  }

  if (SCAN_TERMINAL_CANCELLED.has(normalized)) {
    return "cancelled";
  }

  if (SCAN_TERMINAL_FAILED.has(normalized)) {
    return "failed";
  }

  if (normalized === "running" || normalized === "in_progress") {
    return "running";
  }

  if (normalized === "pending" || normalized === "queued") {
    return "pending";
  }

  if (isScanRunning) {
    return "pending";
  }

  return "pending";
}

function computeScanProgress(payload: ScanJobResponse | null, phase: ScanPhase, fallbackProgress: number): number {
  if (!payload) {
    return fallbackProgress;
  }

  const explicitPercent = normalizeLegacyProgress(payload.progress_percent);
  if (explicitPercent !== null) {
    return explicitPercent;
  }

  const scannedPackages = coerceNonNegativeNumber(payload.scanned_packages) ?? 0;
  const totalUniquePackages = coerceNonNegativeNumber(payload.total_unique_packages) ?? 0;

  if (totalUniquePackages > 0) {
    return Math.max(0, Math.min(100, (scannedPackages / totalUniquePackages) * 100));
  }

  return phase === "completed" ? 100 : 0;
}

function deriveScanDisplay(scanDetails: ScanJobResponse | null, fallbackProgress: number, isScanRunning: boolean, scanError: string | null): ScanDisplay {
  const phase = normalizeScanPhase(scanDetails?.status, isScanRunning, scanError !== null);
  const scannedPackages = coerceNonNegativeNumber(scanDetails?.scanned_packages);
  const totalDependencyNodes = coerceNonNegativeNumber(scanDetails?.total_dependency_nodes);
  const totalUniquePackages = coerceNonNegativeNumber(scanDetails?.total_unique_packages);
  const progressPercent = computeScanProgress(scanDetails, phase, fallbackProgress);
  const packagesPerMinute = coerceNonNegativeNumber(scanDetails?.packages_per_minute);
  const elapsedSeconds = coerceNonNegativeNumber(scanDetails?.elapsed_seconds);
  const estimatedSecondsRemaining = coerceNonNegativeNumber(scanDetails?.estimated_seconds_remaining);

  let primaryCountLabel = "No scan data yet";

  if (scannedPackages !== null && totalUniquePackages !== null) {
    primaryCountLabel = `Scanned ${scannedPackages} / ${totalUniquePackages} packages`;
  } else if (scannedPackages !== null) {
    primaryCountLabel = `Scanned ${scannedPackages} packages`;
  } else if (phase === "pending") {
    primaryCountLabel = "Queued for scan";
  } else if (phase === "running") {
    primaryCountLabel = "Scanning packages";
  }

  const secondaryCountLabel = totalDependencyNodes !== null ? `${totalDependencyNodes} total dependency nodes in graph` : null;

  const etaLabel =
    phase === "completed"
      ? "ETA 0s"
      : phase === "cancelled"
        ? "Cancelled"
        : phase === "running" && estimatedSecondsRemaining === null
          ? "Estimating..."
          : estimatedSecondsRemaining !== null
            ? `ETA ${formatDuration(estimatedSecondsRemaining)}`
            : phase === "pending"
              ? "Queued"
              : null;

  const speedLabel = packagesPerMinute !== null ? `${packagesPerMinute.toFixed(1)} packages/min` : null;
  const elapsedLabel = elapsedSeconds !== null ? `Elapsed ${formatDuration(elapsedSeconds)}` : null;

  return {
    phase,
    progressPercent,
    progressLabel: `${Math.round(progressPercent)}% complete`,
    primaryCountLabel,
    secondaryCountLabel,
    etaLabel,
    speedLabel,
    elapsedLabel,
    statusLabel: phase.charAt(0).toUpperCase() + phase.slice(1),
  };
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

function collectUniquePackageLabels(nodes: DependencyNode[], ecosystem: Ecosystem): string[] {
  const labels = new Set<string>();

  const walk = (node: DependencyNode) => {
    if (node.ecosystem !== ecosystem) {
      return;
    }

    labels.add(`${node.name}@${node.version}`);
    (node.children ?? []).forEach(walk);
  };

  nodes.forEach(walk);

  return Array.from(labels).sort((left, right) => left.localeCompare(right));
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
  const [scanDetails, setScanDetails] = useState<ScanJobResponse | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("graph");
  const [isHydrated, setIsHydrated] = useState(false);
  const [scanScope, setScanScope] = useState<ScanScope>("full");
  const [selectedScanPackages, setSelectedScanPackages] = useState<string[]>([]);
  const [isAgentChatOpen, setIsAgentChatOpen] = useState(true);
  const [isCancellingScan, setIsCancellingScan] = useState(false);
  const [liveElapsedSeconds, setLiveElapsedSeconds] = useState(0);
  const isMountedRef = useRef(true);
  const scanPollTimerRef = useRef<number | null>(null);
  const elapsedTickerRef = useRef<number | null>(null);
  const scanRetryAttemptRef = useRef(0);
  const liveResultKeysRef = useRef<Set<string>>(new Set());
  const repoContextRef = useRef<RepoContext | null>(null);
  const repoContextPromiseRef = useRef<Promise<RepoContext> | null>(null);
  const scanDisplay = useMemo(
    () => deriveScanDisplay(scanDetails, scanProgress, isScanRunning, scanError),
    [scanDetails, scanProgress, isScanRunning, scanError],
  );
  const hasScanStarted = isScanRunning || hasScanned || scanJobId !== null || scanDetails !== null || scanError !== null;
  const shouldShowScanRuntime = isHydrated && hasScanStarted;
  const liveFailedRowsCount = useMemo(
    () => scanResultRows.filter((row) => row.errorMessage !== null || row.status === "failed").length,
    [scanResultRows],
  );
  const canCancelScan = scanJobId !== null && (scanDisplay.phase === "pending" || scanDisplay.phase === "running");
  const availableScanPackages = useMemo(
    () => collectUniquePackageLabels(nodes, repositoryEcosystem ?? "npm"),
    [nodes, repositoryEcosystem],
  );
  const selectedScanPackageSet = useMemo(() => new Set(selectedScanPackages), [selectedScanPackages]);
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
  const toggleSelectedScanPackage = useCallback((packageLabel: string) => {
    setSelectedScanPackages((current) =>
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
    { key: "details", label: "Details" },
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
    setIsCancellingScan(false);
    setLiveElapsedSeconds(0);
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

    setLiveElapsedSeconds(normalizeLiveElapsedSeconds(scanDetails));

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
        const tokenBucket = token ? hashString(token) : null;
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

      const response = await fetch(
        `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/scan/latest/results`,
        {
          method: "GET",
          headers,
          credentials: "include",
          cache: "no-store",
        },
      );

      if (!response.ok) {
        if (cachedScanResults === null) {
          setScanResultsMap({});
        }
        return;
      }

      const payload = (await response.json()) as unknown;
      const normalized = normalizeScanResultsPayload(payload);
      setScanResultsMap(normalized.map);
      setHasScanned(normalized.rows.length > 0 || Object.keys(normalized.map).length > 0);

      const latestScanResponse = await fetch(
        `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/scan/latest`,
        {
          method: "GET",
          headers,
          credentials: "include",
          cache: "no-store",
        },
      );

      if (!latestScanResponse.ok) {
        setLatestScanSummary({
          status: null,
          processed: null,
          total: null,
          completedAt: null,
        });
      } else {
        const latestScanPayload = (await latestScanResponse.json()) as unknown;

        if (latestScanPayload === null) {
          setLatestScanSummary({
            status: null,
            processed: null,
            total: null,
            completedAt: null,
          });
        } else {
          setLatestScanSummary(normalizeLatestCompletedScan(latestScanPayload));
        }
      }

      if (scanResultsCacheKey) {
        setCachedValue(scanResultsCacheKey, normalized.map, {
          ttlMs: SCAN_RESULTS_CACHE_TTL_MS,
          scope: "both",
          maxPersistentSizeBytes: MAX_CACHE_BYTES,
        });
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
        const response = await fetch(
          `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/scan/${encodeURIComponent(jobId)}`,
          {
            method: "GET",
            headers,
            credentials: "include",
            cache: "no-store",
          },
        );

        if (!response.ok) {
          const httpError = new Error(`Could not read scan status (${response.status}).`) as Error & { status: number };
          httpError.status = response.status;
          throw httpError;
        }

        const payload = (await response.json()) as ScanJobResponse;
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
    setIsScanModalOpen(true);
    setIsScanRunning(true);
    setIsCancellingScan(false);
    setScanStatus("pending");
    setScanProgress(0);
    setLiveElapsedSeconds(0);
    setScanResultRows([]);
    liveResultKeysRef.current = new Set();
    scanRetryAttemptRef.current = 0;

    try {
      const { owner, repoName, headers, ecosystem } = await resolveRepoCoordinates();
      const token = clientSessionStorage.readToken();
      const scanResultsCacheKey = token ? buildScanResultsCacheKey(token, owner, repoName) : null;
      const selectedPackagesPayload = isPartialScan ? selectedScanPackages : undefined;
      const triggerBody: Record<string, unknown> = { ecosystem };

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

      const triggerResponse = await fetch(
        `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/scan`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...headers,
          },
          body: JSON.stringify(triggerBody),
          credentials: "include",
        },
      );

      if (!triggerResponse.ok) {
        throw new Error(`Could not trigger package scan (${triggerResponse.status}).`);
      }

      const triggerPayload = (await triggerResponse.json()) as ScanTriggerResponse;

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
  }, [isPartialScan, pollScanJob, resolveRepoCoordinates, selectedScanPackages]);

  const cancelScanJob = useCallback(async () => {
    if (!scanJobId || isCancellingScan) {
      return;
    }

    setIsCancellingScan(true);
    setScanError(null);

    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const cancelUrl = `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/scan/${encodeURIComponent(scanJobId)}/cancel`;

      const tryCancelRequest = async () => {
        const response = await fetch(cancelUrl, {
          method: "POST",
          headers,
          credentials: "include",
        });

        if (!response.ok) {
          const cancelError = new Error(`Cancel request failed (${response.status}).`) as Error & { status: number };
          cancelError.status = response.status;
          throw cancelError;
        }

        return response;
      };

      let cancelResponse: Response;
      try {
        cancelResponse = await tryCancelRequest();
      } catch (firstError) {
        const message = firstError instanceof Error ? firstError.message.toLowerCase() : "";
        const isNetworkError = message.includes("network") || message.includes("failed to fetch") || message.includes("timeout");

        if (!isNetworkError) {
          throw firstError;
        }

        cancelResponse = await tryCancelRequest();
      }

      const payload = (await cancelResponse.json()) as { status?: unknown; message?: unknown };
      const cancelledStatus = normalizeStatusValue(payload.status);

      if (scanPollTimerRef.current !== null) {
        window.clearTimeout(scanPollTimerRef.current);
        scanPollTimerRef.current = null;
      }

      setIsScanRunning(false);
      setScanStatus(cancelledStatus === "cancelled" ? "Scan cancelled by user" : "Scan cancellation acknowledged");
      setScanDetails((current) => ({
        ...(current ?? {}),
        status: "cancelled",
      }));
      setScanError(null);
    } catch (cancelError) {
      const status =
        typeof cancelError === "object" && cancelError !== null && "status" in cancelError && typeof (cancelError as { status?: unknown }).status === "number"
          ? ((cancelError as { status: number }).status)
          : null;

      if (status === 400) {
        setScanError("Cannot cancel: job already completed.");
      } else if (status === 404) {
        setScanError("Scan job not found.");
      } else {
        setScanError("Unable to cancel scan. Please try again.");
      }
    } finally {
      setIsCancellingScan(false);
    }
  }, [isCancellingScan, resolveRepoCoordinates, scanJobId]);

  useEffect(() => {
    setIsLoadingTree(true);
    void Promise.all([loadDependencyTree(), loadLatestScanResults()]);
  }, [decodedId, loadDependencyTree, loadLatestScanResults]);

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
          {sections.map((section) => (
            <button
              key={section.key}
              type="button"
              onClick={() => setActiveSection(section.key)}
              className={`border-b-2 pb-2 text-sm font-medium transition ${
                activeSection === section.key
                  ? "border-teal-500 text-teal-400"
                  : "border-transparent text-gray-400 hover:text-gray-200"
              }`}
            >
              {section.label}
            </button>
          ))}
        </div>

        <div className="relative flex-1 overflow-hidden">
          <main className="flex-1 relative h-full">
          {activeSection === "graph" ? (
            <div className="relative h-full w-full px-4 pb-0 pt-4">
              <div className="relative h-full overflow-hidden rounded-2xl border border-gray-800 bg-gray-950/90">
                <div
                  className="absolute left-4 top-4 z-10 max-w-md cursor-pointer rounded-2xl border border-gray-700/80 bg-gray-950/90 px-4 py-3 shadow-[0_18px_50px_-24px_rgba(2,6,23,0.95)] backdrop-blur"
                  role="button"
                  tabIndex={0}
                  onClick={() => setIsScanModalOpen(true)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setIsScanModalOpen(true);
                    }
                  }}
                >
                  <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Malware Package Scan</p>
                  <p className="mt-1 text-sm text-slate-400">
                    Run malware scans on all detected packages and highlight graph nodes by risk.
                  </p>
                  {shouldShowScanRuntime ? (
                    <span
                      className={`mt-2 inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${
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
                    <div className="mt-3">
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

                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      void triggerPackageScan();
                    }}
                    disabled={!canStartScan}
                    className="mt-3 inline-flex items-center rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200 transition hover:border-cyan-300 hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {scanStartLabel}
                  </button>
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

          {activeSection === "details" ? (
            <div className="flex h-full w-full items-center justify-center text-slate-300">Details content coming soon.</div>
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

      {isScanModalOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-sm">
          <div className="flex max-h-[90vh] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-[0_36px_80px_-30px_rgba(2,6,23,0.95)]">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Scan Status Details</p>
                <p className="mt-1 text-sm text-slate-300">Track malware scan progress while continuing to navigate the graph.</p>
              </div>
              <button
                type="button"
                onClick={() => setIsScanModalOpen(false)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.1em] text-slate-200 transition hover:border-slate-500"
              >
                Close
              </button>
            </div>

            <div className="mt-5 flex-1 overflow-y-auto pr-1">
              {scanError ? (
                <div className="mb-4 rounded-xl border border-rose-400/40 bg-rose-500/10 p-3 text-xs text-rose-100">
                  {scanError}
                </div>
              ) : null}

              <div className="grid gap-4 lg:grid-cols-[360px_minmax(0,1fr)]">
                <div className="space-y-4">
                  <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Current status</p>
                    <p className="mt-1 text-sm text-slate-200">{shouldShowScanRuntime ? scanDisplay.statusLabel : "Ready to start"}</p>
                    {scanJobId ? <p className="mt-2 text-xs text-slate-400">Job ID: {scanJobId}</p> : null}
                    <div className="mt-3 flex flex-wrap gap-2">
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
                      {canCancelScan ? (
                        <button
                          type="button"
                          onClick={() => {
                            void cancelScanJob();
                          }}
                          disabled={isCancellingScan}
                          className="inline-flex items-center rounded-lg border border-rose-400/40 bg-rose-500/15 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-rose-100 transition hover:bg-rose-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {isCancellingScan ? "Cancelling..." : "Cancel Scan"}
                        </button>
                      ) : null}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Scan Scope</p>
                    <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
                      <button
                        type="button"
                        onClick={() => setScanScope("full")}
                        className={`rounded-lg border px-3 py-2 text-left text-sm transition ${
                          scanScope === "full"
                            ? "border-cyan-300/60 bg-cyan-500/15 text-cyan-100"
                            : "border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500"
                        }`}
                      >
                        <span className="block font-semibold uppercase tracking-[0.12em]">Full scan</span>
                        <span className="mt-1 block text-xs text-slate-400">Scan every unique package in the tree.</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setScanScope("partial")}
                        className={`rounded-lg border px-3 py-2 text-left text-sm transition ${
                          scanScope === "partial"
                            ? "border-cyan-300/60 bg-cyan-500/15 text-cyan-100"
                            : "border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-500"
                        }`}
                      >
                        <span className="block font-semibold uppercase tracking-[0.12em]">Partial scan</span>
                        <span className="mt-1 block text-xs text-slate-400">Pick specific packages from the list or graph.</span>
                      </button>
                    </div>

                    {isPartialScan ? (
                      <div className="mt-4 space-y-3">
                        <div className="flex items-center justify-between gap-3">
                          <p className="text-xs text-slate-400">Selected {selectedScanPackages.length} of {availableScanPackages.length}</p>
                          <button
                            type="button"
                            onClick={() => setSelectedScanPackages([])}
                            className="text-xs font-medium text-cyan-200 underline decoration-cyan-400/50 underline-offset-2"
                          >
                            Clear selection
                          </button>
                        </div>

                        <div className="max-h-52 overflow-auto rounded-lg border border-slate-800 bg-slate-950/50 p-2">
                          {availableScanPackages.length === 0 ? (
                            <p className="p-2 text-xs text-slate-400">No packages available for the selected ecosystem.</p>
                          ) : (
                            <div className="grid gap-2">
                              {availableScanPackages.map((packageLabel) => {
                                const selected = selectedScanPackageSet.has(packageLabel);

                                return (
                                  <button
                                    key={packageLabel}
                                    type="button"
                                    onClick={() => toggleSelectedScanPackage(packageLabel)}
                                    className={`flex items-center justify-between rounded-md border px-3 py-2 text-left text-sm transition ${
                                      selected
                                        ? "border-cyan-300/60 bg-cyan-500/15 text-cyan-100"
                                        : "border-slate-800 bg-slate-900/40 text-slate-300 hover:border-slate-600"
                                    }`}
                                  >
                                    <span className="truncate">{packageLabel}</span>
                                    <span className="ml-3 text-[10px] uppercase tracking-[0.14em] text-slate-400">
                                      {selected ? "Selected" : "Add"}
                                    </span>
                                  </button>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : null}
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</p>
                    {shouldShowScanRuntime ? (
                      <>
                        <p className="mt-1 text-sm text-slate-200">{scanDisplay.primaryCountLabel}</p>
                        {scanDetails ? (
                          <p className="mt-1 text-xs text-slate-400">
                            Scanned {(coerceNonNegativeNumber(scanDetails.scanned_packages) ?? 0)} / {(coerceNonNegativeNumber(scanDetails.total_unique_packages) ?? 0)}
                          </p>
                        ) : null}
                        {scanDisplay.secondaryCountLabel ? <p className="mt-1 text-xs text-slate-400">{scanDisplay.secondaryCountLabel}</p> : null}
                        <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800">
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
                      <p className="mt-1 text-sm text-slate-300">Click Start scan packages to begin scanning.</p>
                    )}
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Latest Completed Scan Summary</p>
                    {latestScanSummary.status === null ? (
                      <p className="mt-2 text-xs text-slate-400">No completed scans yet.</p>
                    ) : (
                      <>
                        <p className="mt-2 text-xs text-slate-300">Status: {latestScanSummary.status}</p>
                        <p className="mt-1 text-xs text-slate-300">
                          Processed: {latestScanSummary.processed ?? "-"} / {latestScanSummary.total ?? "-"}
                        </p>
                        <p className="mt-1 text-xs text-slate-300">Completed: {formatTimestampForDisplay(latestScanSummary.completedAt)}</p>
                      </>
                    )}
                  </div>

                  <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Current Job Package Results (Live)</p>
                    {scanJobId ? (
                      <p className="mt-2 text-xs text-slate-400">
                        Rows: {scanResultRows.length} · Failed rows: {liveFailedRowsCount}
                      </p>
                    ) : (
                      <p className="mt-2 text-xs text-slate-400">Start a scan to stream live package rows from /scan/{'{'}job_id{'}'}.</p>
                    )}
                    {scanJobId && scanResultRows.length === 0 ? (
                      <p className="mt-2 text-xs text-slate-400">Waiting for first package rows from current job...</p>
                    ) : null}
                    {scanJobId && scanResultRows.length > 0 ? (
                      <div className="mt-3 max-h-[36vh] overflow-auto rounded-lg border border-slate-800">
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
                      <p className="mt-2 text-xs text-slate-400">No live rows for current job yet.</p>
                    )}
                  </div>
                </div>
              </div>

            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
