"use client";

import { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
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
};

type ScanResultMapEntry = {
  malware_status?: string;
  malware_score?: number | null;
  scan_timestamp?: string | null;
  scanner_version?: string | null;
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

const SCAN_TERMINAL_DONE = new Set(["completed", "success", "succeeded", "done"]);
const SCAN_TERMINAL_FAILED = new Set(["failed", "error", "cancelled"]);
const ALL_ECOSYSTEMS: Ecosystem[] = ["npm", "pypi"];
const SCAN_POLL_INTERVAL_MS = 2000;

type ScanPhase = "pending" | "running" | "completed" | "failed";

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

function normalizeScanPhase(status: string | undefined, isScanRunning: boolean, hasError: boolean): ScanPhase {
  if (hasError) {
    return "failed";
  }

  const normalized = typeof status === "string" ? status.trim().toLowerCase() : "";

  if (SCAN_TERMINAL_DONE.has(normalized)) {
    return "completed";
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

  if (phase === "completed") {
    return 100;
  }

  const scannedPackages = coerceNonNegativeNumber(payload.scanned_packages ?? payload.completed_packages);
  const totalUniquePackages = coerceNonNegativeNumber(payload.total_unique_packages);
  const totalPackages = coerceNonNegativeNumber(payload.total_packages);
  const denominator = totalUniquePackages && totalUniquePackages > 0 ? totalUniquePackages : totalPackages && totalPackages > 0 ? totalPackages : null;

  if (scannedPackages !== null && denominator !== null) {
    return Math.max(0, Math.min(100, (scannedPackages / denominator) * 100));
  }

  const explicitProgress = normalizeLegacyProgress(payload.progress_percent ?? payload.progress);
  if (explicitProgress !== null) {
    return explicitProgress;
  }

  if (
    typeof payload.completed_packages === "number" &&
    typeof payload.total_packages === "number" &&
    payload.total_packages > 0
  ) {
    return Math.max(0, Math.min(100, (payload.completed_packages / payload.total_packages) * 100));
  }

  if (phase === "running") {
    return fallbackProgress > 0 ? fallbackProgress : 60;
  }

  if (phase === "pending") {
    return fallbackProgress > 0 ? fallbackProgress : 0;
  }

  return fallbackProgress;
}

function deriveScanDisplay(scanDetails: ScanJobResponse | null, fallbackProgress: number, isScanRunning: boolean, scanError: string | null): ScanDisplay {
  const phase = normalizeScanPhase(scanDetails?.status, isScanRunning, scanError !== null);
  const scannedPackages = coerceNonNegativeNumber(scanDetails?.scanned_packages ?? scanDetails?.completed_packages);
  const totalUniquePackages = coerceNonNegativeNumber(scanDetails?.total_unique_packages);
  const totalDependencyNodes = coerceNonNegativeNumber(scanDetails?.total_dependency_nodes);
  const totalPackages = coerceNonNegativeNumber(scanDetails?.total_packages);
  const progressPercent = computeScanProgress(scanDetails, phase, fallbackProgress);
  const packagesPerMinute = coerceNonNegativeNumber(scanDetails?.packages_per_minute);
  const elapsedSeconds = coerceNonNegativeNumber(scanDetails?.elapsed_seconds);
  const estimatedSecondsRemaining = coerceNonNegativeNumber(scanDetails?.estimated_seconds_remaining);

  let primaryCountLabel = "No scan data yet";

  if (scannedPackages !== null && totalUniquePackages !== null) {
    primaryCountLabel = `Scanned ${scannedPackages} of ${totalUniquePackages} unique packages`;
  } else if (scannedPackages !== null && totalPackages !== null) {
    primaryCountLabel = `Scanned ${scannedPackages} of ${totalPackages} packages`;
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
      : phase === "running" && estimatedSecondsRemaining === null
        ? "Estimating…"
        : estimatedSecondsRemaining !== null
          ? `ETA ${formatDuration(estimatedSecondsRemaining)}`
          : phase === "pending"
            ? "Queued"
            : null;

  const speedLabel = packagesPerMinute !== null ? `${packagesPerMinute.toFixed(1)} packages/min` : null;
  const elapsedLabel =
    phase === "completed" && elapsedSeconds !== null
      ? `Elapsed ${formatDuration(elapsedSeconds)}`
      : phase !== "completed" && elapsedSeconds !== null
        ? `Elapsed ${formatDuration(elapsedSeconds)}`
        : null;

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

function normalizeProgress(status: string, payload: ScanJobResponse): number {
  if (typeof payload.progress === "number" && Number.isFinite(payload.progress)) {
    if (payload.progress <= 1) {
      return Math.max(0, Math.min(100, payload.progress * 100));
    }

    return Math.max(0, Math.min(100, payload.progress));
  }

  if (typeof payload.completed_packages === "number" && typeof payload.total_packages === "number" && payload.total_packages > 0) {
    return Math.max(0, Math.min(100, (payload.completed_packages / payload.total_packages) * 100));
  }

  if (SCAN_TERMINAL_DONE.has(status)) {
    return 100;
  }

  if (SCAN_TERMINAL_FAILED.has(status)) {
    return 100;
  }

  if (status === "running" || status === "in_progress") {
    return 60;
  }

  if (status === "pending" || status === "queued") {
    return 15;
  }

  return 5;
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
  const isMountedRef = useRef(true);
  const scanPollTimerRef = useRef<number | null>(null);
  const repoContextRef = useRef<RepoContext | null>(null);
  const repoContextPromiseRef = useRef<Promise<RepoContext> | null>(null);
  const scanDisplay = useMemo(
    () => deriveScanDisplay(scanDetails, scanProgress, isScanRunning, scanError),
    [scanDetails, scanProgress, isScanRunning, scanError],
  );

  const sections = [
    { key: "graph", label: "Dependency Graph" },
    { key: "details", label: "Details" },
    { key: "add", label: "Add Dependency" },
  ] as const;

  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      if (scanPollTimerRef.current !== null) {
        window.clearTimeout(scanPollTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    setNodes([]);
    setScanResultsMap({});
    setTreeError(null);
    setScanError(null);
    setIsLoadingTree(true);
    setIsScanRunning(false);
    setScanJobId(null);
    setScanProgress(0);
    setScanDetails(null);
    setScanStatus("Waiting to start malware scan.");
    setHasScanned(false);
    setRepositoryLanguage("");
    setRepositoryEcosystem(null);
    repoContextRef.current = null;
    repoContextPromiseRef.current = null;
    if (scanPollTimerRef.current !== null) {
      window.clearTimeout(scanPollTimerRef.current);
      scanPollTimerRef.current = null;
    }
  }, [decodedId]);

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
        setScanResultsMap({});
        return;
      }

      const payload = (await response.json()) as Record<string, ScanResultMapEntry>;
      setScanResultsMap(payload);
      setHasScanned(Object.keys(payload).length > 0);

      if (scanResultsCacheKey) {
        setCachedValue(scanResultsCacheKey, payload, {
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
          throw new Error(`Could not read scan status (${response.status}).`);
        }

        const payload = (await response.json()) as ScanJobResponse;
        const statusValue = typeof payload.status === "string" ? payload.status.toLowerCase() : "pending";
        const phase = normalizeScanPhase(statusValue, true, false);

        if (!isMountedRef.current) {
          return;
        }

        setScanDetails(payload);
        setScanStatus(statusValue);
        setScanProgress(computeScanProgress(payload, phase, 0));

        if (SCAN_TERMINAL_DONE.has(statusValue)) {
          setIsScanRunning(false);
          setScanStatus("Scan completed. Applying latest highlights.");
          setScanProgress(100);
          setHasScanned(true);
          await loadLatestScanResults();
          setScanStatus("Latest malware scan results loaded.");
          return;
        }

        if (SCAN_TERMINAL_FAILED.has(statusValue)) {
          setIsScanRunning(false);
          setScanError(`Package scan failed with status: ${statusValue}`);
          return;
        }

        scanPollTimerRef.current = window.setTimeout(() => {
          void pollScanJob(owner, repoName, jobId, headers);
        }, SCAN_POLL_INTERVAL_MS);
      } catch (pollError) {
        if (!isMountedRef.current) {
          return;
        }

        const message = pollError instanceof Error ? pollError.message : "Unexpected error while polling scan status.";
        setScanError(message);
        setIsScanRunning(false);
      }
    },
    [loadLatestScanResults],
  );

  const triggerPackageScan = useCallback(async () => {
    setScanError(null);
    setIsScanModalOpen(true);
    setIsScanRunning(true);
    setScanStatus("pending");
    setScanProgress(0);

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

      const triggerResponse = await fetch(
        `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/scan`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...headers,
          },
          body: JSON.stringify({ ecosystem }),
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
  }, [pollScanJob, resolveRepoCoordinates]);

  useEffect(() => {
    setIsLoadingTree(true);
    void Promise.all([loadDependencyTree(), loadLatestScanResults()]);
  }, [decodedId, loadDependencyTree, loadLatestScanResults]);

  return (
    <section className="relative flex h-[calc(100vh-64px)] w-full overflow-hidden bg-black">
      <div className="flex h-full min-w-0 flex-1 flex-col pr-80">
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
            <div className="relative h-full w-full p-4">
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
                  <p className="mt-1 text-xs text-slate-500">{scanDisplay.statusLabel}</p>

                  <div className="mt-3">
                    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full transition-all duration-300 ${scanError ? "bg-rose-400" : scanDisplay.phase === "pending" ? "animate-pulse bg-cyan-300/90" : "bg-cyan-400"}`}
                        style={{ width: `${Math.max(0, Math.min(100, scanDisplay.phase === "pending" ? 34 : scanDisplay.progressPercent))}%` }}
                      />
                    </div>
                    <p className="mt-1 text-[11px] uppercase tracking-[0.12em] text-slate-500">{scanDisplay.progressLabel}</p>
                    <p className="mt-1 text-xs text-slate-400">{scanDisplay.primaryCountLabel}</p>
                    {scanDisplay.secondaryCountLabel ? <p className="mt-1 text-xs text-slate-500">{scanDisplay.secondaryCountLabel}</p> : null}
                    <div className="mt-2 flex flex-wrap gap-3 text-[11px] uppercase tracking-[0.12em] text-slate-500">
                      {scanDisplay.etaLabel ? <span>{scanDisplay.etaLabel}</span> : null}
                      {scanDisplay.speedLabel ? <span>{scanDisplay.speedLabel}</span> : null}
                      {scanDisplay.elapsedLabel ? <span>{scanDisplay.elapsedLabel}</span> : null}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      void triggerPackageScan();
                    }}
                    disabled={isScanRunning}
                    className="mt-3 inline-flex items-center rounded-lg border border-cyan-400/40 bg-cyan-500/15 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200 transition hover:border-cyan-300 hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {isScanRunning ? "Scanning packages..." : "Scan packages"}
                  </button>
                </div>

                <div className="absolute inset-0 h-full w-full">
                  <DependencyTree nodes={nodes} ecosystem={repositoryEcosystem ?? "npm"} scanResultsMap={scanResultsMap} />
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
            <div className="flex h-full w-full items-center justify-center text-slate-300">Add Dependency content coming soon.</div>
          ) : null}
          </main>
        </div>
      </div>

      <aside className="absolute inset-y-0 right-0 w-80 border-l border-gray-800 bg-gray-950/80 flex flex-col h-full">
        <div className="border-b border-gray-800 px-4 py-4">
          <div className="flex items-center gap-2">
            <div className="h-8 w-8 rounded-lg border border-cyan-300/40 bg-cyan-500/20 text-cyan-200 grid place-items-center text-sm font-bold">
              AI
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-100">SentinelFlow Agent</p>
              <p className="text-xs text-slate-400">Repository assistant</p>
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm text-slate-300">
            Ask me about dependencies, risk signals, or what to patch first.
          </div>
          <div className="rounded-xl border border-cyan-400/25 bg-cyan-500/10 p-3 text-sm text-cyan-100">
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

      {isScanModalOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-sm">
          <div className="w-full max-w-2xl rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-[0_36px_80px_-30px_rgba(2,6,23,0.95)]">
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

            <div className="mt-5 space-y-4">
              <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Current status</p>
                <p className="mt-1 text-sm text-slate-200">{scanDisplay.statusLabel}</p>
                {scanJobId ? <p className="mt-2 text-xs text-slate-400">Job ID: {scanJobId}</p> : null}
                {scanError ? <p className="mt-2 text-xs text-rose-300">{scanError}</p> : null}
              </div>

              <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</p>
                <p className="mt-1 text-sm text-slate-200">{scanDisplay.primaryCountLabel}</p>
                {scanDisplay.secondaryCountLabel ? <p className="mt-1 text-xs text-slate-400">{scanDisplay.secondaryCountLabel}</p> : null}
                <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full rounded-full transition-all duration-300 ${scanError ? "bg-rose-400" : scanDisplay.phase === "pending" ? "animate-pulse bg-cyan-300/90" : "bg-cyan-400"}`}
                    style={{ width: `${Math.max(0, Math.min(100, scanDisplay.phase === "pending" ? 34 : scanDisplay.progressPercent))}%` }}
                  />
                </div>
                <p className="mt-2 text-xs text-slate-400">{scanDisplay.progressLabel}</p>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-slate-400">
                  {scanDisplay.etaLabel ? <span>{scanDisplay.etaLabel}</span> : null}
                  {scanDisplay.speedLabel ? <span>{scanDisplay.speedLabel}</span> : null}
                  {scanDisplay.elapsedLabel ? <span>{scanDisplay.elapsedLabel}</span> : null}
                </div>
                {scanError ? <p className="mt-2 text-xs text-rose-300">{scanError}</p> : null}
              </div>

              <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Timestamps</p>
                <p className="mt-2 text-xs text-slate-300">Started: {scanDetails?.started_at ?? "-"}</p>
                <p className="mt-1 text-xs text-slate-300">Completed: {scanDetails?.completed_at ?? "-"}</p>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
