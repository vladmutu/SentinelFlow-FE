"use client";

import { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DependencyTree } from "@/app/components/dependency-tree";
import { DependencyNode } from "@/app/types/dashboard";

const TOKEN_STORAGE_KEY = "sentinel_token";
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL;

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

const SCAN_TERMINAL_DONE = new Set(["completed", "success", "succeeded", "done"]);
const SCAN_TERMINAL_FAILED = new Set(["failed", "error", "cancelled"]);

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

function readToken() {
  if (typeof window === "undefined") {
    return null;
  }

  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

function normalizeChildren(input: unknown): DependencyNode[] {
  if (Array.isArray(input)) {
    return input
      .map((child) => normalizeNode(undefined, child))
      .filter((child): child is DependencyNode => child !== null);
  }

  if (input && typeof input === "object") {
    return Object.entries(input as Record<string, unknown>)
      .map(([name, child]) => normalizeNode(name, child))
      .filter((child): child is DependencyNode => child !== null);
  }

  return [];
}

function normalizeNode(nameHint: string | undefined, input: unknown): DependencyNode | null {
  if (!input || typeof input !== "object") {
    if (!nameHint) {
      return null;
    }

    return {
      name: nameHint,
      version: typeof input === "string" ? input : "unknown",
      ecosystem: "npm",
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

  const children = normalizeChildren(record.children ?? record.dependencies ?? []);

  return {
    name,
    version,
    ecosystem: "npm",
    children,
  };
}

function normalizeDependencyTree(payload: unknown): DependencyNode[] {
  if (Array.isArray(payload)) {
    return payload
      .map((node) => normalizeNode(undefined, node))
      .filter((node): node is DependencyNode => node !== null);
  }

  if (!payload || typeof payload !== "object") {
    return [];
  }

  const record = payload as Record<string, unknown>;

  if (record.tree) {
    return normalizeDependencyTree(record.tree);
  }

  if (record.nodes) {
    return normalizeDependencyTree(record.nodes);
  }

  if (record.dependencies) {
    return normalizeChildren(record.dependencies);
  }

  const rootNode = normalizeNode(undefined, payload);
  return rootNode ? [rootNode] : [];
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

function LoadingState() {
  return (
    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/65 p-6">
      <div className="space-y-3">
        <div className="h-5 w-52 animate-pulse rounded bg-slate-700/70" />
        <div className="h-4 w-full animate-pulse rounded bg-slate-800/80" />
        <div className="h-4 w-5/6 animate-pulse rounded bg-slate-800/80" />
        <div className="h-4 w-2/3 animate-pulse rounded bg-slate-800/80" />
      </div>
      <p className="mt-5 text-sm text-slate-300">Scanning installed packages for malware and building the dependency graph...</p>
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
    setIsLoadingTree(false);
    setIsScanRunning(false);
    setScanJobId(null);
    setScanProgress(0);
    setScanDetails(null);
    setScanStatus("Waiting to start malware scan.");
    setHasScanned(false);
    if (scanPollTimerRef.current !== null) {
      window.clearTimeout(scanPollTimerRef.current);
      scanPollTimerRef.current = null;
    }
  }, [decodedId]);

  const resolveRepoCoordinates = useCallback(async (): Promise<RepoCoordinates> => {
    if (!API_BASE_URL) {
      throw new Error("Missing NEXT_PUBLIC_API_URL configuration.");
    }

    const token = readToken();
    const [candidateOwner, candidateRepo] = decodedId.includes("/")
      ? decodedId.split("/", 2)
      : [null, decodedId];

    let owner = candidateOwner;

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

    return {
      owner: safeOwner,
      repoName: safeRepoName,
      headers,
    };
  }, [decodedId]);

  const loadDependencyTree = useCallback(async () => {
    setIsLoadingTree(true);

    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();

      const treeResponse = await fetch(
        `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/dependencies/npm`,
        {
          method: "GET",
          headers,
          credentials: "include",
          cache: "no-store",
        }
      );

      if (!treeResponse.ok) {
        if (treeResponse.status === 404) {
          throw new Error("This repository does not appear to be a Node.js project.");
        }

        throw new Error(`Could not load dependency tree (${treeResponse.status}).`);
      }

      const payload = await treeResponse.json();
      const normalized = normalizeDependencyTree(payload);

      if (isMountedRef.current) {
        setNodes(normalized);
      }
    } catch (loadError) {
      if (!isMountedRef.current) {
        return;
      }

      const message = loadError instanceof Error ? loadError.message : "Unexpected error while loading dependencies.";
      setTreeError(message);
    } finally {
      if (isMountedRef.current) {
        setIsLoadingTree(false);
      }
    }
  }, [resolveRepoCoordinates]);

  const loadLatestScanResults = useCallback(async () => {
    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
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
    } catch {
      setScanResultsMap({});
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
        const statusValue = typeof payload.status === "string" ? payload.status.toLowerCase() : "unknown";

        if (!isMountedRef.current) {
          return;
        }

        setScanDetails(payload);
        setScanStatus(`Scan status: ${statusValue}`);
        setScanProgress(normalizeProgress(statusValue, payload));

        if (SCAN_TERMINAL_DONE.has(statusValue)) {
          setIsScanRunning(false);
          setScanStatus("Scan completed. Applying latest highlights.");
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
        }, 2000);
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
    setScanStatus("Starting package malware scan...");
    setScanProgress(5);

    try {
      const { owner, repoName, headers } = await resolveRepoCoordinates();
      const triggerResponse = await fetch(
        `${API_BASE_URL}/api/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/scan`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...headers,
          },
          body: JSON.stringify({ ecosystem: "npm" }),
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
      setScanStatus(`Scan job created: ${triggerPayload.job_id}`);

      if (scanPollTimerRef.current !== null) {
        window.clearTimeout(scanPollTimerRef.current);
      }

      scanPollTimerRef.current = window.setTimeout(() => {
        void pollScanJob(owner, repoName, triggerPayload.job_id, headers);
      }, 1000);
    } catch (scanError) {
      const message = scanError instanceof Error ? scanError.message : "Unexpected error while running package scan.";
      setScanError(message);
      setScanStatus("Package scan failed.");
      setScanProgress(100);
      setHasScanned(false);
    } finally {
      if (!scanPollTimerRef.current) {
        setIsScanRunning(false);
      }
    }
  }, [pollScanJob, resolveRepoCoordinates]);

  useEffect(() => {
    void Promise.all([loadDependencyTree(), loadLatestScanResults()]);
  }, [loadDependencyTree, loadLatestScanResults]);

  return (
    <section className="relative flex h-[calc(100vh-64px)] w-full overflow-hidden bg-black">
      <div className="flex h-full min-w-0 flex-1 flex-col pr-80">
        <header className="border-b border-gray-800 bg-gray-950 px-6 py-4">
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Repository</p>
          <h1 className="mt-1 line-clamp-1 text-2xl font-semibold text-slate-100">{decodedId}</h1>
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
                  <p className="mt-1 text-xs text-slate-500">{scanStatus}</p>

                  <div className="mt-3">
                    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full transition-all duration-300 ${scanError ? "bg-rose-400" : "bg-cyan-400"}`}
                        style={{ width: `${Math.max(0, Math.min(100, scanProgress))}%` }}
                      />
                    </div>
                    <p className="mt-1 text-[11px] uppercase tracking-[0.12em] text-slate-500">{Math.round(scanProgress)}% complete</p>
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
                  <DependencyTree nodes={nodes} ecosystem="npm" scanResultsMap={scanResultsMap} />
                </div>

                {!hasScanned && !isLoadingTree && !treeError ? (
                  <div className="pointer-events-none absolute inset-0 flex items-end justify-start p-4 text-slate-300">
                    <div className="max-w-sm rounded-2xl border border-slate-700/80 bg-slate-950/70 px-4 py-3 text-sm leading-relaxed backdrop-blur">
                      The graph canvas is ready. Run a package malware scan to populate the tree.
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
                <p className="mt-1 text-sm text-slate-200">{scanStatus}</p>
                {scanJobId ? <p className="mt-2 text-xs text-slate-400">Job ID: {scanJobId}</p> : null}
                {scanError ? <p className="mt-2 text-xs text-rose-300">{scanError}</p> : null}
              </div>

              <div className="rounded-xl border border-slate-700 bg-slate-950/70 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-400">Progress</p>
                <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full rounded-full transition-all duration-300 ${scanError ? "bg-rose-400" : "bg-cyan-400"}`}
                    style={{ width: `${Math.max(0, Math.min(100, scanProgress))}%` }}
                  />
                </div>
                <p className="mt-2 text-xs text-slate-400">{Math.round(scanProgress)}%</p>
                {typeof scanDetails?.completed_packages === "number" && typeof scanDetails?.total_packages === "number" ? (
                  <p className="mt-2 text-xs text-slate-400">
                    {scanDetails.completed_packages}/{scanDetails.total_packages} packages processed
                  </p>
                ) : null}
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
