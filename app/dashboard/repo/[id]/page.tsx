"use client";

import { use, useEffect, useMemo, useState } from "react";
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
      <p className="mt-5 text-sm text-slate-300">Loading lockfile and building dependency tree...</p>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-2xl border border-rose-300/30 bg-rose-500/10 p-6 text-rose-100 shadow-[0_24px_70px_-42px_rgba(251,113,133,0.85)]">
      <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-rose-200">Dependency Tree Unavailable</p>
      <p className="mt-3 text-sm leading-relaxed text-rose-100/90">{message}</p>
    </div>
  );
}

export default function RepoDetailsPage({ params }: RepoDetailsPageProps) {
  const resolvedParams = use(params);
  const decodedId = useMemo(() => decodeURIComponent(resolvedParams.id), [resolvedParams.id]);
  const [nodes, setNodes] = useState<DependencyNode[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeSection, setActiveSection] = useState("graph");

  const sections = [
    { key: "graph", label: "Dependency Graph" },
    { key: "scan", label: "Scan Components" },
    { key: "details", label: "Details" },
    { key: "add", label: "Add Dependency" },
  ] as const;

  useEffect(() => {
    let isActive = true;

    const loadTree = async () => {
      setIsLoading(true);
      setError(null);

      if (!API_BASE_URL) {
        if (isActive) {
          setError("Missing NEXT_PUBLIC_API_URL configuration.");
          setIsLoading(false);
        }
        return;
      }

      const token = readToken();
      const [candidateOwner, candidateRepo] = decodedId.includes("/")
        ? decodedId.split("/", 2)
        : [null, decodedId];

      let owner = candidateOwner;

      if (!owner) {
        if (!token) {
          if (isActive) {
            setError("Could not resolve repository owner because no session token is available.");
            setIsLoading(false);
          }
          return;
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
          if (isActive) {
            setError("Unable to resolve authenticated owner for this repository.");
            setIsLoading(false);
          }
          return;
        }

        const userPayload = (await meResponse.json()) as UserPayload;
        owner = normalizeOwner(userPayload);

        if (!owner && isActive) {
          setError("Authenticated session did not return a valid GitHub owner.");
          setIsLoading(false);
          return;
        }
      }

      const safeOwner = owner;
      const safeRepoName = candidateRepo ?? decodedId;

      if (!safeOwner) {
        if (isActive) {
          setError("Could not resolve repository owner.");
          setIsLoading(false);
        }
        return;
      }

      const headers: HeadersInit = token
        ? {
            Authorization: `Bearer ${token}`,
          }
        : {};

      const treeResponse = await fetch(
        `${API_BASE_URL}/api/repos/${encodeURIComponent(safeOwner)}/${encodeURIComponent(safeRepoName)}/dependencies/npm`,
        {
          method: "GET",
          headers,
          credentials: "include",
          cache: "no-store",
        }
      );

      if (!treeResponse.ok) {
        if (!isActive) {
          return;
        }

        if (treeResponse.status === 404) {
          setError("This repository does not appear to be a Node.js project.");
        } else {
          setError(`Could not load dependency tree (${treeResponse.status}).`);
        }
        setIsLoading(false);
        return;
      }

      const payload = await treeResponse.json();
      const normalized = normalizeDependencyTree(payload);

      if (isActive) {
        setNodes(normalized);
        setIsLoading(false);
      }
    };

    loadTree().catch((loadError: unknown) => {
      if (!isActive) {
        return;
      }

      const message = loadError instanceof Error ? loadError.message : "Unexpected error while loading dependencies.";
      setError(message);
      setIsLoading(false);
    });

    return () => {
      isActive = false;
    };
  }, [decodedId]);

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
            <>
              {!isLoading && !error ? (
                <div className="absolute inset-0 w-full h-full">
                  <DependencyTree nodes={nodes} ecosystem="npm" />
                </div>
              ) : null}

              {isLoading ? (
                <div className="absolute inset-0 flex items-center justify-center p-8">
                  <LoadingState />
                </div>
              ) : null}

              {!isLoading && error ? (
                <div className="absolute inset-0 flex items-center justify-center p-8">
                  <ErrorState message={error} />
                </div>
              ) : null}
            </>
          ) : null}

          {activeSection === "scan" ? (
            <div className="flex h-full w-full items-center justify-center text-slate-300">Scan Components content coming soon.</div>
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
            Tip: "Highlight outdated transitive packages with known CVEs."
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
    </section>
  );
}
