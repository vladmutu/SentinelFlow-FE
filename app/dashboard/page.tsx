"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

const TOKEN_STORAGE_KEY = "sentinel_token";
const SESSION_ENDPOINT = "http://localhost:8000/api/auth/me";
const REPOS_ENDPOINT = "http://localhost:8000/api/repos";
const GITHUB_APP_NAME = process.env.NEXT_PUBLIC_GITHUB_APP_NAME;
const GITHUB_INSTALLATION_URL = `https://github.com/apps/${GITHUB_APP_NAME}/installations/new`;

type DashboardUser = {
  login: string;
  avatarUrl: string | null;
};

type RepositoryItem = {
  id: string;
  name: string;
  visibility: "public" | "private";
  description: string;
  language: string;
};

type DashboardState = {
  user: DashboardUser | null;
  repos: RepositoryItem[];
  isLoading: boolean;
  error: string | null;
};

type UserApiPayload = {
  username?: unknown;
  login?: unknown;
  avatar_url?: unknown;
  user?: {
    username?: unknown;
    login?: unknown;
    avatar_url?: unknown;
  };
};

type RepoApiPayload = {
  id?: unknown;
  node_id?: unknown;
  full_name?: unknown;
  name?: unknown;
  private?: unknown;
  visibility?: unknown;
  description?: unknown;
  language?: unknown;
};

type ReposResponsePayload = RepoApiPayload[] | { repos?: RepoApiPayload[] };

const tokenStorage = {
  read() {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  },
  save(token: string) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
  },
  clear() {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  },
};

function normalizeUser(payload: UserApiPayload): DashboardUser {
  const source = payload.user ?? payload;
  const login =
    typeof source.username === "string" && source.username.length > 0
      ? source.username
      : typeof source.login === "string" && source.login.length > 0
        ? source.login
        : "unknown-user";
  const avatarUrl = typeof source.avatar_url === "string" && source.avatar_url.length > 0 ? source.avatar_url : null;

  return { login, avatarUrl };
}

function toRepositoryItem(payload: RepoApiPayload, index: number): RepositoryItem {
  const idSource = payload.id ?? payload.node_id;
  const id = typeof idSource === "number" || typeof idSource === "string" ? String(idSource) : `repo-${index}`;
  const fallbackName = `repository-${index + 1}`;
  const name =
    typeof payload.name === "string" && payload.name.length > 0
      ? payload.name
      : typeof payload.full_name === "string" && payload.full_name.length > 0
        ? payload.full_name
        : fallbackName;
  const description = typeof payload.description === "string" ? payload.description : "No description provided.";
  const language = typeof payload.language === "string" && payload.language.length > 0 ? payload.language : "Unknown";

  const visibility =
    payload.visibility === "private" || payload.private === true
      ? "private"
      : "public";

  return {
    id,
    name,
    visibility,
    description,
    language,
  };
}

function normalizeRepos(payload: ReposResponsePayload): RepositoryItem[] {
  const source = Array.isArray(payload) ? payload : Array.isArray(payload.repos) ? payload.repos : [];
  return source.map((repo, index) => toRepositoryItem(repo, index));
}

function LoadingSkeleton() {
  return (
    <div className="mx-auto w-full max-w-7xl space-y-6">
      <div className="h-16 animate-pulse rounded-2xl border border-slate-700/70 bg-slate-900/60" />
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={`skeleton-${index}`} className="space-y-4 rounded-2xl border border-slate-700/70 bg-slate-900/50 p-5">
            <div className="h-5 w-2/3 animate-pulse rounded bg-slate-700/80" />
            <div className="h-4 w-1/3 animate-pulse rounded bg-slate-800/90" />
            <div className="h-3 w-full animate-pulse rounded bg-slate-800/70" />
            <div className="h-3 w-5/6 animate-pulse rounded bg-slate-800/70" />
            <div className="h-10 w-full animate-pulse rounded-xl bg-cyan-500/20" />
          </div>
        ))}
      </div>
    </div>
  );
}

function DashboardHeader({
  user,
  installUrl,
  onRefresh,
}: {
  user: DashboardUser;
  installUrl: string;
  onRefresh: () => void;
}) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-slate-700/80 bg-slate-900/70 px-5 py-4 shadow-[0_12px_40px_-18px_rgba(8,145,178,0.7)] backdrop-blur">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-300/40 bg-cyan-400/15 text-sm font-black tracking-wider text-cyan-200">
          SF
        </div>
        <div>
          <p className="text-[11px] uppercase tracking-[0.24em] text-cyan-300">SentinelFlow</p>
          <p className="text-lg font-semibold text-slate-100">Project Dependency Manager</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2">
        <button
          type="button"
          onClick={onRefresh}
          className="inline-flex items-center rounded-lg border border-slate-600 bg-slate-800/70 px-3 py-2 text-xs font-semibold uppercase tracking-[0.1em] text-slate-200 transition hover:border-emerald-300/60 hover:text-emerald-100"
        >
          Refresh
        </button>

        <a
          href={installUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center rounded-lg border border-slate-600 bg-slate-800/70 px-3 py-2 text-xs font-semibold uppercase tracking-[0.1em] text-slate-200 transition hover:border-cyan-300/60 hover:text-cyan-100"
        >
          Manage Repository Access
        </a>

        <div className="flex items-center gap-3 rounded-xl border border-slate-700 bg-slate-900/80 px-3 py-2">
          {user.avatarUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={user.avatarUrl} alt={`${user.login} avatar`} className="h-9 w-9 rounded-full border border-cyan-300/40" />
          ) : (
            <div className="flex h-9 w-9 items-center justify-center rounded-full border border-slate-600 bg-slate-800 text-xs font-semibold text-slate-200">
              {user.login.slice(0, 1).toUpperCase()}
            </div>
          )}
          <p className="text-sm font-semibold text-slate-100">@{user.login}</p>
        </div>
      </div>
    </header>
  );
}

function RepositoryCard({ repo }: { repo: RepositoryItem }) {
  const repoUrl = `/dashboard/repo/${encodeURIComponent(repo.name)}`;

  return (
    <Link href={repoUrl} className="block">
      <article className="group rounded-2xl border border-slate-700/70 bg-slate-900/55 p-5 transition duration-200 hover:-translate-y-0.5 hover:border-cyan-300/45 hover:bg-slate-900/85 hover:shadow-[0_18px_36px_-24px_rgba(34,211,238,0.85)]">
        <div className="flex items-start justify-between gap-3">
          <h2 className="line-clamp-1 text-lg font-semibold text-slate-100">{repo.name}</h2>
          <span
            className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${
              repo.visibility === "private"
                ? "border-amber-300/35 bg-amber-400/10 text-amber-200"
                : "border-emerald-300/35 bg-emerald-400/10 text-emerald-200"
            }`}
          >
            {repo.visibility === "private" ? "Private" : "Public"}
          </span>
        </div>

        <p className="mt-3 line-clamp-3 min-h-[4.3rem] text-sm leading-relaxed text-slate-300">{repo.description}</p>

        <div className="mt-5 flex items-center justify-between">
          <p className="rounded-full border border-slate-700 bg-slate-900/90 px-2.5 py-1 text-xs font-medium text-slate-300">
            {repo.language}
          </p>
          <span className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300/90 transition group-hover:text-cyan-200">
            Open Details
          </span>
        </div>
      </article>
    </Link>
  );
}

function EmptyRepositoriesState({ installUrl }: { installUrl: string }) {
  return (
    <div className="rounded-2xl border border-cyan-300/30 bg-cyan-500/10 p-8 text-center shadow-[0_24px_80px_-40px_rgba(34,211,238,0.9)]">
      <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">No Connected Repositories</p>
      <h2 className="mt-3 font-['Rajdhani',_Space_Grotesk,_sans-serif] text-3xl font-bold text-slate-100">
        Install SentinelFlow On Your GitHub Repositories
      </h2>
      <p className="mx-auto mt-3 max-w-2xl text-slate-300">
        You are authenticated, but SentinelFlow does not currently have repository access. Select repositories to begin dependency scanning.
      </p>
      <a
        href={installUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="mt-6 inline-flex items-center justify-center rounded-xl border border-cyan-200/70 bg-cyan-400/20 px-6 py-3 text-sm font-semibold tracking-wide text-cyan-100 transition hover:bg-cyan-400/30 hover:text-white"
      >
        Select Repositories to Scan
      </a>
    </div>
  );
}

function UnauthorizedPanel() {
  return (
    <div className="mx-auto w-full max-w-2xl rounded-2xl border border-rose-300/20 bg-slate-900/70 p-8 shadow-[0_20px_60px_-24px_rgba(15,23,42,0.9)] backdrop-blur">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-rose-300">Unauthorized</p>
      <h2 className="mt-3 text-2xl font-semibold text-slate-100">Authentication required</h2>
      <p className="mt-3 text-slate-300">Your session token is missing or invalid. Please sign in again.</p>
      <Link
        href="/"
        className="mt-6 inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/70 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-cyan-300/60 hover:bg-slate-700"
      >
        Return to home
      </Link>
    </div>
  );
}

function ErrorPanel({ message }: { message: string }) {
  return (
    <div className="mx-auto w-full max-w-3xl rounded-2xl border border-rose-300/20 bg-slate-900/70 p-8 shadow-[0_20px_60px_-24px_rgba(15,23,42,0.9)] backdrop-blur">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-rose-300">Data load failed</p>
      <h2 className="mt-3 text-2xl font-semibold text-slate-100">Unable to load repositories</h2>
      <p className="mt-3 text-slate-300">{message}</p>
    </div>
  );
}

function useDashboardData() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [state, setState] = useState<DashboardState>({
    user: null,
    repos: [],
    isLoading: true,
    error: null,
  });
  const [isUnauthorized, setIsUnauthorized] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);

  const tokenFromQuery = useMemo(() => searchParams.get("token"), [searchParams]);

  useEffect(() => {
    let isActive = true;

    const loadDashboardData = async () => {
      const effectiveToken = tokenFromQuery ?? tokenStorage.read();

      if (tokenFromQuery) {
        tokenStorage.save(tokenFromQuery);
        router.replace("/dashboard");
      }

      if (!effectiveToken) {
        if (isActive) {
          setIsUnauthorized(true);
          setState((current) => ({ ...current, isLoading: false }));
        }
        return;
      }

      try {
        const meResponse = await fetch(SESSION_ENDPOINT, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${effectiveToken}`,
          },
          cache: "no-store",
        });

        if (!meResponse.ok) {
          throw new Error(`Session invalid (${meResponse.status})`);
        }

        const mePayload = (await meResponse.json()) as UserApiPayload;

        const reposResponse = await fetch(REPOS_ENDPOINT, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${effectiveToken}`,
          },
          cache: "no-store",
        });

        if (!reposResponse.ok) {
          throw new Error(`Repository fetch failed (${reposResponse.status})`);
        }

        const reposPayload = (await reposResponse.json()) as ReposResponsePayload;

        if (!isActive) {
          return;
        }

        setState({
          user: normalizeUser(mePayload),
          repos: normalizeRepos(reposPayload),
          isLoading: false,
          error: null,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unexpected error while loading dashboard data.";

        const invalidSession = message.includes("Session invalid") || message.includes("401");

        if (invalidSession) {
          tokenStorage.clear();
        }

        if (!isActive) {
          return;
        }

        if (invalidSession) {
          setIsUnauthorized(true);
          setState((current) => ({ ...current, isLoading: false }));
          router.push("/");
          return;
        }

        setState((current) => ({
          ...current,
          isLoading: false,
          error: message,
        }));
      }
    };

    void loadDashboardData();

    return () => {
      isActive = false;
    };
  }, [refreshNonce, router, tokenFromQuery]);

  useEffect(() => {
    const handleWindowFocus = () => {
      setRefreshNonce((current) => current + 1);
    };

    window.addEventListener("focus", handleWindowFocus);

    return () => {
      window.removeEventListener("focus", handleWindowFocus);
    };
  }, []);

  return {
    user: state.user,
    repos: state.repos,
    isLoading: state.isLoading,
    error: state.error,
    isUnauthorized,
    refresh: () => setRefreshNonce((current) => current + 1),
  };
}

function DashboardPanel({
  user,
  repos,
  onRefresh,
}: {
  user: DashboardUser;
  repos: RepositoryItem[];
  onRefresh: () => void;
}) {
  const hasRepos = repos.length > 0;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6">
      <DashboardHeader user={user} installUrl={GITHUB_INSTALLATION_URL} onRefresh={onRefresh} />

      <section className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-400">Connected Repositories</p>
        <h1 className="font-['Rajdhani',_Space_Grotesk,_sans-serif] text-4xl font-bold tracking-tight text-slate-100">
          Dependency Risk Surface
        </h1>
      </section>

      {hasRepos ? (
        <section className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          {repos.map((repo) => (
            <RepositoryCard key={repo.id} repo={repo} />
          ))}
        </section>
      ) : (
        <EmptyRepositoriesState installUrl={GITHUB_INSTALLATION_URL} />
      )}
    </div>
  );
}

function DashboardAuthGate() {
  const { user, repos, isLoading, error, isUnauthorized, refresh } = useDashboardData();

  if (isLoading) {
    return <LoadingSkeleton />;
  }

  if (isUnauthorized) {
    return <UnauthorizedPanel />;
  }

  if (error) {
    return <ErrorPanel message={error} />;
  }

  if (!user) {
    return <UnauthorizedPanel />;
  }

  return <DashboardPanel user={user} repos={repos} onRefresh={refresh} />;
}

export default function DashboardPage() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-slate-950 px-6 py-16 text-slate-100 sm:px-10">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_10%,rgba(6,182,212,0.2),transparent_35%),radial-gradient(circle_at_80%_20%,rgba(16,185,129,0.18),transparent_40%),linear-gradient(120deg,rgba(2,6,23,1)_0%,rgba(3,7,18,1)_48%,rgba(2,6,23,1)_100%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(148,163,184,0.06)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.06)_1px,transparent_1px)] bg-[size:36px_36px] opacity-30" />
      <section className="relative reveal-up">
        <Suspense
          fallback={
            <div className="mx-auto flex w-full max-w-2xl items-center justify-center rounded-2xl border border-slate-700 bg-slate-900/70 p-8 text-slate-300">
              Preparing dashboard...
            </div>
          }
        >
          <DashboardAuthGate />
        </Suspense>
      </section>
    </main>
  );
}
