"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Ecosystem } from "@/app/types/dashboard";
import {
  createDependencyIdempotencyKey,
  createDependencyPr as createDependencyPrApi,
  DependencyApiError,
  fetchPackageVersions as fetchPackageVersionsApi,
  mapDependencyApiError,
  type CreateDependencyPrRequest,
  type CreateDependencyPrResponse,
  type DependencyDraft,
  type PackageSearchResult,
  searchPackages as searchPackagesApi,
} from "@/app/lib/api/dependency-pr";
import { checkDependencyCompatibility, type CompatibilityCheckResponse } from "@/app/lib/api/scan-api";

type RepoCoordinates = {
  owner: string;
  repoName: string;
  headers: HeadersInit;
};

type DependencyApiClient = {
  searchPackages: typeof searchPackagesApi;
  fetchPackageVersions: typeof fetchPackageVersionsApi;
  createDependencyPr: typeof createDependencyPrApi;
};

type SelectionEntry = {
  name: string;
  version: string;
  suspected: boolean;
};

interface AddDependencyPanelProps {
  apiBaseUrl?: string;
  initialEcosystem: Ecosystem;
  allowedEcosystems?: Ecosystem[];
  resolveRepoCoordinates: () => Promise<RepoCoordinates>;
  className?: string;
  client?: DependencyApiClient;
}

const SEARCH_DEBOUNCE_MS = 300;
const SEARCH_PAGE_SIZE = 8;

const defaultDependencyApiClient: DependencyApiClient = {
  searchPackages: searchPackagesApi,
  fetchPackageVersions: fetchPackageVersionsApi,
  createDependencyPr: createDependencyPrApi,
};

function getTyposquatSeverity(confidence: number): "high" | "medium" {
  return confidence >= 0.75 ? "high" : "medium";
}

function normalizeVersionForEcosystem(ecosystem: Ecosystem, value: string): string {
  const trimmed = value.trim();

  if (ecosystem === "pypi") {
    return trimmed.replace(/^=+/, "");
  }

  return trimmed;
}

function formatPackageVersion(version: string | null): string {
  return version ?? "Version unavailable";
}

function formatMonthlyDownloads(monthlyDownloads: number | null): string {
  if (monthlyDownloads === null) {
    return "N/A";
  }

  return `${new Intl.NumberFormat("en-US").format(monthlyDownloads)} / month`;
}

function mergeSearchResults(existing: PackageSearchResult[], incoming: PackageSearchResult[]): PackageSearchResult[] {
  const seenNames = new Set(existing.map((item) => item.name));
  const merged = [...existing];

  incoming.forEach((item) => {
    if (seenNames.has(item.name)) {
      return;
    }

    seenNames.add(item.name);
    merged.push(item);
  });

  return merged;
}

function levenshteinDistance(source: string, target: string): number {
  if (source === target) {
    return 0;
  }

  if (source.length === 0) {
    return target.length;
  }

  if (target.length === 0) {
    return source.length;
  }

  const matrix: number[][] = Array.from({ length: source.length + 1 }, () => Array(target.length + 1).fill(0));

  for (let row = 0; row <= source.length; row += 1) {
    matrix[row][0] = row;
  }

  for (let column = 0; column <= target.length; column += 1) {
    matrix[0][column] = column;
  }

  for (let row = 1; row <= source.length; row += 1) {
    for (let column = 1; column <= target.length; column += 1) {
      const substitutionCost = source[row - 1] === target[column - 1] ? 0 : 1;
      matrix[row][column] = Math.min(
        matrix[row - 1][column] + 1,
        matrix[row][column - 1] + 1,
        matrix[row - 1][column - 1] + substitutionCost,
      );
    }
  }

  return matrix[source.length][target.length];
}

function findDidYouMeanCandidate(
  suspect: PackageSearchResult,
  query: string,
  results: PackageSearchResult[],
): PackageSearchResult | null {
  const safeCandidates = results.filter((candidate) => {
    if (candidate.name === suspect.name) {
      return false;
    }

    if (candidate.typosquat.is_suspected) {
      return false;
    }

    const candidateDistance = levenshteinDistance(query.toLowerCase(), candidate.name.toLowerCase());
    return candidateDistance <= 2;
  });

  if (safeCandidates.length === 0) {
    return null;
  }

  const sorted = safeCandidates.sort((left, right) => {
    const leftDistance = levenshteinDistance(query.toLowerCase(), left.name.toLowerCase());
    const rightDistance = levenshteinDistance(query.toLowerCase(), right.name.toLowerCase());

    if (leftDistance !== rightDistance) {
      return leftDistance - rightDistance;
    }

    return (right.score ?? 0) - (left.score ?? 0);
  });

  return sorted[0] ?? null;
}

function SearchResultSkeletonCard() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-2">
          <div className="h-4 w-40 animate-pulse rounded bg-slate-700/80" />
          <div className="h-3 w-24 animate-pulse rounded bg-slate-800/90" />
        </div>
        <div className="h-8 w-20 animate-pulse rounded-md bg-cyan-500/15" />
      </div>

      <div className="mt-3 space-y-2">
        <div className="h-3 w-full animate-pulse rounded bg-slate-800/90" />
        <div className="h-3 w-5/6 animate-pulse rounded bg-slate-800/90" />
        <div className="h-3 w-2/3 animate-pulse rounded bg-slate-800/90" />
      </div>

      <div className="mt-3 flex items-center gap-2">
        <div className="h-5 w-28 animate-pulse rounded-full bg-slate-800/90" />
        <div className="h-5 w-24 animate-pulse rounded-full bg-slate-800/90" />
      </div>
    </div>
  );
}

function SearchLoadingPanel({ compact }: { compact: boolean }) {
  return (
    <div className={`mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4 ${compact ? "" : "min-h-[18rem]"}`}>
      <div className="flex items-center gap-3">
        <div className="h-10 w-10 animate-spin rounded-full border-2 border-cyan-300/30 border-t-cyan-300" />
        <div>
          <p className="text-sm font-medium text-slate-100">Loading package results</p>
          <p className="text-xs text-slate-400">Fetching the next set of matches...</p>
        </div>
      </div>

      <div className="mt-4 space-y-3">
        <SearchResultSkeletonCard />
        <SearchResultSkeletonCard />
        <SearchResultSkeletonCard />
      </div>
    </div>
  );
}

export function AddDependencyPanel({
  apiBaseUrl,
  initialEcosystem,
  allowedEcosystems,
  resolveRepoCoordinates,
  className,
  client,
}: AddDependencyPanelProps) {
  const apiClient = useMemo(() => client ?? defaultDependencyApiClient, [client]);
  const selectableEcosystems = useMemo(() => {
    const incoming = Array.isArray(allowedEcosystems)
      ? allowedEcosystems.filter((value): value is Ecosystem => value === "npm" || value === "pypi")
      : [];

    const deduped = Array.from(new Set(incoming));
    return deduped.length > 0 ? deduped : [initialEcosystem];
  }, [allowedEcosystems, initialEcosystem]);

  const [ecosystem, setEcosystem] = useState<Ecosystem>(selectableEcosystems[0] ?? initialEcosystem);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<PackageSearchResult[]>([]);
  const [searchPage, setSearchPage] = useState(1);
  const [searchSuggestion, setSearchSuggestion] = useState<string | null>(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searchRetryable, setSearchRetryable] = useState(false);
  const [searchRetryToken, setSearchRetryToken] = useState(0);
  const [searchHasMore, setSearchHasMore] = useState(false);
  const [selection, setSelection] = useState<SelectionEntry[]>([]);
  const [versionLookupByPackage, setVersionLookupByPackage] = useState<Record<string, { loading: boolean; error: string | null; versions: string[] }>>({});
  const [pendingSuspicious, setPendingSuspicious] = useState<string | null>(null);
  const [branchName, setBranchName] = useState("");
  const [prTitle, setPrTitle] = useState("");
  const [prBody, setPrBody] = useState("");
  const [submitLoading, setSubmitLoading] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState<CreateDependencyPrResponse | null>(null);
  const [compatibilityResult, setCompatibilityResult] = useState<CompatibilityCheckResponse | null>(null);
  const [isCheckingCompat, setIsCheckingCompat] = useState(false);

  const searchDebounceRef = useRef<number | null>(null);
  const searchAbortControllerRef = useRef<AbortController | null>(null);
  const latestSearchRequestIdRef = useRef(0);
  const activeSearchSignatureRef = useRef<string>("");
  const inFlightSearchKeysRef = useRef<Set<string>>(new Set());
  const resultsListRef = useRef<HTMLDivElement | null>(null);
  const resultsSentinelRef = useRef<HTMLDivElement | null>(null);
  const versionLookupAbortControllerRef = useRef<AbortController | null>(null);
  const versionLookupRequestIdRef = useRef(0);

  useEffect(() => {
    const fallback = selectableEcosystems[0] ?? initialEcosystem;
    const next = selectableEcosystems.includes(initialEcosystem) ? initialEcosystem : fallback;

    setEcosystem((current) => (current === next ? current : next));
  }, [initialEcosystem, selectableEcosystems]);

  const selectedNameSet = useMemo(() => new Set(selection.map((item) => item.name)), [selection]);

  const requestMoreResults = useCallback(() => {
    if (searchLoading || searchError || !searchHasMore) {
      return;
    }

    setSearchPage((current) => current + 1);
  }, [searchError, searchHasMore, searchLoading]);

  useEffect(() => {
    setSearchPage(1);
    setSearchHasMore(false);
    setSearchRetryable(false);
  }, [query, ecosystem]);

  const retrySearch = useCallback(() => {
    setSearchRetryToken((current) => current + 1);
  }, []);

  useEffect(() => {
    const safeBaseUrl = apiBaseUrl?.trim();
    const trimmedQuery = query.trim();
    const searchSignature = `${ecosystem}:${trimmedQuery}`;
    const isNewSearch = searchPage === 1 || activeSearchSignatureRef.current !== searchSignature;

    if (searchDebounceRef.current !== null) {
      window.clearTimeout(searchDebounceRef.current);
    }

    searchDebounceRef.current = window.setTimeout(async () => {
      if (!safeBaseUrl) {
        setSearchError("Missing NEXT_PUBLIC_API_URL configuration.");
        setSearchRetryable(false);
        setSearchLoading(false);
        return;
      }

      if (trimmedQuery.length === 0) {
        searchAbortControllerRef.current?.abort();
        searchAbortControllerRef.current = null;
        activeSearchSignatureRef.current = "";
        setResults([]);
        setSearchHasMore(false);
        setSearchSuggestion(null);
        setSearchError(null);
        setSearchRetryable(false);
        setSearchLoading(false);
        return;
      }

      if (trimmedQuery.length < 2) {
        setResults([]);
        setSearchHasMore(false);
        setSearchSuggestion(null);
        setSearchError(null);
        setSearchRetryable(false);
        setSearchLoading(false);
        activeSearchSignatureRef.current = searchSignature;
        return;
      }

      const inFlightKey = `${searchSignature}:${searchPage}`;
      if (inFlightSearchKeysRef.current.has(inFlightKey)) {
        return;
      }

      searchAbortControllerRef.current?.abort();
      const controller = new AbortController();
      searchAbortControllerRef.current = controller;
      const requestId = latestSearchRequestIdRef.current + 1;
      latestSearchRequestIdRef.current = requestId;
      inFlightSearchKeysRef.current.add(inFlightKey);

      setSearchLoading(true);
      setSearchError(null);
      setSearchRetryable(false);

      if (isNewSearch) {
        setResults([]);
        setSearchHasMore(false);
        setSearchSuggestion(null);
      }

      try {
        const repo = await resolveRepoCoordinates();
        const response = await apiClient.searchPackages(
          {
            baseUrl: safeBaseUrl,
            authHeaders: repo.headers,
          },
          ecosystem,
          trimmedQuery,
          searchPage,
          SEARCH_PAGE_SIZE,
          { signal: controller.signal },
        );

        if (controller.signal.aborted || requestId !== latestSearchRequestIdRef.current) {
          return;
        }

        activeSearchSignatureRef.current = searchSignature;
        setSearchHasMore(response.results.length >= SEARCH_PAGE_SIZE);
        setSearchSuggestion(isNewSearch ? response.did_you_mean : null);
        setResults((current) => (searchPage === 1 ? response.results : mergeSearchResults(current, response.results)));
        setSearchError(null);
      } catch (error) {
        if (controller.signal.aborted || requestId !== latestSearchRequestIdRef.current) {
          return;
        }

        if (error instanceof DOMException && error.name === "AbortError") {
          return;
        }

        if (error instanceof DependencyApiError && (error.status === 401 || error.status === 403)) {
          window.location.href = "/login";
          return;
        }

        const isRetryableError =
          (error instanceof DependencyApiError && error.status === 502) ||
          (error instanceof Error && /(network|fetch)/i.test(error.message));

        setSearchError(mapDependencyApiError(error));
        setSearchRetryable(isRetryableError);
      } finally {
        inFlightSearchKeysRef.current.delete(inFlightKey);

        if (requestId === latestSearchRequestIdRef.current) {
          setSearchLoading(false);
        }
      }
    }, SEARCH_DEBOUNCE_MS);

    return () => {
      if (searchDebounceRef.current !== null) {
        window.clearTimeout(searchDebounceRef.current);
        searchDebounceRef.current = null;
      }

      searchAbortControllerRef.current?.abort();
    };
  }, [apiBaseUrl, apiClient, ecosystem, query, resolveRepoCoordinates, searchPage, searchRetryToken]);

  useEffect(() => {
    const sentinel = resultsSentinelRef.current;
    const root = resultsListRef.current;

    if (!sentinel || !root || searchLoading || searchError || !searchHasMore) {
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        const firstEntry = entries[0];

        if (!firstEntry?.isIntersecting) {
          return;
        }

        requestMoreResults();
      },
      {
        root,
        rootMargin: "160px 0px 160px 0px",
        threshold: 0.1,
      },
    );

    observer.observe(sentinel);

    return () => {
      observer.disconnect();
    };
  }, [requestMoreResults, results.length, searchHasMore, searchError, searchLoading]);

  const loadPackageVersions = useCallback(
    async (packageName: string) => {
      const safeBaseUrl = apiBaseUrl?.trim();

      if (!safeBaseUrl) {
        return;
      }

      versionLookupAbortControllerRef.current?.abort();
      const controller = new AbortController();
      versionLookupAbortControllerRef.current = controller;
      const requestId = versionLookupRequestIdRef.current + 1;
      versionLookupRequestIdRef.current = requestId;

      setVersionLookupByPackage((current) => ({
        ...current,
        [packageName]: {
          loading: true,
          error: null,
          versions: current[packageName]?.versions ?? [],
        },
      }));

      try {
        const repo = await resolveRepoCoordinates();
        const response = await apiClient.fetchPackageVersions(
          {
            baseUrl: safeBaseUrl,
            authHeaders: repo.headers,
          },
          ecosystem,
          packageName,
          { signal: controller.signal },
        );

        if (controller.signal.aborted || requestId !== versionLookupRequestIdRef.current) {
          return;
        }

        const versions = response.versions;

        setVersionLookupByPackage((current) => ({
          ...current,
          [packageName]: {
            loading: false,
            error: null,
            versions,
          },
        }));

        if (versions.length > 0) {
          setSelection((current) =>
            current.map((entry) => {
              if (entry.name !== packageName) {
                return entry;
              }

              if (entry.version.trim().length > 0 && entry.version !== "latest") {
                return entry;
              }

              return {
                ...entry,
                version: versions[0] ?? entry.version,
              };
            }),
          );
        }
      } catch (error) {
        if (controller.signal.aborted || requestId !== versionLookupRequestIdRef.current) {
          return;
        }

        setVersionLookupByPackage((current) => ({
          ...current,
          [packageName]: {
            loading: false,
            error: mapDependencyApiError(error),
            versions: current[packageName]?.versions ?? [],
          },
        }));
      } finally {
        if (versionLookupAbortControllerRef.current === controller) {
          versionLookupAbortControllerRef.current = null;
        }
      }
    },
    [apiBaseUrl, apiClient, ecosystem, resolveRepoCoordinates],
  );

  const addPackageToSelection = useCallback(
    (item: PackageSearchResult, force = false) => {
      if (!force && item.typosquat.is_suspected) {
        setPendingSuspicious(item.name);
        return;
      }

      setSelection((current) => {
        if (current.some((entry) => entry.name === item.name)) {
          return current;
        }

        const initialVersion = normalizeVersionForEcosystem(ecosystem, item.version ?? "");
        return [
          ...current,
          {
            name: item.name,
            version: initialVersion,
            suspected: item.typosquat.is_suspected,
          },
        ];
      });

      setPendingSuspicious(null);
      void loadPackageVersions(item.name);
    },
    [ecosystem, loadPackageVersions],
  );

  const confirmSuspiciousSelection = useCallback(
    (item: PackageSearchResult) => {
      addPackageToSelection(item, true);
    },
    [addPackageToSelection],
  );

  const removeSelected = useCallback((name: string) => {
    setSelection((current) => current.filter((entry) => entry.name !== name));
  }, []);

  const updateSelectedVersion = useCallback((name: string, version: string) => {
    setSelection((current) => current.map((entry) => (entry.name === name ? { ...entry, version } : entry)));
  }, []);

  const runCompatibilityCheck = useCallback(async () => {
    if (isCheckingCompat || selection.length === 0) return;
    const safeBaseUrl = apiBaseUrl?.trim();
    if (!safeBaseUrl) return;
    setIsCheckingCompat(true);
    setCompatibilityResult(null);
    try {
      const repo = await resolveRepoCoordinates();
      const dependencies = selection.map((entry) => ({
        name: entry.name,
        version: normalizeVersionForEcosystem(ecosystem, entry.version),
      }));
      const result = await checkDependencyCompatibility(
        { baseUrl: safeBaseUrl, authHeaders: repo.headers, owner: repo.owner, repoName: repo.repoName },
        { ecosystem, dependencies },
      );
      setCompatibilityResult(result);
    } catch { /* silent */ } finally {
      setIsCheckingCompat(false);
    }
  }, [apiBaseUrl, ecosystem, isCheckingCompat, resolveRepoCoordinates, selection]);

  const submitSelection = useCallback(async () => {
    if (submitLoading || selection.length === 0) {
      return;
    }

    const safeBaseUrl = apiBaseUrl?.trim();

    if (!safeBaseUrl) {
      setSubmitError("Missing NEXT_PUBLIC_API_URL configuration.");
      return;
    }

    setSubmitLoading(true);
    setSubmitError(null);
    setSubmitSuccess(null);

    try {
      const repo = await resolveRepoCoordinates();
      const dependencies: DependencyDraft[] = selection.map((entry) => ({
        name: entry.name,
        version: normalizeVersionForEcosystem(ecosystem, entry.version),
      }));

      const payload: CreateDependencyPrRequest = {
        ecosystem,
        dependencies,
        idempotency_key: createDependencyIdempotencyKey(repo.owner, repo.repoName),
      };

      if (ecosystem === "npm") {
        // Note: Backend requires either updated_package_lock_json OR generate_lockfile_server_side=true.
        // Since we don't support lock file uploads yet, we default to true.
        // The allowBackendLockfileGeneration flag is kept for future use when file upload is implemented.
        payload.generate_lockfile_server_side = true;
      }

      if (branchName.trim().length > 0) {
        payload.branch_name = branchName.trim();
      }

      if (prTitle.trim().length > 0) {
        payload.pr_title = prTitle.trim();
      }

      if (prBody.trim().length > 0) {
        payload.pr_body = prBody.trim();
      }

      const response = await apiClient.createDependencyPr(
        {
          baseUrl: safeBaseUrl,
          authHeaders: repo.headers,
        },
        repo.owner,
        repo.repoName,
        payload,
      );

      setSubmitSuccess(response);
      setSelection([]);
      setPendingSuspicious(null);
    } catch (error) {
      setSubmitError(mapDependencyApiError(error));
    } finally {
      setSubmitLoading(false);
    }
  }, [
    apiBaseUrl,
    apiClient,
    branchName,
    ecosystem,
    prBody,
    prTitle,
    resolveRepoCoordinates,
    selection,
    submitLoading,
  ]);

  useEffect(() => {
    setCompatibilityResult(null);
  }, [selection]);

  const handleSuggestionSearch = useCallback((suggestion: string) => {
    setQuery(suggestion);
    setSearchSuggestion(null);
  }, []);

  const canRenderLoadingPanel = searchLoading && results.length === 0;

  return (
    <div className={`flex h-full min-h-0 flex-col gap-4 ${className ?? ""}`}>
      <section className="rounded-2xl border border-slate-800 bg-slate-950/90 p-5 shadow-[0_24px_80px_rgba(2,6,23,0.45)]">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Add dependency</p>
            <h2 className="mt-2 text-2xl font-semibold text-slate-50">Search, compare, and add packages</h2>
            <p className="mt-2 max-w-2xl text-sm text-slate-400">
              Search the registry, inspect versions, and create a dependency PR directly from the repo.
            </p>
          </div>

          {selectableEcosystems.length > 1 ? (
            <div className="flex flex-wrap gap-2">
              {selectableEcosystems.map((availableEcosystem) => (
                <button
                  key={availableEcosystem}
                  type="button"
                  aria-pressed={ecosystem === availableEcosystem}
                  onClick={() => setEcosystem(availableEcosystem)}
                  className={`rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.12em] transition ${
                    ecosystem === availableEcosystem
                      ? "border-cyan-300/70 bg-cyan-500/20 text-cyan-50"
                      : "border-slate-700 bg-slate-900 text-slate-300 hover:border-slate-500"
                  }`}
                >
                  {availableEcosystem}
                </button>
              ))}
            </div>
          ) : null}
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
          <label className="block">
            <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">Search package</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={ecosystem === "npm" ? "react, zod, next..." : "requests, django, numpy..."}
              className="w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
            />
          </label>

        </div>

        {searchError ? (
          <div className="mt-3 rounded-lg border border-rose-400/35 bg-rose-500/10 px-3 py-2 text-xs text-rose-100">
            <p>{searchError}</p>
            {searchRetryable ? (
              <button
                type="button"
                onClick={retrySearch}
                className="mt-2 rounded-md border border-rose-300/40 bg-rose-500/15 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-rose-50"
              >
                Retry
              </button>
            ) : null}
          </div>
        ) : null}
        {submitError ? <p className="mt-3 rounded-lg border border-rose-400/35 bg-rose-500/10 px-3 py-2 text-xs text-rose-100">{submitError}</p> : null}
      </section>

      <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(360px,0.85fr)]">
        <section className="flex min-h-0 flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/90 p-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Registry results</p>
              <h3 className="mt-2 text-lg font-semibold text-slate-100">Matches for {query.trim() || "your query"}</h3>
            </div>
            {searchLoading ? <div className="h-3 w-3 animate-pulse rounded-full bg-cyan-300" aria-hidden="true" /> : null}
          </div>

          {searchSuggestion ? (
            <div className="mt-4 rounded-xl border border-cyan-400/20 bg-cyan-500/10 p-4 text-sm text-cyan-50">
              <p className="font-medium">Did you mean {searchSuggestion}?</p>
              <button
                type="button"
                onClick={() => handleSuggestionSearch(searchSuggestion)}
                className="mt-2 rounded-md border border-cyan-300/40 bg-cyan-500/15 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.14em] text-cyan-100"
              >
                Search {searchSuggestion}
              </button>
            </div>
          ) : null}

          {canRenderLoadingPanel ? <SearchLoadingPanel compact={false} /> : null}

          {results.length > 0 ? (
            <div className="mt-4 flex min-h-0 flex-1 flex-col overflow-hidden">
              <div
                ref={resultsListRef}
                data-testid="dependency-search-results"
                className="h-full min-h-0 overflow-y-auto pr-1"
              >
                <div className="grid gap-3">
                  {results.map((item) => {
                    const selected = selectedNameSet.has(item.name);
                    const suspected = item.typosquat.is_suspected;
                    const severity = getTyposquatSeverity(item.typosquat.confidence);
                    const didYouMean = suspected ? findDidYouMeanCandidate(item, query.trim(), results) : null;

                    return (
                      <article key={`${item.name}:${item.version ?? "latest"}`} className="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div>
                            <p className="text-sm font-semibold text-slate-100">{item.name}</p>
                            <p className="text-xs uppercase tracking-[0.12em] text-cyan-200">{formatPackageVersion(item.version)}</p>
                          </div>
                          <button
                            type="button"
                            disabled={selected}
                            onClick={() => addPackageToSelection(item)}
                            className="rounded-md border border-cyan-400/50 bg-cyan-500/15 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-cyan-100 transition hover:bg-cyan-500/30 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {selected ? "Selected" : "Select"}
                          </button>
                        </div>

                        <p className="mt-2 text-xs text-slate-300">{item.description || "No description"}</p>
                        <p className="mt-1 text-xs text-slate-400">{formatMonthlyDownloads(item.monthly_downloads)}</p>

                        <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-400">
                          {item.registry_url ? (
                            <a href={item.registry_url} target="_blank" rel="noreferrer" className="text-cyan-200 underline decoration-cyan-400/50 underline-offset-2">
                              Source
                            </a>
                          ) : null}
                          {item.homepage ? (
                            <a href={item.homepage} target="_blank" rel="noreferrer" className="text-cyan-200 underline decoration-cyan-400/50 underline-offset-2">
                              Homepage
                            </a>
                          ) : null}
                        </div>

                        {suspected ? (
                          <div className="mt-3 rounded-lg border border-amber-300/35 bg-amber-500/10 p-3">
                            <div className="flex items-center gap-2">
                              <span
                                className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${
                                  severity === "high"
                                    ? "border border-rose-300/45 bg-rose-500/20 text-rose-100"
                                    : "border border-amber-300/45 bg-amber-500/20 text-amber-100"
                                }`}
                              >
                                {severity === "high" ? "High Risk" : "Medium Risk"}
                              </span>
                              {item.typosquat.levenshtein_distance !== null ? (
                                <span className="text-[11px] uppercase tracking-[0.12em] text-amber-100/90">distance {item.typosquat.levenshtein_distance}</span>
                              ) : null}
                            </div>

                            <p className="mt-2 text-xs text-amber-100/90">
                              {item.typosquat.reasons[0] ?? "Package name resembles another known package. Check carefully."}
                            </p>

                            {didYouMean ? (
                              <p className="mt-2 text-xs text-cyan-100">
                                Did you mean {didYouMean.name}
                                {didYouMean.version ? `@${didYouMean.version}` : ""}?
                                <button
                                  type="button"
                                  onClick={() => addPackageToSelection(didYouMean)}
                                  className="ml-2 text-cyan-200 underline decoration-cyan-400/50 underline-offset-2"
                                >
                                  Select safer package
                                </button>
                              </p>
                            ) : (
                              <p className="mt-2 text-xs text-amber-100/90">This name is 1 edit away from your query. Check carefully before continuing.</p>
                            )}

                            {pendingSuspicious === item.name ? (
                              <div className="mt-3 flex flex-wrap gap-2">
                                <button
                                  type="button"
                                  onClick={() => confirmSuspiciousSelection(item)}
                                  className="rounded-md border border-rose-300/40 bg-rose-500/20 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-rose-100"
                                >
                                  I understand, add anyway
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setPendingSuspicious(null)}
                                  className="rounded-md border border-slate-600 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-200"
                                >
                                  Cancel
                                </button>
                              </div>
                            ) : null}
                          </div>
                        ) : null}
                      </article>
                    );
                  })}

                  <div ref={resultsSentinelRef} className="h-px w-full" aria-hidden="true" />

                  {searchLoading ? (
                    <div className="rounded-xl border border-cyan-400/20 bg-cyan-500/10 p-3">
                      <div className="flex items-center gap-3">
                        <div className="h-6 w-6 animate-spin rounded-full border-2 border-cyan-300/30 border-t-cyan-300" />
                        <div>
                          <p className="text-sm font-medium text-cyan-100">Loading more results</p>
                          <p className="text-xs text-cyan-100/70">Fetching the next 8 matches...</p>
                        </div>
                      </div>
                      <div className="mt-3 space-y-2">
                        <div className="h-3 w-5/6 animate-pulse rounded bg-cyan-200/25" />
                        <div className="h-3 w-2/3 animate-pulse rounded bg-cyan-200/20" />
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            </div>
          ) : searchLoading ? null : (
            <div className="mt-4 rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-4 text-sm text-slate-400">
              <p className="font-medium text-slate-200">No results yet.</p>
              <p className="mt-1">Start typing to search the registry.</p>
            </div>
          )}
        </section>

        <section className="flex min-h-0 flex-col rounded-2xl border border-slate-800 bg-slate-950/90 p-5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Selection & PR</p>
          <h3 className="mt-2 text-lg font-semibold text-slate-100">Selected dependencies</h3>

          <div className="mt-3 space-y-2">
            {selection.length === 0 ? (
              <p className="rounded-lg border border-dashed border-slate-700 bg-slate-900/60 p-3 text-xs text-slate-400">
                Select one or more packages to build the PR payload.
              </p>
            ) : (
              selection.map((entry) => {
                const versionLookup = versionLookupByPackage[entry.name];
                const versionOptions = Array.from(new Set([entry.version, ...(versionLookup?.versions ?? [])].filter((version) => version.trim().length > 0)));

                return (
                  <div key={entry.name} className="rounded-lg border border-slate-800 bg-slate-900/55 p-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-medium text-slate-100">{entry.name}</p>
                      <button
                        type="button"
                        onClick={() => removeSelected(entry.name)}
                        className="rounded-md border border-rose-400/35 bg-rose-500/10 px-2 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-rose-100"
                      >
                        Remove
                      </button>
                    </div>

                    <label htmlFor={`selected-version-${entry.name}`} className="mt-2 block text-[11px] uppercase tracking-[0.12em] text-slate-400">
                      Version
                    </label>
                    {versionLookup?.loading ? <p className="mt-1 text-xs text-slate-400">Loading available versions...</p> : null}
                    {versionLookup?.error ? <p className="mt-1 text-xs text-rose-200">{versionLookup.error}</p> : null}

                    {versionOptions.length > 0 ? (
                      <select
                        id={`selected-version-${entry.name}`}
                        value={entry.version}
                        onChange={(event) => updateSelectedVersion(entry.name, event.target.value)}
                        className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-400/60"
                      >
                        {versionOptions.map((version) => (
                          <option key={version} value={version}>
                            {version}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        id={`selected-version-${entry.name}`}
                        type="text"
                        value={entry.version}
                        onChange={(event) => updateSelectedVersion(entry.name, event.target.value)}
                        className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-400/60"
                      />
                    )}
                  </div>
                );
              })
            )}
          </div>

          {ecosystem === "npm" ? (
            <label className="mt-4 flex items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={true}
                onChange={() => {}}
                disabled={true}
              />
              <span
                title="Lock file generation is always enabled. Custom lock file uploads will be supported in a future release."
                className="cursor-help"
              >
                Backend generates lockfile (always enabled)
              </span>
            </label>
          ) : null}

          <div className="mt-4 space-y-2">
            <input
              type="text"
              value={branchName}
              onChange={(event) => setBranchName(event.target.value)}
              placeholder="Optional branch name"
              className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
            />
            <input
              type="text"
              value={prTitle}
              onChange={(event) => setPrTitle(event.target.value)}
              placeholder="Optional PR title"
              className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
            />
            <textarea
              value={prBody}
              onChange={(event) => setPrBody(event.target.value)}
              rows={4}
              placeholder="Optional PR body"
              className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
            />
          </div>

          {submitSuccess ? (
            <div className="mt-3 rounded-lg border border-emerald-300/35 bg-emerald-500/10 px-3 py-3 text-xs text-emerald-100">
              <p className="font-semibold uppercase tracking-[0.12em]">PR request accepted</p>
              {typeof submitSuccess.pr_number === "number" ? <p className="mt-1">PR #{submitSuccess.pr_number}</p> : null}
              {submitSuccess.branch_name ? <p className="mt-1">Branch: {submitSuccess.branch_name}</p> : null}
              {submitSuccess.pr_url ? (
                <a href={submitSuccess.pr_url} target="_blank" rel="noreferrer" className="mt-2 inline-flex text-cyan-200 underline decoration-cyan-400/50 underline-offset-2">
                  Open PR
                </a>
              ) : null}
              {submitSuccess.status ? <p className="mt-1">Status: {submitSuccess.status}</p> : null}
              {submitSuccess.message ? <p className="mt-1">{submitSuccess.message}</p> : null}
              {submitSuccess.scan_job_id ? (
                <p className="mt-2 font-mono text-emerald-200/80">Security scan enqueued (job: {submitSuccess.scan_job_id})</p>
              ) : null}
              {submitSuccess.typosquat_warnings && submitSuccess.typosquat_warnings.length > 0 ? (
                <div className="mt-3 rounded-md border border-amber-300/35 bg-amber-500/10 px-3 py-2">
                  <p className="font-semibold uppercase tracking-[0.12em] text-amber-200">Typosquat warnings</p>
                  <ul className="mt-2 space-y-2">
                    {submitSuccess.typosquat_warnings.map((warning) => (
                      <li key={warning.package_name} className="text-amber-100/90">
                        <span className="font-medium">{warning.package_name}</span>
                        <span
                          className={`ml-2 rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${
                            warning.risk_level === "high"
                              ? "border border-rose-300/45 bg-rose-500/20 text-rose-100"
                              : "border border-amber-300/45 bg-amber-500/20 text-amber-100"
                          }`}
                        >
                          {warning.risk_level}
                        </span>
                        {warning.reasons[0] ? (
                          <p className="mt-0.5 text-[11px] text-amber-100/75">{warning.reasons[0]}</p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}

          {selection.length > 0 ? (
            <button
              type="button"
              onClick={() => { void runCompatibilityCheck(); }}
              disabled={isCheckingCompat || submitLoading}
              className="mt-4 w-full rounded-lg border border-amber-400/40 bg-amber-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.14em] text-amber-100 transition hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isCheckingCompat ? "Checking..." : "Check Compatibility"}
            </button>
          ) : null}

          {compatibilityResult ? (
            <div className={`mt-3 rounded-lg border px-3 py-3 text-xs ${compatibilityResult.compatible ? "border-emerald-400/30 bg-emerald-500/10" : "border-amber-400/30 bg-amber-500/10"}`}>
              <p className={`font-semibold uppercase tracking-[0.12em] ${compatibilityResult.compatible ? "text-emerald-200" : "text-amber-200"}`}>
                {compatibilityResult.compatible ? "All dependencies compatible" : "Compatibility warning"}
              </p>
              <div className="mt-2 space-y-2">
                {compatibilityResult.checks.map((check) => (
                  <div key={check.name} className={`rounded border p-2 ${check.compatible ? "border-emerald-500/20 bg-emerald-500/5" : "border-amber-500/25 bg-amber-500/10"}`}>
                    <p className="font-medium text-slate-100">{check.name} <span className="font-normal text-slate-400">@ {check.requested_version}</span></p>
                    {check.existing_constraint ? (
                      <p className="mt-0.5 text-slate-400">Existing: <span className="font-mono text-slate-300">{check.existing_constraint}</span></p>
                    ) : null}
                    {!check.compatible && check.reason ? (
                      <p className="mt-1 text-amber-100">{check.reason}</p>
                    ) : null}
                    {!check.compatible && check.suggestion ? (
                      <p className="mt-0.5 text-amber-200/80">Suggestion: {check.suggestion}</p>
                    ) : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          <button
            type="button"
            onClick={() => {
              void submitSelection();
            }}
            disabled={submitLoading || selection.length === 0}
            className="mt-4 inline-flex w-full items-center justify-center rounded-lg border border-cyan-400/55 bg-cyan-500/15 px-4 py-2 text-sm font-semibold uppercase tracking-[0.16em] text-cyan-100 transition hover:bg-cyan-500/30 disabled:cursor-not-allowed disabled:opacity-55"
          >
            {submitLoading ? "Creating PR..." : "Create Dependency PR"}
          </button>
        </section>
      </div>
    </div>
  );
}
