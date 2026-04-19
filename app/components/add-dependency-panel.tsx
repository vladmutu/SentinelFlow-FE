"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Ecosystem } from "@/app/types/dashboard";
import {
  createDependencyIdempotencyKey,
  createDependencyPr as createDependencyPrApi,
  fetchPackageVersions as fetchPackageVersionsApi,
  mapDependencyApiError,
  type CreateDependencyPrRequest,
  type CreateDependencyPrResponse,
  type DependencyDraft,
  type PackageSearchResult,
  searchPackages as searchPackagesApi,
} from "@/app/lib/api/dependency-pr";

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

const SEARCH_DEBOUNCE_MS = 360;
const SEARCH_LIMIT = 1000;

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
    return "Downloads unavailable";
  }

  return `${new Intl.NumberFormat("en-US").format(monthlyDownloads)} monthly downloads`;
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
  const [searchSuggestion, setSearchSuggestion] = useState<string | null>(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [selection, setSelection] = useState<SelectionEntry[]>([]);
  const [versionLookupByPackage, setVersionLookupByPackage] = useState<Record<string, { loading: boolean; error: string | null; versions: string[] }>>({});
  const [pendingSuspicious, setPendingSuspicious] = useState<string | null>(null);
  const [allowBackendLockfileGeneration, setAllowBackendLockfileGeneration] = useState(true);
  const [branchName, setBranchName] = useState("");
  const [prTitle, setPrTitle] = useState("");
  const [prBody, setPrBody] = useState("");
  const [submitLoading, setSubmitLoading] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState<CreateDependencyPrResponse | null>(null);

  const searchDebounceRef = useRef<number | null>(null);
  const searchAbortControllerRef = useRef<AbortController | null>(null);
  const latestSearchRequestIdRef = useRef(0);
  const versionLookupAbortControllerRef = useRef<AbortController | null>(null);
  const versionLookupRequestIdRef = useRef(0);

  useEffect(() => {
    const fallback = selectableEcosystems[0] ?? initialEcosystem;
    const next = selectableEcosystems.includes(initialEcosystem) ? initialEcosystem : fallback;

    setEcosystem((current) => (current === next ? current : next));
  }, [initialEcosystem, selectableEcosystems]);

  const selectedNameSet = useMemo(() => new Set(selection.map((item) => item.name)), [selection]);

  const handleSearch = useCallback(async () => {
    const safeBaseUrl = apiBaseUrl?.trim();
    const trimmedQuery = query.trim();

    if (!safeBaseUrl) {
      setSearchError("Missing NEXT_PUBLIC_API_URL configuration.");
      return;
    }

    if (trimmedQuery.length === 0) {
      if (searchAbortControllerRef.current) {
        searchAbortControllerRef.current.abort();
        searchAbortControllerRef.current = null;
      }
      setResults([]);
      setSearchSuggestion(null);
      setSearchError(null);
      setSearchLoading(false);
      return;
    }

    if (trimmedQuery.length < 2) {
      setResults([]);
      setSearchSuggestion(null);
      setSearchError(null);
      setSearchLoading(false);
      return;
    }

    if (searchAbortControllerRef.current) {
      searchAbortControllerRef.current.abort();
    }

    const controller = new AbortController();
    searchAbortControllerRef.current = controller;
    const requestId = latestSearchRequestIdRef.current + 1;
    latestSearchRequestIdRef.current = requestId;

    setSearchLoading(true);
    setSearchError(null);
    setSearchSuggestion(null);

    try {
      const repo = await resolveRepoCoordinates();
      const response = await apiClient.searchPackages(
        {
          baseUrl: safeBaseUrl,
          authHeaders: repo.headers,
        },
        ecosystem,
        trimmedQuery,
        SEARCH_LIMIT,
        { signal: controller.signal },
      );

      if (requestId !== latestSearchRequestIdRef.current) {
        return;
      }

      setResults(response.results);
      setSearchSuggestion(response.did_you_mean);
      setSearchError(null);
    } catch (error) {
      if (controller.signal.aborted || requestId !== latestSearchRequestIdRef.current) {
        return;
      }

      setSearchSuggestion(null);
      setSearchError(mapDependencyApiError(error));
    } finally {
      if (requestId !== latestSearchRequestIdRef.current) {
        return;
      }

      if (searchAbortControllerRef.current === controller) {
        searchAbortControllerRef.current = null;
      }
      setSearchLoading(false);
    }
  }, [apiBaseUrl, apiClient, ecosystem, query, resolveRepoCoordinates]);

  useEffect(() => {
    if (searchDebounceRef.current !== null) {
      window.clearTimeout(searchDebounceRef.current);
      searchDebounceRef.current = null;
    }

    searchDebounceRef.current = window.setTimeout(() => {
      void handleSearch();
    }, SEARCH_DEBOUNCE_MS);

    return () => {
      if (searchDebounceRef.current !== null) {
        window.clearTimeout(searchDebounceRef.current);
        searchDebounceRef.current = null;
      }

      if (searchAbortControllerRef.current) {
        searchAbortControllerRef.current.abort();
        searchAbortControllerRef.current = null;
      }
    };
  }, [handleSearch]);

  useEffect(() => {
    return () => {
      if (versionLookupAbortControllerRef.current) {
        versionLookupAbortControllerRef.current.abort();
        versionLookupAbortControllerRef.current = null;
      }
    };
  }, []);

  const addToSelection = useCallback((item: PackageSearchResult) => {
    const normalizedVersion = item.version ? normalizeVersionForEcosystem(ecosystem, item.version) : "";

    setSelection((current) => {
      const existing = current.find((entry) => entry.name === item.name);

      if (existing) {
        return current.map((entry) => (entry.name === item.name ? { ...entry, version: normalizedVersion } : entry));
      }

      return [
        ...current,
        {
          name: item.name,
          version: normalizedVersion,
          suspected: item.typosquat.is_suspected,
        },
      ];
    });
  }, [ecosystem]);

  const loadPackageVersions = useCallback(async (packageName: string) => {
    const safeBaseUrl = apiBaseUrl?.trim();

    if (!safeBaseUrl) {
      return;
    }

    if (versionLookupAbortControllerRef.current) {
      versionLookupAbortControllerRef.current.abort();
    }

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
        20,
        { signal: controller.signal },
      );

      if (controller.signal.aborted || requestId !== versionLookupRequestIdRef.current) {
        return;
      }

      setVersionLookupByPackage((current) => ({
        ...current,
        [packageName]: {
          loading: false,
          error: null,
          versions: response.versions,
        },
      }));

      if (response.versions.length > 0) {
        setSelection((current) =>
          current.map((entry) => {
            if (entry.name !== packageName || entry.version.trim().length > 0) {
              return entry;
            }

            return {
              ...entry,
              version: response.versions[0],
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
  }, [apiBaseUrl, apiClient, ecosystem, resolveRepoCoordinates]);

  const selectPackage = useCallback((item: PackageSearchResult) => {
    addToSelection(item);
    void loadPackageVersions(item.name);
  }, [addToSelection, loadPackageVersions]);

  const handleSelect = useCallback((item: PackageSearchResult) => {
    setSubmitError(null);
    setSubmitSuccess(null);

    if (item.typosquat.is_suspected) {
      setPendingSuspicious(item.name);
      return;
    }

    selectPackage(item);
  }, [selectPackage]);

  const confirmSuspiciousSelection = useCallback((item: PackageSearchResult) => {
    setPendingSuspicious(null);
    selectPackage(item);
  }, [selectPackage]);

  const updateSelectedVersion = useCallback((name: string, version: string) => {
    setSelection((current) =>
      current.map((entry) => {
        if (entry.name !== name) {
          return entry;
        }

        return {
          ...entry,
          version,
        };
      }),
    );
  }, []);

  const removeSelected = useCallback((name: string) => {
    setSelection((current) => current.filter((entry) => entry.name !== name));
    setVersionLookupByPackage((current) => {
      if (!current[name]) {
        return current;
      }

      const next = { ...current };
      delete next[name];
      return next;
    });
  }, []);

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
        payload.generate_lockfile_server_side = allowBackendLockfileGeneration;
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
    } catch (error) {
      setSubmitError(mapDependencyApiError(error));
    } finally {
      setSubmitLoading(false);
    }
  }, [
    allowBackendLockfileGeneration,
    apiBaseUrl,
    branchName,
    apiClient,
    ecosystem,
    prBody,
    prTitle,
    resolveRepoCoordinates,
    selection,
    submitLoading,
  ]);

  return (
    <div className={`grid h-full min-h-0 w-full gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)] ${className ?? ""}`}>
      <section className="flex h-full min-h-0 flex-col rounded-2xl border border-slate-800 bg-slate-950/90 p-5">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Create Dependency PR</p>
        <h2 className="mt-2 text-xl font-semibold text-slate-100">Search dependencies via backend proxy</h2>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor="dependency-ecosystem" className="text-xs uppercase tracking-[0.14em] text-slate-400">
              Ecosystem
            </label>
            <select
              id="dependency-ecosystem"
              value={ecosystem}
              onChange={(event) => {
                setEcosystem(event.target.value as Ecosystem);
                setSubmitError(null);
                setSubmitSuccess(null);
              }}
              className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-400/60"
            >
              {selectableEcosystems.map((availableEcosystem) => (
                <option key={availableEcosystem} value={availableEcosystem}>
                  {availableEcosystem === "npm" ? "npm" : "PyPI"}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="mt-4 flex min-h-0 flex-1 flex-col rounded-xl border border-slate-800 bg-slate-900/40 p-4">
          <label htmlFor="dependency-query" className="text-xs uppercase tracking-[0.14em] text-slate-400">
            Search package
          </label>
          <input
            id="dependency-query"
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={ecosystem === "npm" ? "react" : "requests"}
            className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/60"
          />

          {searchLoading ? <p className="mt-3 text-xs text-slate-400">Searching...</p> : null}
          {searchError ? <p className="mt-3 text-xs text-rose-200">{searchError}</p> : null}

          {!searchLoading && !searchError && query.trim().length >= 2 && results.length === 0 ? (
            searchSuggestion ? (
              <div className="mt-3 rounded-lg border border-cyan-400/25 bg-cyan-500/10 p-3 text-xs text-cyan-100">
                <p>Did you mean {searchSuggestion}?</p>
                <button
                  type="button"
                  onClick={() => setQuery(searchSuggestion)}
                  className="mt-2 text-cyan-200 underline decoration-cyan-400/50 underline-offset-2"
                >
                  Search {searchSuggestion}
                </button>
              </div>
            ) : (
              <p className="mt-3 text-xs text-slate-400">No packages found for this query.</p>
            )
          ) : null}

          {results.length > 0 ? (
            <div className="mt-4 min-h-0 flex-1 overflow-y-auto pr-1">
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
                        onClick={() => handleSelect(item)}
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
                          <span className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] ${
                            severity === "high"
                              ? "border border-rose-300/45 bg-rose-500/20 text-rose-100"
                              : "border border-amber-300/45 bg-amber-500/20 text-amber-100"
                          }`}>
                            {severity === "high" ? "High Risk" : "Medium Risk"}
                          </span>
                          {item.typosquat.levenshtein_distance !== null ? (
                            <span className="text-[11px] uppercase tracking-[0.12em] text-amber-100/90">
                              distance {item.typosquat.levenshtein_distance}
                            </span>
                          ) : null}
                        </div>

                        <p className="mt-2 text-xs text-amber-100/90">
                          {item.typosquat.reasons[0] ?? "Package name resembles another known package. Check carefully."}
                        </p>

                        {didYouMean ? (
                          <p className="mt-2 text-xs text-cyan-100">
                            Did you mean {didYouMean.name}{didYouMean.version ? `@${didYouMean.version}` : ""}?
                            <button
                              type="button"
                              onClick={() => selectPackage(didYouMean)}
                              className="ml-2 text-cyan-200 underline decoration-cyan-400/50 underline-offset-2"
                            >
                              Select safer package
                            </button>
                          </p>
                        ) : (
                          <p className="mt-2 text-xs text-amber-100/90">
                            This name is 1 edit away from your query. Check carefully before continuing.
                          </p>
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
              </div>
            </div>
          ) : null}
        </div>
      </section>

      <section className="h-full rounded-2xl border border-slate-800 bg-slate-950/90 p-5">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Selection & PR</p>
        <h3 className="mt-2 text-lg font-semibold text-slate-100">Selected dependencies</h3>

        <div className="mt-3 space-y-2">
          {selection.length === 0 ? (
            <p className="rounded-lg border border-dashed border-slate-700 bg-slate-900/60 p-3 text-xs text-slate-400">
              Select one or more packages to build the PR payload.
            </p>
          ) : (
            selection.map((entry) => (
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
                {versionLookupByPackage[entry.name]?.loading ? (
                  <p className="mt-1 text-xs text-slate-400">Loading available versions...</p>
                ) : null}
                {versionLookupByPackage[entry.name]?.error ? (
                  <p className="mt-1 text-xs text-rose-200">{versionLookupByPackage[entry.name]?.error}</p>
                ) : null}
                {versionLookupByPackage[entry.name]?.versions.length ? (
                  <select
                    id={`selected-version-${entry.name}`}
                    value={entry.version}
                    onChange={(event) => updateSelectedVersion(entry.name, event.target.value)}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-400/60"
                  >
                    <option value={entry.version}>{entry.version}</option>
                    {versionLookupByPackage[entry.name].versions
                      .filter((version) => version !== entry.version)
                      .map((version) => (
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
            ))
          )}
        </div>

        {ecosystem === "npm" ? (
          <label className="mt-4 flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={allowBackendLockfileGeneration}
              onChange={(event) => setAllowBackendLockfileGeneration(event.target.checked)}
            />
            <span
              title="When enabled, the backend generates and commits package-lock.json for you. Disable this if you prefer to manage lockfile updates manually in your local environment."
              className="cursor-help"
            >
              Let backend generate lockfile server-side
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

        {submitError ? (
          <p className="mt-3 rounded-lg border border-rose-400/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-100">{submitError}</p>
        ) : null}

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
          </div>
        ) : null}

        <button
          type="button"
          onClick={() => {
            void submitSelection();
          }}
          disabled={submitLoading || selection.length === 0}
          className="mt-5 inline-flex w-full items-center justify-center rounded-lg border border-cyan-400/55 bg-cyan-500/15 px-4 py-2 text-sm font-semibold uppercase tracking-[0.16em] text-cyan-100 transition hover:bg-cyan-500/30 disabled:cursor-not-allowed disabled:opacity-55"
        >
          {submitLoading ? "Creating PR..." : "Create Dependency PR"}
        </button>
      </section>
    </div>
  );
}
