import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AddDependencyPanel } from "@/app/components/add-dependency-panel";
import { DependencyApiError, searchPackages, type PackageSearchResponse } from "@/app/lib/api/dependency-pr";

function makeSearchResponse(overrides?: Partial<PackageSearchResponse>): PackageSearchResponse {
  return {
    ecosystem: "npm",
    query: "rea",
    total: 2,
    results: [
      {
        ecosystem: "npm",
        name: "reaqt",
        version: "1.0.0",
        description: "Suspicious package",
        homepage: null,
        registry_url: "https://registry.npmjs.org/reaqt",
        score: 0.1,
        monthly_downloads: 100,
        typosquat: {
          is_suspected: true,
          confidence: 0.9,
          levenshtein_distance: 1,
          edit_distance: 1,
          normalized_conflict: "react",
          reasons: ["Package name closely resembles react"],
        },
      },
      {
        ecosystem: "npm",
        name: "react",
        version: "19.2.0",
        description: "Safe package",
        homepage: "https://react.dev",
        registry_url: "https://registry.npmjs.org/react",
        score: 0.9,
        monthly_downloads: 1000000,
        typosquat: {
          is_suspected: false,
          confidence: 0,
          levenshtein_distance: null,
          edit_distance: null,
          normalized_conflict: null,
          reasons: [],
        },
      },
    ],
    did_you_mean: null,
    ...overrides,
  };
}

describe("AddDependencyPanel", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it("renders typosquatting warning and requires confirmation before selecting suspicious package", async () => {
    const searchPackages = vi.fn().mockResolvedValue(makeSearchResponse());
    const fetchPackageVersions = vi.fn().mockResolvedValue({ name: "reaqt", versions: ["1.0.1", "1.0.0"] });
    const createDependencyPr = vi.fn();

    render(
      <AddDependencyPanel
        apiBaseUrl="http://localhost:8000"
        initialEcosystem="npm"
        resolveRepoCoordinates={async () => ({ owner: "octo", repoName: "repo", headers: {} })}
        client={{ searchPackages, fetchPackageVersions, createDependencyPr }}
      />,
    );

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Search package"), "rea");

    expect(await screen.findByText("High Risk")).toBeInTheDocument();
    expect(screen.getByText(/distance 1/i)).toBeInTheDocument();
    expect(screen.getByText(/Did you mean react@19.2.0/i)).toBeInTheDocument();

    const selectButtons = screen.getAllByRole("button", { name: "Select" });
    await user.click(selectButtons[0]);

    expect(await screen.findByRole("button", { name: "I understand, add anyway" })).toBeInTheDocument();
    expect(createDependencyPr).not.toHaveBeenCalled();
  });

  it("sorts package search results by relevance", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        ecosystem: "pypi",
        query: "scikit",
        total: 3,
        results: [
          {
            ecosystem: "pypi",
            name: "far-package",
            version: "1.0.0",
            description: "Farther match",
            homepage: null,
            registry_url: null,
            score: 0.2,
            monthly_downloads: 10,
            typosquat: {
              is_suspected: false,
              confidence: 0,
              levenshtein_distance: 6,
              edit_distance: 6,
              normalized_conflict: null,
              reasons: [],
            },
          },
          {
            ecosystem: "pypi",
            name: "near-no-version",
            version: null,
            description: "Near match without version",
            homepage: null,
            registry_url: null,
            score: 0.9,
            monthly_downloads: 300,
            typosquat: {
              is_suspected: false,
              confidence: 0,
              levenshtein_distance: 1,
              edit_distance: 1,
              normalized_conflict: null,
              reasons: [],
            },
          },
          {
            ecosystem: "pypi",
            name: "near-with-version",
            version: "2.0.0",
            description: "Near match with version",
            homepage: null,
            registry_url: null,
            score: 0.8,
            monthly_downloads: 700,
            typosquat: {
              is_suspected: false,
              confidence: 0,
              levenshtein_distance: 1,
              edit_distance: 1,
              normalized_conflict: null,
              reasons: [],
            },
          },
        ],
        did_you_mean: null,
      }),
    });

    vi.stubGlobal("fetch", fetchSpy);

    const response = await searchPackages(
      { baseUrl: "http://localhost:8000" },
      "pypi",
      "scikit",
      1000,
    );

    expect(response.results.map((result) => result.name)).toEqual([
      "near-with-version",
      "near-no-version",
      "far-package",
    ]);
  });

  it("shows a did-you-mean suggestion when the backend returns one", async () => {
    const searchPackages = vi.fn().mockResolvedValue({
      ecosystem: "npm",
      query: "rpequests",
      total: 0,
      results: [],
      did_you_mean: "requests",
    });
    const fetchPackageVersions = vi.fn();
    const createDependencyPr = vi.fn();

    render(
      <AddDependencyPanel
        apiBaseUrl="http://localhost:8000"
        initialEcosystem="npm"
        resolveRepoCoordinates={async () => ({ owner: "octo", repoName: "repo", headers: {} })}
        client={{ searchPackages, fetchPackageVersions, createDependencyPr }}
      />,
    );

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Search package"), "rpequests");

    expect(await screen.findByText(/Did you mean requests\?/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Search requests/i }));
    expect(screen.getByLabelText("Search package")).toHaveValue("requests");
  });

  it("renders packages even when the search response omits a version", async () => {
    const searchPackages = vi.fn().mockResolvedValue({
      ecosystem: "pypi",
      query: "scikit",
      total: 1,
      results: [
        {
          ecosystem: "pypi",
          name: "scikit-learn",
          version: null,
          description: "Machine learning library",
          homepage: "https://scikit-learn.org",
          registry_url: "https://pypi.org/project/scikit-learn/",
          score: 0.99,
          monthly_downloads: 200310655,
          typosquat: {
            is_suspected: false,
            confidence: 0,
            levenshtein_distance: null,
            edit_distance: null,
            normalized_conflict: null,
            reasons: [],
          },
        },
      ],
      did_you_mean: null,
    });
    const fetchPackageVersions = vi.fn().mockResolvedValue({ name: "scikit-learn", versions: ["1.6.1", "1.6.0"] });
    const createDependencyPr = vi.fn();

    render(
      <AddDependencyPanel
        apiBaseUrl="http://localhost:8000"
        initialEcosystem="pypi"
        allowedEcosystems={["pypi"]}
        resolveRepoCoordinates={async () => ({ owner: "octo", repoName: "repo", headers: {} })}
        client={{ searchPackages, fetchPackageVersions, createDependencyPr }}
      />,
    );

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Search package"), "scikit");

    expect(await screen.findByText("scikit-learn")).toBeInTheDocument();
    expect(screen.getByText(/Version unavailable/i)).toBeInTheDocument();
    expect(screen.getByText(/200,310,655 monthly downloads/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Select" }));
    expect(await screen.findByLabelText("Version")).toBeInTheDocument();
    await screen.findByDisplayValue("1.6.1");
  });

  it("submits expected payload shape for npm dependency PR", async () => {
    const searchPackages = vi.fn().mockResolvedValue(
      makeSearchResponse({
        results: [
          {
            ecosystem: "npm",
            name: "react",
            version: "19.2.0",
            description: "Safe package",
            homepage: null,
            registry_url: "https://registry.npmjs.org/react",
            score: 0.9,
            monthly_downloads: 50000000,
            typosquat: {
              is_suspected: false,
              confidence: 0,
              levenshtein_distance: null,
              edit_distance: null,
              normalized_conflict: null,
              reasons: [],
            },
          },
        ],
      }),
    );

    const fetchPackageVersions = vi.fn().mockResolvedValue({ name: "react", versions: ["19.2.0", "19.1.0", "18.3.1"] });
    const createDependencyPr = vi.fn().mockResolvedValue({
      pr_url: "https://github.com/octo/repo/pull/1",
      pr_number: 1,
      branch_name: "deps/react",
      status: "accepted",
      message: "Created",
    });

    render(
      <AddDependencyPanel
        apiBaseUrl="http://localhost:8000"
        initialEcosystem="npm"
        resolveRepoCoordinates={async () => ({
          owner: "octo",
          repoName: "repo",
          headers: { Authorization: "Bearer token" },
        })}
        client={{ searchPackages, fetchPackageVersions, createDependencyPr }}
      />,
    );

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Search package"), "react");

    await user.click(await screen.findByRole("button", { name: "Select" }));
    await user.selectOptions(await screen.findByLabelText("Version"), "19.1.0");
    await user.click(screen.getByRole("button", { name: "Create Dependency PR" }));

    await waitFor(() => expect(createDependencyPr).toHaveBeenCalledTimes(1));

    const payload = createDependencyPr.mock.calls[0][3];
    expect(payload.ecosystem).toBe("npm");
    expect(payload.dependencies).toEqual([{ name: "react", version: "19.1.0" }]);
    expect(payload.generate_lockfile_server_side).toBe(true);
    expect(typeof payload.idempotency_key).toBe("string");
    expect(payload.idempotency_key).toContain("dep-add-octo-repo");
  });

  it("shows success and failure submit states", async () => {
    const searchPackages = vi.fn().mockResolvedValue(
      makeSearchResponse({
        results: [
          {
            ecosystem: "npm",
            name: "react",
            version: "19.2.0",
            description: "Safe package",
            homepage: null,
            registry_url: "https://registry.npmjs.org/react",
            score: 0.9,
            monthly_downloads: 50000000,
            typosquat: {
              is_suspected: false,
              confidence: 0,
              levenshtein_distance: null,
              edit_distance: null,
              normalized_conflict: null,
              reasons: [],
            },
          },
        ],
      }),
    );

    const fetchPackageVersions = vi.fn().mockResolvedValue({ name: "react", versions: ["19.2.0", "19.1.0"] });
    const createDependencyPr = vi
      .fn()
      .mockResolvedValueOnce({ pr_url: "https://example.test/pr/10", pr_number: 10, status: "accepted" })
      .mockRejectedValueOnce(new DependencyApiError(409, "Branch already exists"));

    render(
      <AddDependencyPanel
        apiBaseUrl="http://localhost:8000"
        initialEcosystem="npm"
        resolveRepoCoordinates={async () => ({ owner: "octo", repoName: "repo", headers: {} })}
        client={{ searchPackages, fetchPackageVersions, createDependencyPr }}
      />,
    );

    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Search package"), "react");

    await user.click(await screen.findByRole("button", { name: "Select" }));
    await user.click(screen.getByRole("button", { name: "Create Dependency PR" }));

    expect(await screen.findByText(/PR #10/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText("Search package"), "react");
    const selectButtons = await screen.findAllByRole("button", { name: "Select" });
    await user.click(selectButtons[0]);
    await user.click(screen.getByRole("button", { name: "Create Dependency PR" }));

    expect(await screen.findByText(/Dependency PR conflict/i)).toBeInTheDocument();
  });
});
