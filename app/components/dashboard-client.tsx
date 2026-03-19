"use client";

import { FormEvent, useMemo, useState } from "react";

import { DependencyTree } from "@/app/components/dependency-tree";
import { DashboardSidebar } from "@/app/components/dashboard-sidebar";
import {
  apiContract,
  idleDynamicAnalysis,
  idleStaticAnalysis,
  initialRepositories,
} from "@/app/lib/mock-dashboard-data";
import {
  DynamicAnalysisReport,
  Ecosystem,
  GithubSession,
  QueuedDependencyChange,
  Repository,
  StaticAnalysisResult,
} from "@/app/types/dashboard";

function generateId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function classifyRepoRisk(repo: Repository): StaticAnalysisResult {
  if (repo.riskScore >= 80) {
    return {
      status: "critical",
      summary:
        "Model detected high-confidence malicious package behavior in transitive dependencies.",
      modelConfidence: 0.94,
      suspiciousCalls: ["ptrace", "execve", "setuid", "connect"],
    };
  }

  if (repo.riskScore >= 55) {
    return {
      status: "empty",
      summary:
        "Classifier was inconclusive for this dependency graph. Dynamic analysis is recommended.",
      modelConfidence: 0.49,
      suspiciousCalls: [],
    };
  }

  return {
    status: "clean",
    summary: "No suspicious behavior indicators found in static model scoring.",
    modelConfidence: 0.89,
    suspiciousCalls: [],
  };
}

function buildDynamicReport(repo: Repository): DynamicAnalysisReport {
  if (repo.riskScore >= 75) {
    return {
      vmStatus: "complete",
      notes:
        "Dynamic sandbox run detected syscall chains consistent with stealth process injection behavior.",
      suspiciousCalls: ["clone", "ptrace", "mprotect", "execve", "socket"],
    };
  }

  return {
    vmStatus: "complete",
    notes:
      "Dynamic sandbox run completed with normal package installation and startup behavior.",
    suspiciousCalls: [],
  };
}

export function DashboardClient({ session }: { session: GithubSession }) {
  const [repositories, setRepositories] = useState(initialRepositories);
  const [selectedRepoId, setSelectedRepoId] = useState(initialRepositories[0]?.id ?? "");
  const [dependencyName, setDependencyName] = useState("");
  const [dependencyVersion, setDependencyVersion] = useState("");
  const [dependencyEcosystem, setDependencyEcosystem] = useState<Ecosystem>("npm");
  const [queuedChanges, setQueuedChanges] = useState<QueuedDependencyChange[]>([]);
  const [staticAnalysis, setStaticAnalysis] = useState<StaticAnalysisResult>(
    idleStaticAnalysis,
  );
  const [dynamicReport, setDynamicReport] = useState<DynamicAnalysisReport>(
    idleDynamicAnalysis,
  );

  const selectedRepo = useMemo(
    () => repositories.find((repo) => repo.id === selectedRepoId),
    [repositories, selectedRepoId],
  );

  function handleDependencyAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!selectedRepo || !dependencyName.trim()) {
      return;
    }

    const normalizedVersion = dependencyVersion.trim() || "latest";

    const queued: QueuedDependencyChange = {
      id: generateId(),
      packageName: dependencyName.trim(),
      version: normalizedVersion,
      ecosystem: dependencyEcosystem,
      repositoryId: selectedRepo.id,
    };

    setQueuedChanges((current) => [queued, ...current]);

    setRepositories((current) =>
      current.map((repo) => {
        if (repo.id !== selectedRepo.id) {
          return repo;
        }

        return {
          ...repo,
          ecosystems: repo.ecosystems.includes(dependencyEcosystem)
            ? repo.ecosystems
            : [...repo.ecosystems, dependencyEcosystem],
          dependencies: [
            {
              name: dependencyName.trim(),
              version: normalizedVersion,
              ecosystem: dependencyEcosystem,
            },
            ...repo.dependencies,
          ],
        };
      }),
    );

    setDependencyName("");
    setDependencyVersion("");
  }

  function runStaticAnalysis() {
    if (!selectedRepo) {
      return;
    }

    setStaticAnalysis({
      status: "running",
      summary: "Classification model is scoring dependency graph and package metadata...",
    });

    setTimeout(() => {
      setStaticAnalysis(classifyRepoRisk(selectedRepo));
      setDynamicReport(idleDynamicAnalysis);
    }, 950);
  }

  function launchDynamicAnalysis() {
    if (!selectedRepo) {
      return;
    }

    setDynamicReport({
      vmStatus: "spawning",
      notes: "Provisioning disposable VM container and installing repository dependencies...",
      suspiciousCalls: [],
    });

    setTimeout(() => {
      setDynamicReport({
        vmStatus: "running",
        notes: "VM running behavioral instrumentation and tracing process/syscall activity...",
        suspiciousCalls: [],
      });
    }, 650);

    setTimeout(() => {
      setDynamicReport(buildDynamicReport(selectedRepo));
    }, 1700);
  }

  return (
    <main className="app-shell min-h-screen w-full px-4 py-6 sm:px-8 sm:py-10">
      <section className="mx-auto grid w-full max-w-7xl gap-5 lg:grid-cols-[320px_1fr]">
        <DashboardSidebar
          session={session}
          repositories={repositories}
          selectedRepoId={selectedRepoId}
          onSelectRepo={setSelectedRepoId}
          onResetAnalysis={() => {
            setStaticAnalysis(idleStaticAnalysis);
            setDynamicReport(idleDynamicAnalysis);
          }}
        />

        <div className="space-y-5">
          <section className="glass-card reveal-up p-5" style={{ animationDelay: "90ms" }}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="eyebrow">Selected Repository</p>
                <h2 className="text-2xl font-bold text-default">{selectedRepo?.name ?? "No repository selected"}</h2>
              </div>
              <div className="flex flex-wrap gap-2">
                {selectedRepo?.ecosystems.map((ecosystem) => (
                  <span key={ecosystem} className="badge">
                    {ecosystem.toUpperCase()}
                  </span>
                ))}
                <span className="badge">Risk {selectedRepo?.riskScore ?? 0}/100</span>
              </div>
            </div>
          </section>

          <section className="grid gap-5 xl:grid-cols-2">
            <article className="glass-card reveal-up space-y-3 p-5" style={{ animationDelay: "140ms" }}>
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-default">npm Dependency Tree</h3>
                <span className="text-xs text-muted">{apiContract.dependencyTree}</span>
              </div>
              {selectedRepo ? <DependencyTree nodes={selectedRepo.dependencies} ecosystem="npm" /> : null}
            </article>

            <article className="glass-card reveal-up space-y-3 p-5" style={{ animationDelay: "180ms" }}>
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-default">PyPI Dependency Tree</h3>
                <span className="text-xs text-muted">{apiContract.dependencyTree}</span>
              </div>
              {selectedRepo ? <DependencyTree nodes={selectedRepo.dependencies} ecosystem="pypi" /> : null}
            </article>
          </section>

          <section className="grid gap-5 xl:grid-cols-2">
            <article className="glass-card reveal-up space-y-4 p-5" style={{ animationDelay: "220ms" }}>
              <h3 className="text-lg font-semibold text-default">Add Dependency</h3>
              <form className="space-y-3" onSubmit={handleDependencyAdd}>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div>
                    <label className="label" htmlFor="dependency-name">
                      Package Name
                    </label>
                    <input
                      id="dependency-name"
                      className="input"
                      value={dependencyName}
                      onChange={(event) => setDependencyName(event.target.value)}
                      placeholder="lodash"
                      required
                    />
                  </div>
                  <div>
                    <label className="label" htmlFor="dependency-version">
                      Version
                    </label>
                    <input
                      id="dependency-version"
                      className="input"
                      value={dependencyVersion}
                      onChange={(event) => setDependencyVersion(event.target.value)}
                      placeholder="^4.17.21"
                    />
                  </div>
                </div>

                <div>
                  <label className="label" htmlFor="dependency-ecosystem">
                    Ecosystem
                  </label>
                  <select
                    id="dependency-ecosystem"
                    className="input"
                    value={dependencyEcosystem}
                    onChange={(event) => setDependencyEcosystem(event.target.value as Ecosystem)}
                  >
                    <option value="npm">npm</option>
                    <option value="pypi">PyPI</option>
                  </select>
                </div>

                <button type="submit" className="button-primary">
                  Queue Dependency Update
                </button>
              </form>

              <ul className="space-y-2">
                {queuedChanges.slice(0, 4).map((change) => (
                  <li key={change.id} className="panel-inset rounded-xl p-3 text-sm text-default">
                    {change.packageName}@{change.version} ({change.ecosystem}) queued for {repositories.find(
                      (repo) => repo.id === change.repositoryId,
                    )?.name ?? "repository"}
                  </li>
                ))}
              </ul>
            </article>

            <article className="glass-card reveal-up space-y-4 p-5" style={{ animationDelay: "260ms" }}>
              <h3 className="text-lg font-semibold text-default">Analysis Pipeline</h3>

              <div className="panel-inset space-y-2 rounded-2xl p-4">
                <p className="label">Static Analysis</p>
                <p className="text-sm text-default">{staticAnalysis.summary}</p>
                <p className="text-xs text-muted">API: {apiContract.staticAnalysis}</p>
                {typeof staticAnalysis.modelConfidence === "number" ? (
                  <p className="text-xs text-muted">
                    Confidence: {(staticAnalysis.modelConfidence * 100).toFixed(1)}%
                  </p>
                ) : null}
                {staticAnalysis.suspiciousCalls && staticAnalysis.suspiciousCalls.length > 0 ? (
                  <p className="text-xs text-warning">
                    Flagged syscalls: {staticAnalysis.suspiciousCalls.join(", ")}
                  </p>
                ) : null}
                <button type="button" className="button-secondary" onClick={runStaticAnalysis}>
                  Run Classification Model
                </button>
              </div>

              <div className="panel-inset space-y-2 rounded-2xl p-4">
                <p className="label">Dynamic Analysis (VM Container)</p>
                <p className="text-sm text-default">{dynamicReport.notes}</p>
                <p className="text-xs text-muted">API: {apiContract.dynamicAnalysis}</p>
                {dynamicReport.suspiciousCalls.length > 0 ? (
                  <p className="text-xs text-danger">
                    Observed suspicious syscalls: {dynamicReport.suspiciousCalls.join(", ")}
                  </p>
                ) : null}
                <button
                  type="button"
                  className="button-secondary"
                  onClick={launchDynamicAnalysis}
                  disabled={
                    staticAnalysis.status !== "empty" && staticAnalysis.status !== "warning"
                  }
                >
                  Launch Disposable VM and Trace Behavior
                </button>
                <p className="text-xs text-muted">
                  Enable this step when static classification is inconclusive or warns of risk.
                </p>
              </div>
            </article>
          </section>
        </div>
      </section>
    </main>
  );
}
