const GITHUB_LOGIN_URL = "http://localhost:8000/api/auth/github/login";

function FeaturePill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-full border border-cyan-400/25 bg-cyan-500/10 px-4 py-2 text-xs text-cyan-200 backdrop-blur-sm sm:text-sm">
      <span className="mr-2 text-cyan-100/70">{label}</span>
      <span className="font-semibold tracking-wide text-cyan-100">{value}</span>
    </div>
  );
}

function CapabilityCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 p-5 shadow-[0_0_0_1px_rgba(15,23,42,0.6)]">
      <p className="text-xs uppercase tracking-[0.22em] text-slate-400">{title}</p>
      <p className="mt-2 text-sm leading-relaxed text-slate-300">{description}</p>
    </div>
  );
}

export default function HomePage() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-slate-950 text-slate-100">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_20%,rgba(6,182,212,0.24),transparent_42%),radial-gradient(circle_at_80%_0%,rgba(16,185,129,0.2),transparent_38%),linear-gradient(130deg,rgba(2,6,23,1)_0%,rgba(3,7,18,1)_42%,rgba(2,6,23,1)_100%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(148,163,184,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.08)_1px,transparent_1px)] bg-[size:42px_42px] opacity-20" />

      <section className="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col justify-center px-6 py-20 sm:px-10">
        <div className="reveal-up space-y-10">
          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/30 bg-emerald-500/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.24em] text-emerald-200">
            SentinelFlow
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />
            Dependency Security Workspace
          </div>

          <div className="max-w-4xl space-y-6">
            <h1 className="font-['Rajdhani',_Space_Grotesk,_sans-serif] text-5xl font-bold leading-[1.03] tracking-tight text-slate-100 sm:text-6xl lg:text-7xl">
              Inspect Dependencies.
              <br />
              <span className="text-cyan-300">See What Needs Attention.</span>
            </h1>
            <p className="max-w-2xl text-base leading-relaxed text-slate-300 sm:text-lg">
              SentinelFlow helps you review dependency trees, understand repository risk, and move from scan results to next steps without leaving the dashboard.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <FeaturePill label="Repository setup" value="GitHub App install" />
            <FeaturePill label="Dependency view" value="npm and PyPI trees" />
            <FeaturePill label="Analysis" value="Static and dynamic checks" />
          </div>

          <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
            <a
              href={GITHUB_LOGIN_URL}
              className="inline-flex items-center justify-center gap-3 rounded-xl border border-cyan-300/40 bg-cyan-400/20 px-7 py-3.5 text-sm font-semibold tracking-wide text-cyan-100 shadow-[0_14px_28px_-12px_rgba(6,182,212,0.65)] transition duration-200 hover:border-cyan-200/80 hover:bg-cyan-400/30 hover:text-white"
            >
              <span>Install SentinelFlow</span>
              <span aria-hidden="true">-&gt;</span>
            </a>
            <p className="text-sm text-slate-400">
              Starts the GitHub authorization flow from
              <span className="ml-1 font-medium text-slate-200">localhost:8000</span>
            </p>
          </div>
        </div>

        <div className="mt-14 grid gap-4 sm:grid-cols-3">
          <CapabilityCard
            title="Scan repository trees"
            description="Open a repository, trigger a scan, and build a dependency graph for the selected ecosystem."
          />
          <CapabilityCard
            title="Read graph context"
            description="Use the graph view and minimap to inspect package structure, transitive dependencies, and layout at a glance."
          />
          <CapabilityCard
            title="Review analysis results"
            description="See static and dynamic analysis summaries, then decide what to patch or investigate next."
          />
        </div>
      </section>
    </main>
  );
}
