import { GithubSession, Repository } from "@/app/types/dashboard";

interface DashboardSidebarProps {
  session: GithubSession;
  repositories: Repository[];
  selectedRepoId: string;
  onSelectRepo: (repoId: string) => void;
  onResetAnalysis: () => void;
}

export function DashboardSidebar({
  session,
  repositories,
  selectedRepoId,
  onSelectRepo,
  onResetAnalysis,
}: DashboardSidebarProps) {
  return (
    <aside className="glass-card reveal-up space-y-5 p-5">
      <header className="space-y-3">
        <p className="eyebrow">SentinelFlow</p>
        <h1 className="text-2xl font-bold text-default">Dependency Security Dashboard</h1>
        <p className="text-sm text-muted">
          Inspect npm and PyPI trees, queue dependency updates, and trigger static and dynamic
          analysis.
        </p>
      </header>

      <div className="panel-inset space-y-3 rounded-2xl p-4">
        <p className="label">Authenticated Account</p>
        <div className="panel-inset flex items-center gap-3 rounded-lg px-3 py-2.5">
          <div className="avatar-chip">
            {session.login.slice(0, 1).toUpperCase()}
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-default">{session.name}</p>
            <p className="truncate text-xs text-muted">@{session.login}</p>
          </div>
        </div>
        <form action="/api/auth/logout" method="post">
          <button type="submit" className="button-secondary w-full">
            Sign out
          </button>
        </form>
      </div>

      <div className="space-y-2">
        <p className="label">Repositories ({repositories.length} repositories)</p>
        <ul className="space-y-2">
          {repositories.map((repo) => (
            <li key={repo.id}>
              <button
                type="button"
                className={`repo-item ${selectedRepoId === repo.id ? "repo-item-active" : ""}`}
                onClick={() => {
                  onSelectRepo(repo.id);
                  onResetAnalysis();
                }}
              >
                <span className="font-semibold text-default">{repo.name}</span>
                <span className="text-xs text-muted">
                  {repo.visibility} · pushed {repo.lastPush}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </aside>
  );
}
