import { redirect } from "next/navigation";

import { getGithubSession } from "@/app/lib/auth/session";

const oauthErrors: Record<string, string> = {
  missing_client_id: "GitHub OAuth client id is missing on the server.",
  missing_secret: "GitHub OAuth client secret is missing on the server.",
  invalid_state: "Session validation failed. Please try signing in again.",
  token_exchange_failed: "GitHub token exchange failed.",
  token_missing: "GitHub did not return an access token.",
  user_fetch_failed: "Unable to fetch your GitHub profile.",
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const session = await getGithubSession();
  if (session) {
    redirect("/dashboard");
  }

  const { error } = await searchParams;
  const message = error ? oauthErrors[error] ?? "OAuth login failed." : null;

  return (
    <main className="app-shell min-h-screen w-full px-4 py-10 sm:px-8">
      <section className="mx-auto flex w-full max-w-xl items-center justify-center">
        <div className="glass-card reveal-up w-full space-y-6 p-8">
          <header className="space-y-2 text-center">
            <p className="eyebrow">SentinelFlow</p>
            <h1 className="text-3xl font-bold text-default">Sign in with GitHub</h1>
            <p className="text-sm text-muted">
              Authenticate with GitHub OAuth before managing repositories and dependency analysis.
            </p>
          </header>

          {message ? (
            <p className="panel-inset rounded-lg p-3 text-sm text-danger">{message}</p>
          ) : null}

          <a
            href="/api/auth/github"
            className="button-primary flex w-full items-center justify-center py-2.5 text-sm"
          >
            Continue with GitHub OAuth
          </a>

          <p className="text-xs text-muted">
            Required environment variables: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.
          </p>
        </div>
      </section>
    </main>
  );
}
