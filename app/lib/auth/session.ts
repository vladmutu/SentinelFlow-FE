import { cookies } from "next/headers";

import { GithubSession } from "@/app/types/dashboard";

const SESSION_COOKIE_NAME = "sf_session";

export function encodeSession(session: GithubSession): string {
  return Buffer.from(JSON.stringify(session), "utf8").toString("base64url");
}

export function decodeSession(raw: string | undefined): GithubSession | null {
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
    if (
      typeof parsed?.id !== "number" ||
      typeof parsed?.login !== "string" ||
      typeof parsed?.name !== "string" ||
      typeof parsed?.avatarUrl !== "string"
    ) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

export async function getGithubSession(): Promise<GithubSession | null> {
  const cookieStore = await cookies();
  const cookieValue = cookieStore.get(SESSION_COOKIE_NAME)?.value;
  return decodeSession(cookieValue);
}

export const authCookies = {
  session: SESSION_COOKIE_NAME,
  token: "sf_github_token",
  state: "sf_oauth_state",
};
