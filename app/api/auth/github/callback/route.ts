import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { authCookies, encodeSession } from "@/app/lib/auth/session";

interface GithubTokenResponse {
  access_token?: string;
  token_type?: string;
  scope?: string;
  error?: string;
}

interface GithubUserResponse {
  id: number;
  login: string;
  name: string | null;
  avatar_url: string;
}

function getBaseUrl(request: Request): string {
  const forwardedHost = request.headers.get("x-forwarded-host");
  const forwardedProto = request.headers.get("x-forwarded-proto") || "http";

  if (forwardedHost) {
    return `${forwardedProto}://${forwardedHost}`;
  }

  return new URL(request.url).origin;
}

export async function GET(request: Request) {
  const requestUrl = new URL(request.url);
  const code = requestUrl.searchParams.get("code");
  const state = requestUrl.searchParams.get("state");

  const cookieStore = await cookies();
  const stateCookie = cookieStore.get(authCookies.state)?.value;

  if (!code || !state || !stateCookie || state !== stateCookie) {
    return NextResponse.redirect(new URL("/login?error=invalid_state", request.url));
  }

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return NextResponse.redirect(new URL("/login?error=missing_secret", request.url));
  }

  const baseUrl = getBaseUrl(request);
  const callbackUrl = `${baseUrl}/api/auth/github/callback`;

  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: callbackUrl,
    }),
    cache: "no-store",
  });

  if (!tokenResponse.ok) {
    return NextResponse.redirect(new URL("/login?error=token_exchange_failed", request.url));
  }

  const tokenJson = (await tokenResponse.json()) as GithubTokenResponse;
  if (!tokenJson.access_token || tokenJson.error) {
    return NextResponse.redirect(new URL("/login?error=token_missing", request.url));
  }

  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${tokenJson.access_token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    cache: "no-store",
  });

  if (!userResponse.ok) {
    return NextResponse.redirect(new URL("/login?error=user_fetch_failed", request.url));
  }

  const userJson = (await userResponse.json()) as GithubUserResponse;
  const response = NextResponse.redirect(new URL("/dashboard", request.url));

  response.cookies.set(authCookies.state, "", {
    path: "/",
    maxAge: 0,
  });

  response.cookies.set(
    authCookies.session,
    encodeSession({
      id: userJson.id,
      login: userJson.login,
      name: userJson.name ?? userJson.login,
      avatarUrl: userJson.avatar_url,
    }),
    {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 60 * 60 * 8,
    },
  );

  response.cookies.set(authCookies.token, tokenJson.access_token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 8,
  });

  return response;
}
