import crypto from "node:crypto";

import { NextResponse } from "next/server";

import { authCookies } from "@/app/lib/auth/session";

function getBaseUrl(request: Request): string {
  const forwardedHost = request.headers.get("x-forwarded-host");
  const forwardedProto = request.headers.get("x-forwarded-proto") || "http";

  if (forwardedHost) {
    return `${forwardedProto}://${forwardedHost}`;
  }

  return new URL(request.url).origin;
}

export async function GET(request: Request) {
  const clientId = process.env.GITHUB_CLIENT_ID;

  if (!clientId) {
    return NextResponse.redirect(new URL("/login?error=missing_client_id", request.url));
  }

  const state = crypto.randomUUID();
  const baseUrl = getBaseUrl(request);
  const callbackUrl = `${baseUrl}/api/auth/github/callback`;

  const githubAuthorizeUrl = new URL("https://github.com/login/oauth/authorize");
  githubAuthorizeUrl.searchParams.set("client_id", clientId);
  githubAuthorizeUrl.searchParams.set("redirect_uri", callbackUrl);
  githubAuthorizeUrl.searchParams.set("scope", "read:user repo");
  githubAuthorizeUrl.searchParams.set("state", state);

  const response = NextResponse.redirect(githubAuthorizeUrl);
  response.cookies.set(authCookies.state, state, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 10,
  });

  return response;
}
