import { NextResponse } from "next/server";

import { authCookies } from "@/app/lib/auth/session";

export async function POST(request: Request) {
  const response = NextResponse.redirect(new URL("/login", request.url));
  response.headers.set("Clear-Site-Data", '"storage"');

  response.cookies.set(authCookies.session, "", {
    path: "/",
    maxAge: 0,
  });

  response.cookies.set(authCookies.token, "", {
    path: "/",
    maxAge: 0,
  });

  response.cookies.set(authCookies.state, "", {
    path: "/",
    maxAge: 0,
  });

  return response;
}
