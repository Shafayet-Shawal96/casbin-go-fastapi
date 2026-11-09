import { NextRequest, NextResponse } from "next/server";

import { SESSION_COOKIE } from "@/lib/auth";
import { gatewayFetch } from "@/lib/gateway";

const ONE_HOUR = 60 * 60;

export async function POST(req: NextRequest) {
  let res: Response;
  try {
    res = await gatewayFetch("/auth/login", { method: "POST", body: await req.text() });
  } catch (error) {
    console.error("login request failed", error);
    return NextResponse.json({ detail: "service unavailable" }, { status: 502 });
  }

  const body = await res.json().catch(() => ({ detail: "login failed" }));
  if (!res.ok) return NextResponse.json(body, { status: res.status });

  const response = NextResponse.json({ ok: true });
  response.cookies.set(SESSION_COOKIE, body.token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.COOKIE_SECURE === "true",
    path: "/",
    maxAge: ONE_HOUR,
  });
  return response;
}
