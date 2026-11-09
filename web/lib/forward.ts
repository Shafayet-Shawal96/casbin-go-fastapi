import "server-only";

import { NextRequest, NextResponse } from "next/server";

import { can, getSession, getToken } from "./auth";
import { gatewayFetch } from "./gateway";

type ForwardOptions = {
  obj: string;
  act: string;
  /** Gateway path, including any query string. */
  path: string;
  targetId?: number;
};

function detail(message: string, status: number) {
  return NextResponse.json({ detail: message }, { status });
}

/** Parses a route id, returning undefined unless it is a plain positive number. */
export function parseId(raw: string): number | undefined {
  return /^[1-9][0-9]{0,17}$/.test(raw) ? Number(raw) : undefined;
}

export function invalidId() {
  return detail("invalid user id", 400);
}

/** Authorizes the request in Next.js, then forwards it to the Go gateway. */
export async function forward(req: NextRequest, options: ForwardOptions) {
  try {
    const user = await getSession();
    const token = await getToken();
    if (!user || !token) return detail("authentication required", 401);
    if (!can(user, options.obj, options.act, options.targetId)) return detail("forbidden", 403);

    const hasBody = req.method !== "GET";
    const res = await gatewayFetch(options.path, {
      method: req.method,
      token,
      body: hasBody ? await req.text() : undefined,
    });
    return new NextResponse(await res.text(), {
      status: res.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("gateway request failed", error);
    return detail("service unavailable", 502);
  }
}
