import { NextRequest } from "next/server";

import { forward } from "@/lib/forward";

export function GET(req: NextRequest) {
  const query = new URLSearchParams();
  for (const key of ["limit", "offset"]) {
    const value = req.nextUrl.searchParams.get(key);
    if (value !== null) query.set(key, value);
  }
  const suffix = query.size ? `?${query}` : "";
  return forward(req, { obj: "users", act: "list", path: `/api/users${suffix}` });
}

export function POST(req: NextRequest) {
  return forward(req, { obj: "users", act: "create", path: "/api/users" });
}
