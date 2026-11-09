import { NextRequest } from "next/server";

import { forward } from "@/lib/forward";

export function GET(req: NextRequest) {
  return forward(req, { obj: "roles", act: "list", path: "/api/roles" });
}

export function POST(req: NextRequest) {
  return forward(req, { obj: "roles", act: "create", path: "/api/roles" });
}
