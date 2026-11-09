import { NextRequest } from "next/server";

import { forward, invalidId, parseId } from "@/lib/forward";

type Context = { params: Promise<{ id: string }> };

export async function POST(req: NextRequest, { params }: Context) {
  const targetId = parseId((await params).id);
  if (targetId === undefined) return invalidId();
  return forward(req, {
    obj: "users",
    act: "deactivate",
    targetId,
    path: `/api/users/${targetId}/deactivate`,
  });
}
