import { NextRequest } from "next/server";

import { forward, invalidId, parseId } from "@/lib/forward";

type Context = { params: Promise<{ id: string }> };

export async function PUT(req: NextRequest, { params }: Context) {
  const targetId = parseId((await params).id);
  if (targetId === undefined) return invalidId();
  return forward(req, {
    obj: "user_role",
    act: "assign",
    targetId,
    path: `/api/users/${targetId}/role`,
  });
}
