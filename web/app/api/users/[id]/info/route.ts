import { NextRequest } from "next/server";

import { forward, invalidId, parseId } from "@/lib/forward";

type Context = { params: Promise<{ id: string }> };

export async function PATCH(req: NextRequest, { params }: Context) {
  const targetId = parseId((await params).id);
  if (targetId === undefined) return invalidId();
  return forward(req, {
    obj: "user_info",
    act: "update",
    targetId,
    path: `/api/users/${targetId}/info`,
  });
}
