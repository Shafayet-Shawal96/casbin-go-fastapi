import { NextResponse } from "next/server";

import { getSession } from "@/lib/auth";

export async function GET() {
  try {
    const user = await getSession();
    if (!user) return NextResponse.json({ detail: "authentication required" }, { status: 401 });
    return NextResponse.json(user);
  } catch (error) {
    console.error("gateway request failed", error);
    return NextResponse.json({ detail: "service unavailable" }, { status: 502 });
  }
}
