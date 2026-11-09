import { NextRequest, NextResponse } from "next/server";

/** Redirects pages with no session cookie. API routes return their own 401. */
export function middleware(req: NextRequest) {
  if (req.cookies.has("session")) return NextResponse.next();
  return NextResponse.redirect(new URL("/login", req.url));
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|login).*)"],
};
