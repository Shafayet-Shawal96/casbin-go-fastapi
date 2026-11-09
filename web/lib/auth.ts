import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";

import { gatewayFetch } from "./gateway";
import type { CurrentUser } from "./types";

export const SESSION_COOKIE = "session";

export async function getToken(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value;
}

/** Loads the signed-in user and their Casbin permissions, or null if signed out. */
export const getSession = cache(async (): Promise<CurrentUser | null> => {
  const token = await getToken();
  if (!token) return null;

  const res = await gatewayFetch("/api/me", { token });
  if (res.status === 401) return null;
  if (!res.ok) throw new Error(`Could not load session (${res.status})`);
  return res.json();
});

/** True if the user holds the permission, for this target where scope is "own". */
export function can(user: CurrentUser, obj: string, act: string, targetId?: number): boolean {
  return user.permissions.some(
    (p) =>
      p.obj === obj &&
      p.act === act &&
      (p.scope === "any" || (targetId !== undefined && targetId === user.id)),
  );
}

export async function requireUser(): Promise<CurrentUser> {
  const user = await getSession();
  if (!user) redirect("/login");
  return user;
}

/** Page-level check: sends the user away unless they hold the permission. */
export async function requirePermission(obj: string, act: string): Promise<CurrentUser> {
  const user = await requireUser();
  if (!can(user, obj, act)) redirect("/forbidden");
  return user;
}
