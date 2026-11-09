import "server-only";

import { getToken } from "./auth";
import { gatewayFetch } from "./gateway";
import type { RolesResponse } from "./types";

export async function loadRoles(): Promise<RolesResponse> {
  const res = await gatewayFetch("/api/roles", { token: await getToken() });
  if (!res.ok) throw new Error(`Could not load roles (${res.status})`);
  return res.json();
}
