export type ApiResult<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; status: number; message: string };

type ErrorBody = { detail?: string | { msg: string }[] };

function errorMessage(body: ErrorBody | null): string {
  const value = body?.detail;
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((item) => item.msg).join(", ");
  return "Request failed";
}

/** Calls this app's Next.js API. The browser never talks to the gateway. */
export async function sendJson<T = unknown>(
  url: string,
  method: string,
  body?: unknown,
): Promise<ApiResult<T>> {
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    return { ok: false, status: 0, message: "Could not reach the server" };
  }

  const parsed = await res.json().catch(() => null);
  if (res.ok) return { ok: true, data: parsed as T };

  if (res.status === 401 && !url.startsWith("/api/auth/")) {
    window.location.assign("/login");
  }
  return { ok: false, status: res.status, message: errorMessage(parsed) };
}
