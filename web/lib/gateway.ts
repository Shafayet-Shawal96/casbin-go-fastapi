import "server-only";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:8080";

type GatewayOptions = {
  method?: string;
  token?: string;
  body?: string;
};

/** Calls the Go gateway. Only server code can import this module. */
export function gatewayFetch(path: string, options: GatewayOptions = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (options.token) headers.Authorization = `Bearer ${options.token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  return fetch(`${GATEWAY_URL}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body,
    cache: "no-store",
  });
}
