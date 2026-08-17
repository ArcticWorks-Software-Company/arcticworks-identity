/** Typed API client for the Identity backend. Browser-side only: every
 * request carries the session cookie (credentials: include). */

export interface ApiErrorPayload {
  error: { code: string; message: string };
}

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }

  get isReauthRequired() {
    return this.code === "reauth_required";
  }
}

export function apiBase(): string {
  // Same-origin by default (production: nginx serves /api on the same host).
  // Development talks to the API on its own port.
  if (import.meta.env.DEV) return "http://localhost:8080";
  return "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";

  const resp = await fetch(`${apiBase()}${path}`, {
    method,
    headers,
    credentials: "include",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (resp.status === 204) return undefined as T;

  const payload = (await resp.json().catch(() => ({}))) as ApiErrorPayload | T;
  if (!resp.ok) {
    const err = (payload as ApiErrorPayload).error ?? { code: "internal", message: `HTTP ${resp.status}` };
    throw new ApiError(err.code, err.message, resp.status);
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

/** Query params for a URL (for OAuth state strings). */
export function qs(params: Record<string, string | undefined>): string {
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") search.set(k, v);
  }
  const s = search.toString();
  return s ? `?${s}` : "";
}
