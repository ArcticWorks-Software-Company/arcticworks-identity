/** Safe redirect target for post-login navigation (open-redirect guard).
 *
 * Allowed:
 * - relative paths starting with `/` (never `//` — protocol-relative), or
 * - absolute URLs whose origin is this Identity deployment: the API origin
 *   in development (`PUBLIC_API_URL`/`apiBase()`), or the current origin in
 *   same-origin production deployments.
 *
 * The OAuth continuation built by the API is an absolute URL pointing at the
 * API's own authorize endpoint, so it must survive this check.
 */

import { apiBase } from "$lib/api/client";

export function safeContinue(raw: string | null | undefined): string {
  if (!raw) return "";
  if (raw.startsWith("/") && !raw.startsWith("//")) return raw;

  try {
    const url = new URL(raw);
    const api = apiBase();
    const allowed = api
      ? url.origin === new URL(api).origin
      : url.origin === window.location.origin;
    return allowed ? raw : "";
  } catch {
    return "";
  }
}
