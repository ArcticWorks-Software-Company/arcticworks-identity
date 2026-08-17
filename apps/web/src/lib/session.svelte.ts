/** Session store. Loads `/api/auth/me` in the browser; the session cookie is
 * owned by the API (same-site, credentials: include). */

import { browser } from "$app/environment";
import { api } from "$lib/api/client";
import type { MeResponse } from "$lib/api/types";

export interface SessionState {
  loading: boolean;
  me: MeResponse | null;
  error: string | null;
}

let state = $state<SessionState>({ loading: true, me: null, error: null });

export function sessionState(): SessionState {
  return state;
}

let loaded = false;

/** Fetch the current session (browser only). Safe to call repeatedly. */
export async function refreshSession(): Promise<MeResponse | null> {
  if (!browser) return null;
  try {
    const me = await api.get<MeResponse>("/api/auth/me");
    state.loading = false;
    state.me = me;
    state.error = null;
    loaded = true;
    return me;
  } catch (err) {
    const e = err as { status?: number; message?: string };
    state.loading = false;
    state.me = null;
    if (e.status === 401) {
      state.error = null;
      loaded = true;
      return null;
    }
    state.error = e.message ?? "Failed to load session";
    loaded = true;
    return null;
  }
}

/** Idempotent initial load. */
export function ensureSessionLoaded(): Promise<MeResponse | null> {
  if (loaded || !browser) return Promise.resolve(state.me);
  return refreshSession();
}

export function signOut() {
  state.loading = false;
  state.me = null;
  state.error = null;
  loaded = false;
}
