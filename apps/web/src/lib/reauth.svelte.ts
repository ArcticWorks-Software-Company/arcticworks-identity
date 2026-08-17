/** Reauthentication gate: sensitive actions require a fresh password entry.
 * Catches `reauth_required` errors, prompts for the password once, then
 * retries the action. */

import { ApiError, api } from "$lib/api/client";

interface PendingReauth {
  resolve: () => void;
  reject: (e: unknown) => void;
}

const reauth = $state<{ pending: PendingReauth | null; busy: boolean; error: string }>({
  pending: null,
  busy: false,
  error: "",
});

export function reauthState() {
  return reauth;
}

export function closeReauth() {
  reauth.pending?.reject(new Error("Reauthentication cancelled"));
  reauth.pending = null;
  reauth.error = "";
}

export async function submitReauth(password: string): Promise<void> {
  reauth.busy = true;
  reauth.error = "";
  try {
    await api.post("/api/auth/reauth", { password });
    const p = reauth.pending;
    reauth.pending = null;
    p?.resolve();
  } catch (e) {
    reauth.error = e instanceof Error ? e.message : "Reauthentication failed";
  } finally {
    reauth.busy = false;
  }
}

/** Run an action; if the API demands reauthentication, prompt and retry. */
export async function withReauth(run: () => Promise<void>): Promise<void> {
  try {
    await run();
  } catch (e) {
    if (e instanceof ApiError && e.isReauthRequired) {
      await new Promise<void>((resolve, reject) => {
        reauth.pending = { resolve, reject };
      });
      // Retry once after a successful reauthentication.
      await run();
    } else {
      throw e;
    }
  }
}
