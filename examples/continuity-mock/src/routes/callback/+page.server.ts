import { error, redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { encodeSessionCookie, identityClient } from "$lib/identity";

export const load: PageServerLoad = async ({ url, cookies }) => {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const errorParam = url.searchParams.get("error");
  const errorDescription = url.searchParams.get("error_description");
  const stored = cookies.get("mock_oidc");

  if (errorParam) {
    const query = new URLSearchParams({ loginError: errorParam });
    if (errorDescription) query.set("loginErrorDescription", errorDescription);
    cookies.delete("mock_oidc", { path: "/" });
    throw redirect(303, `/?${query}`);
  }
  if (!code || !state || !stored) throw error(400, "Missing authorization response parameters");

  const { codeVerifier, state: storedState } = JSON.parse(stored) as {
    codeVerifier: string;
    state: string;
    nonce: string;
  };
  if (state !== storedState) throw error(400, "State mismatch — possible CSRF");

  const client = identityClient();
  const tokens = await client.exchangeCode(code, { codeVerifier });

  const session = {
    accessToken: tokens.access_token,
    idToken: tokens.id_token,
    refreshToken: tokens.refresh_token,
    expiresAt: Math.floor(Date.now() / 1000) + tokens.expires_in,
  };
  cookies.set("mock_session", encodeSessionCookie(session), {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 12,
  });
  cookies.delete("mock_oidc", { path: "/" });
  throw redirect(303, "/");
};
