import { redirect } from "@sveltejs/kit";
import type { Actions } from "./$types";
import { identityClient } from "$lib/identity";

export const actions = {
  default: async ({ cookies }) => {
    const client = identityClient();
    const { url, codeVerifier, state, nonce } = await client.authorizeUrl();
    cookies.set("mock_oidc", JSON.stringify({ codeVerifier, state, nonce }), {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 600,
    });
    throw redirect(303, url);
  },
} satisfies Actions;
