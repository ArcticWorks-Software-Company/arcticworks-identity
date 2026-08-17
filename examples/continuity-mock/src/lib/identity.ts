import { env } from "$env/dynamic/private";
import { OidcClient, PermissionClient } from "@arcticworks/identity-sdk";

/** OIDC client for this mock product. */
export function identityClient(): OidcClient {
  return new OidcClient({
    issuer: env.IDENTITY_ISSUER ?? "http://localhost:8080",
    clientId: env.IDENTITY_CLIENT_ID ?? "awapp_continuity_mock",
    redirectUri: env.IDENTITY_REDIRECT_URI ?? "http://localhost:5174/callback",
    clientSecret: env.IDENTITY_CLIENT_SECRET ?? "",
  });
}

/** Permission client backed by the product's service account. */
export function permissionClient(): PermissionClient {
  const saClientId = env.IDENTITY_SA_CLIENT_ID ?? "";
  const saSecret = env.IDENTITY_SA_CLIENT_SECRET ?? "";
  return new PermissionClient({
    issuer: env.IDENTITY_ISSUER ?? "http://localhost:8080",
    clientId: saClientId,
    clientSecret: saSecret,
  });
}

export interface MockSession {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
}

export function decodeSessionCookie(value: string): MockSession {
  // SvelteKit's cookies API already URL-decodes stored values.
  return JSON.parse(value) as MockSession;
}

export function encodeSessionCookie(session: MockSession): string {
  // SvelteKit URL-encodes cookie values automatically — no manual encoding.
  return JSON.stringify(session);
}
