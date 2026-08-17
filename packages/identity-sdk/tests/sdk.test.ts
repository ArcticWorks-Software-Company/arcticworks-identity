import { describe, expect, it, vi } from "vitest";
import {
  OidcClient,
  PermissionClient,
  decodeJwtPayload,
  generateCodeVerifier,
  generatePkceChallenge,
  IdentityError,
} from "../src/index.js";

const DISCOVERY = {
  issuer: "http://identity.test",
  authorization_endpoint: "http://identity.test/oidc/authorize",
  token_endpoint: "http://identity.test/oidc/token",
  userinfo_endpoint: "http://identity.test/oidc/userinfo",
  jwks_uri: "http://identity.test/oidc/jwks.json",
  revocation_endpoint: "http://identity.test/oidc/revoke",
  end_session_endpoint: "http://identity.test/oidc/end-session",
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
  code_challenge_methods_supported: ["S256"],
  scopes_supported: ["openid", "profile", "email", "offline_access"],
  claims_supported: ["sub", "name", "email", "email_verified"],
};

function mockFetch(routes: Record<string, unknown>): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    for (const [pattern, payload] of Object.entries(routes)) {
      if (url.includes(pattern)) {
        return new Response(JSON.stringify(payload), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
    }
    return new Response(JSON.stringify({ error: { code: "not_found", message: "no route" } }), { status: 404 });
  }) as unknown as typeof fetch;
}

describe("PKCE", () => {
  it("generates a verifier and a matching S256 challenge", async () => {
    const verifier = await generateCodeVerifier();
    expect(verifier.length).toBeGreaterThan(40);
    const challenge = await generatePkceChallenge(verifier);

    // RFC 7636: challenge = base64url(SHA-256(ASCII(verifier)))
    const data = new TextEncoder().encode(verifier);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(challenge).toBe(expected);
  });

  it("produces distinct values per call", async () => {
    const a = await generateCodeVerifier();
    const b = await generateCodeVerifier();
    expect(a).not.toBe(b);
  });
});

describe("OidcClient", () => {
  const config = {
    issuer: "http://identity.test",
    clientId: "awapp_test",
    redirectUri: "http://localhost:5174/callback",
  };

  it("builds the OIDC end-session URL with hint, redirect and state", async () => {
    const client = new OidcClient(config, mockFetch({ "/.well-known/openid-configuration": DISCOVERY }));
    const url = await client.endSessionUrl({
      idTokenHint: "id.jwt.token",
      postLogoutRedirectUri: "http://localhost:5174/logout",
      state: "bye",
    });
    expect(url).not.toBeNull();
    const parsed = new URL(url!);
    expect(parsed.origin + parsed.pathname).toBe("http://identity.test/oidc/end-session");
    expect(parsed.searchParams.get("id_token_hint")).toBe("id.jwt.token");
    expect(parsed.searchParams.get("post_logout_redirect_uri")).toBe("http://localhost:5174/logout");
    expect(parsed.searchParams.get("client_id")).toBe("awapp_test");
    expect(parsed.searchParams.get("state")).toBe("bye");
  });

  it("builds an authorize URL with PKCE, state and nonce", async () => {
    const client = new OidcClient(config, mockFetch({ "/.well-known/openid-configuration": DISCOVERY }));
    const { url, codeVerifier, state, nonce } = await client.authorizeUrl();

    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe("http://identity.test/oidc/authorize");
    expect(parsed.searchParams.get("client_id")).toBe("awapp_test");
    expect(parsed.searchParams.get("response_type")).toBe("code");
    expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
    expect(parsed.searchParams.get("state")).toBe(state);
    expect(parsed.searchParams.get("nonce")).toBe(nonce);
    expect(parsed.searchParams.get("code_challenge")).toBe(
      await generatePkceChallenge(codeVerifier),
    );
    expect(parsed.searchParams.get("scope")).toContain("openid");
  });

  it("exchanges a code for tokens", async () => {
    const client = new OidcClient(
      { ...config, clientSecret: "s3cret" },
      mockFetch({
        "/.well-known/openid-configuration": DISCOVERY,
        "/oidc/token": {
          access_token: "at-1",
          token_type: "Bearer",
          expires_in: 900,
          id_token: "id.jwt.token",
          refresh_token: "rt-1",
        },
      }),
    );
    const tokens = await client.exchangeCode("code-1", { codeVerifier: "verifier-1" });
    expect(tokens.access_token).toBe("at-1");
    expect(tokens.refresh_token).toBe("rt-1");
  });

  it("maps API errors to IdentityError", async () => {
    const client = new OidcClient(
      config,
      vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).includes("openid-configuration")) {
          return new Response(JSON.stringify(DISCOVERY), { status: 200 });
        }
        return new Response(
          JSON.stringify({ error: { code: "invalid_grant", message: "PKCE verification failed" } }),
          { status: 422, headers: { "content-type": "application/json" } },
        );
      }) as unknown as typeof fetch,
    );
    await expect(client.exchangeCode("code", { codeVerifier: "v" })).rejects.toMatchObject({
      code: "invalid_grant",
    });
  });

  it("rotates refresh tokens", async () => {
    const client = new OidcClient(
      { ...config, clientSecret: "s3cret" },
      mockFetch({
        "/.well-known/openid-configuration": DISCOVERY,
        "/oidc/token": { access_token: "at-2", token_type: "Bearer", expires_in: 900, refresh_token: "rt-2" },
      }),
    );
    const tokens = await client.refresh("rt-1");
    expect(tokens.refresh_token).toBe("rt-2");
  });

  it("decodes JWT payloads", () => {
    const header = btoa(JSON.stringify({ alg: "RS256" })).replace(/=+$/, "");
    const payload = btoa(JSON.stringify({ sub: "user-1", email: "a@b.co" })).replace(/=+$/, "");
    const claims = decodeJwtPayload<{ sub: string; email: string }>(`${header}.${payload}.sig`);
    expect(claims.sub).toBe("user-1");
    expect(claims.email).toBe("a@b.co");
  });
});

describe("PermissionClient", () => {
  it("mints a client_credentials token and checks permissions", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      if (String(input).includes("/oidc/token")) {
        return new Response(JSON.stringify({ access_token: "sa-token", expires_in: 900 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(
        JSON.stringify({ allowed: true, organizationId: "org-1", userId: "user-1", permission: "continuity.document.read" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    const client = new PermissionClient(
      { issuer: "http://identity.test", clientId: "awsa_x", clientSecret: "secret" },
      fetchImpl,
    );
    const allowed = await client.checkPermission({
      organizationId: "org-1",
      userId: "user-1",
      permission: "continuity.document.read",
    });
    expect(allowed).toBe(true);

    const tokenCall = calls.find((c) => c.url.includes("/oidc/token"));
    expect(String(tokenCall?.init?.body)).toContain("grant_type=client_credentials");

    const checkCall = calls.find((c) => c.url.includes("/authorize/check"));
    expect(checkCall?.init?.headers).toMatchObject({ authorization: "Bearer sa-token" });
  });

  it("throws IdentityError on denied auth", async () => {
    const client = new PermissionClient(
      { issuer: "http://identity.test", clientId: "awsa_x", clientSecret: "bad" },
      (async () => {
        return new Response(
          JSON.stringify({ error: { code: "invalid_client", message: "invalid client credentials" } }),
          { status: 422, headers: { "content-type": "application/json" } },
        );
      }) as unknown as typeof fetch,
    );
    await expect(
      client.checkPermission({ organizationId: "o", userId: "u", permission: "a.b.c" }),
    ).rejects.toBeInstanceOf(IdentityError);
  });
});
