/** OIDC client for ArcticWorks Identity (authorization code + PKCE). */

import { createHash, randomBytes } from "node:crypto";
import { errorFromResponse, IdentityError } from "./errors.js";
import type {
  DeviceAuthorizationResponse,
  DiscoveryDocument,
  TokenSet,
  UserInfoClaims,
} from "./types.js";

export interface OidcClientConfig {
  /** Identity issuer, e.g. `https://identity.arcticworks.dev` or `http://localhost:8080`. */
  issuer: string;
  /** Registered client id (application). */
  clientId: string;
  /** Registered redirect URI of this application. */
  redirectUri: string;
  /** Requested scopes; `openid` is implied. */
  scopes?: string[];
  /** Optional confidential client secret (never use in browsers). */
  clientSecret?: string;
}

export interface AuthorizeResult {
  /** The full authorization URL to send the user to. */
  url: string;
  /** PKCE verifier — keep it on the server and use it at code exchange. */
  codeVerifier: string;
  /** CSRF state — verify it at the callback. */
  state: string;
  /** OIDC nonce — verify it in the decoded id_token. */
  nonce: string;
}

export interface ExchangeOptions {
  codeVerifier: string;
  redirectUri?: string;
}

const PKCE_VERIFIER_LENGTH = 64;

function secureRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function generateCodeVerifier(length = PKCE_VERIFIER_LENGTH): Promise<string> {
  return base64Url(secureRandomBytes(length));
}

export async function generatePkceChallenge(verifier: string): Promise<string> {
  const digest = createHash("sha256").update(verifier).digest();
  return base64Url(new Uint8Array(digest));
}

export function randomState(): string {
  return base64Url(secureRandomBytes(16));
}

export function randomNonce(): string {
  return base64Url(secureRandomBytes(16));
}

export class OidcClient {
  readonly config: OidcClientConfig;
  private discoveryCache?: Promise<DiscoveryDocument>;
  private readonly fetchImpl: typeof fetch;

  constructor(config: OidcClientConfig, fetchImpl: typeof fetch = fetch) {
    this.config = { scopes: ["openid", "profile", "email", "offline_access"], ...config };
    this.fetchImpl = fetchImpl;
  }

  /** Discovery document (cached per client instance). */
  discovery(): Promise<DiscoveryDocument> {
    if (!this.discoveryCache) {
      this.discoveryCache = this.fetchDiscovery();
    }
    return this.discoveryCache;
  }

  private async fetchDiscovery(): Promise<DiscoveryDocument> {
    const url = `${this.config.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
    const resp = await this.fetchImpl(url, { headers: { accept: "application/json" } });
    if (!resp.ok) throw new IdentityError("network", `Discovery failed: HTTP ${resp.status}`, resp.status);
    const doc = (await resp.json()) as DiscoveryDocument;
    if (doc.issuer !== this.config.issuer.replace(/\/$/, "")) {
      throw new IdentityError("internal", "Discovery issuer mismatch");
    }
    return doc;
  }

  /** Build the authorization URL with PKCE. Call at the start of a login. */
  async authorizeUrl(options?: { state?: string; nonce?: string; prompt?: "login" | "consent" }): Promise<AuthorizeResult> {
    const [doc, codeVerifier] = await Promise.all([this.discovery(), generateCodeVerifier()]);
    const codeChallenge = await generatePkceChallenge(codeVerifier);
    const state = options?.state ?? randomState();
    const nonce = options?.nonce ?? randomNonce();

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: "code",
      scope: this.config.scopes!.join(" "),
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    if (options?.prompt) params.set("prompt", options.prompt);

    return { url: `${doc.authorization_endpoint}?${params.toString()}`, codeVerifier, state, nonce };
  }

  /** Exchange the authorization code for tokens. */
  async exchangeCode(code: string, options: ExchangeOptions): Promise<TokenSet> {
    const doc = await this.discovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: options.redirectUri ?? this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: options.codeVerifier,
    });
    return this.tokenRequest(doc.token_endpoint, body);
  }

  /** Rotate the refresh token and obtain fresh tokens. */
  async refresh(refreshToken: string): Promise<TokenSet> {
    const doc = await this.discovery();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });
    return this.tokenRequest(doc.token_endpoint, body);
  }

  /** RFC 7009 token revocation. Always succeeds for unknown tokens. */
  async revoke(token: string): Promise<void> {
    const doc = await this.discovery();
    const body = new URLSearchParams({ token, client_id: this.config.clientId });
    if (this.config.clientSecret) body.set("client_secret", this.config.clientSecret);
    const resp = await this.fetchImpl(doc.revocation_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!resp.ok) throw errorFromResponse(resp.status, await resp.json().catch(() => ({})));
  }

  /** UserInfo for an access token (server-side use). */
  async userinfo(accessToken: string): Promise<UserInfoClaims> {
    const doc = await this.discovery();
    const resp = await this.fetchImpl(doc.userinfo_endpoint, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
    });
    if (!resp.ok) throw errorFromResponse(resp.status, await resp.json().catch(() => ({})));
    return (await resp.json()) as UserInfoClaims;
  }

  /** Build the OIDC RP-Initiated Logout URL. The caller sends the browser
   * there (optionally after clearing local tokens); the returned URL is only
   * meaningful when the application registered the `postLogoutRedirectUri`. */
  async endSessionUrl(options?: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string }): Promise<string | null> {
    const doc = await this.discovery();
    const endpoint = doc.end_session_endpoint;
    if (!endpoint) return null;
    const params = new URLSearchParams();
    if (options?.idTokenHint) params.set("id_token_hint", options.idTokenHint);
    if (options?.postLogoutRedirectUri) {
      params.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
      params.set("client_id", this.config.clientId);
    }
    if (options?.state) params.set("state", options.state);
    return `${endpoint}?${params.toString()}`;
  }

  /** RFC 8628: start a device authorization. Show the returned
   * `verification_uri_complete` (or `verification_uri` + `user_code`) to the
   * user, then poll with {@link pollDeviceCode}. */
  async deviceAuthorization(scopes?: string[]): Promise<DeviceAuthorizationResponse> {
    const doc = await this.discovery();
    const endpoint = doc.device_authorization_endpoint;
    if (!endpoint) {
      throw new IdentityError("internal", "Device flow is not supported by this issuer");
    }
    const body = new URLSearchParams({
      client_id: this.config.clientId,
      scope: (scopes ?? this.config.scopes!).join(" "),
    });
    if (this.config.clientSecret) body.set("client_secret", this.config.clientSecret);
    const resp = await this.fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!resp.ok) throw errorFromResponse(resp.status, await resp.json().catch(() => ({})));
    return (await resp.json()) as DeviceAuthorizationResponse;
  }

  /** RFC 8628: exchange a device code once. Throws while the user has not
   * completed the flow (`authorization_pending` / `slow_down`). */
  async exchangeDeviceCode(deviceCode: string): Promise<TokenSet> {
    const doc = await this.discovery();
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: deviceCode,
      client_id: this.config.clientId,
    });
    return this.tokenRequest(doc.token_endpoint, body);
  }

  /** Poll the token endpoint until the user completes (or denies/expires)
   * the device authorization. */
  async pollDeviceCode(deviceCode: string, options?: { intervalMs?: number; timeoutMs?: number }): Promise<TokenSet> {
    const intervalMs = options?.intervalMs ?? 5000;
    const timeoutMs = options?.timeoutMs ?? 15 * 60 * 1000;
    const started = Date.now();
    for (;;) {
      try {
        return await this.exchangeDeviceCode(deviceCode);
      } catch (e) {
        const pending =
          e instanceof IdentityError &&
          (e.message.startsWith("authorization_pending") || e.message.startsWith("slow_down"));
        if (!pending) throw e;
        if (Date.now() - started > timeoutMs) {
          throw new IdentityError("network", "Device authorization timed out");
        }
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
      }
    }
  }

  /** The end-session/return URL is the authorize flow's `prompt=login`; for
   * simple apps, clearing local tokens is the correct logout. */
  private async tokenRequest(endpoint: string, body: URLSearchParams): Promise<TokenSet> {
    if (this.config.clientSecret) body.set("client_secret", this.config.clientSecret);
    const resp = await this.fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!resp.ok) {
      const payload = await resp.json().catch(() => ({}));
      throw errorFromResponse(resp.status, payload);
    }
    return (await resp.json()) as TokenSet;
  }
}

/** Decode a JWT payload without verifying the signature. Verification must
 * be done with the issuer's JWKS (`OidcClient.userinfo` is the safe
 * server-side path). */
export function decodeJwtPayload<T = Record<string, unknown>>(jwt: string): T {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new IdentityError("token_invalid", "Malformed JWT");
  const payload = parts[1]!;
  const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const json = new TextDecoder().decode(
    Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)),
  );
  return JSON.parse(json) as T;
}
