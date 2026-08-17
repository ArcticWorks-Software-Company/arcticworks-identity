/** Organization-scoped permission checks for product APIs (server-side). */

import { errorFromResponse, IdentityError } from "./errors.js";
import type { PermissionCheckRequest, PermissionCheckResponse } from "./types.js";

export interface PermissionClientConfig {
  /** Identity issuer. */
  issuer: string;
  /** Service-account or device client id (never expose in browsers). */
  clientId: string;
  /** Corresponding client secret. */
  clientSecret: string;
}

interface CachedToken {
  accessToken: string;
  expiresAt: number; // epoch seconds
}

/**
 * Checks permissions for ArcticWorks users through the documented
 * `POST /api/v1/authorize/check` endpoint. The client authenticates with its
 * own service-account (or device) credentials via `client_credentials` and
 * caches the access token until expiry. The caller may only check users
 * within its own organization.
 */
export class PermissionClient {
  readonly config: PermissionClientConfig;
  private token?: CachedToken;
  private readonly fetchImpl: typeof fetch;

  constructor(config: PermissionClientConfig, fetchImpl: typeof fetch = fetch) {
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  private async accessToken(): Promise<string> {
    if (this.token && this.token.expiresAt > Math.floor(Date.now() / 1000) + 30) {
      return this.token.accessToken;
    }
    const tokenUrl = `${this.config.issuer.replace(/\/$/, "")}/oidc/token`;
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });
    const resp = await this.fetchImpl(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!resp.ok) throw errorFromResponse(resp.status, await resp.json().catch(() => ({})));
    const payload = (await resp.json()) as { access_token: string; expires_in: number };
    this.token = {
      accessToken: payload.access_token,
      expiresAt: Math.floor(Date.now() / 1000) + payload.expires_in,
    };
    return this.token.accessToken;
  }

  /** Check a single permission. Deny-by-default: missing memberships and
   * unknown permissions return `false`, not an error. */
  async checkPermission(req: PermissionCheckRequest): Promise<boolean> {
    return (await this.checkMany([req]))[req.permission]!;
  }

  /** Check several permissions for the same user in one round-trip. */
  async checkMany(requests: PermissionCheckRequest[]): Promise<Record<string, boolean>> {
    if (requests.length === 0) return {};
    const token = await this.accessToken();
    const results: Record<string, boolean> = {};

    for (const req of requests) {
      const resp = await this.fetchImpl(`${this.config.issuer.replace(/\/$/, "")}/api/v1/authorize/check`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(req),
      });
      if (!resp.ok) {
        throw errorFromResponse(resp.status, await resp.json().catch(() => ({})));
      }
      const payload = (await resp.json()) as PermissionCheckResponse;
      results[req.permission] = payload.allowed;
    }
    return results;
  }

  /** Convenience: true only when the user is an active member. */
  async isMember(organizationId: string, userId: string): Promise<boolean> {
    return this.checkPermission({ organizationId, userId, permission: "org.overview.read" });
  }
}

export { IdentityError };
