/**
 * @arcticworks/identity-sdk — TypeScript SDK for ArcticWorks applications.
 *
 * Two server-side building blocks:
 * - `OidcClient`: authorization-code + PKCE login against ArcticWorks
 *   Identity (build the authorize URL, exchange the code, rotate refresh
 *   tokens, revoke tokens, read UserInfo).
 * - `PermissionClient`: organization-scoped permission checks through the
 *   documented `/api/v1/authorize/check` endpoint, authenticating with the
 *   product's own service-account (or device) credentials.
 *
 * Product APIs must never trust the browser with secrets; use this SDK
 * server-side. SecureNet, Continuity, Hub and every future ArcticWorks
 * product authenticate directly through Identity — never through another
 * product.
 */

export { OidcClient, generateCodeVerifier, generatePkceChallenge, randomState, randomNonce, decodeJwtPayload } from "./oidc.js";
export type { OidcClientConfig, AuthorizeResult, ExchangeOptions } from "./oidc.js";
export { PermissionClient } from "./permissions.js";
export type { PermissionClientConfig } from "./permissions.js";
export { IdentityError } from "./errors.js";
export type { IdentityErrorCode } from "./errors.js";
export type {
  DiscoveryDocument,
  TokenSet,
  IdTokenClaims,
  UserInfoClaims,
  PermissionCheckRequest,
  PermissionCheckResponse,
  IdentitySession,
} from "./types.js";
