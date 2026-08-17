/** Shared types for ArcticWorks Identity integrations. */

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  revocation_endpoint: string;
  end_session_endpoint?: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  code_challenge_methods_supported: string[];
  scopes_supported: string[];
  claims_supported: string[];
}

export interface TokenSet {
  access_token: string;
  token_type: string;
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
}

/** Standard OIDC ID token claims, decoded. */
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  azp?: string;
  at_hash?: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  /** Organization context chosen at consent time. */
  org?: string;
}

/** Response of the UserInfo endpoint (scoped by the access token). */
export interface UserInfoClaims {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  org?: string;
}

export interface PermissionCheckRequest {
  /** The organization the check is scoped to (must match the caller's own organization). */
  organizationId: string;
  /** The user whose permission is being evaluated. */
  userId: string;
  /** Permission identifier in `product.resource.action` form. */
  permission: string;
}

export interface PermissionCheckResponse {
  allowed: boolean;
  organizationId: string;
  userId: string;
  permission: string;
}

/** A session established for a user via ArcticWorks Identity. */
export interface IdentitySession {
  user: {
    id: string;
    email: string;
    displayName: string;
    emailVerified: boolean;
  };
  currentOrgId?: string;
  memberships: Array<{
    orgId: string;
    orgName: string;
    orgSlug: string;
    roleId?: string;
    roleName: string;
    isOwner: boolean;
    status: string;
    isCurrent: boolean;
    joinedAt: string;
  }>;
}
