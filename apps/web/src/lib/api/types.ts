/** API response types (camelCase, matching the backend). */

export interface UserJson {
  id: string;
  email: string;
  displayName: string;
  emailVerified: boolean;
}

export interface MembershipJson {
  orgId: string;
  orgName: string;
  orgSlug: string;
  roleId?: string;
  roleName: string;
  isOwner: boolean;
  status: string;
  isCurrent: boolean;
  joinedAt: string;
}

export interface MeResponse {
  user: UserJson;
  currentOrgId?: string;
  memberships: MembershipJson[];
}

export interface SessionJson {
  id: string;
  isCurrent: boolean;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ip?: string;
  userAgent?: string;
}

export interface PasskeyJson {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface OrganizationJson {
  id: string;
  name: string;
  slug: string;
  ownerId: string;
  createdAt: string;
}

export interface MemberJson {
  userId: string;
  email: string;
  displayName: string;
  roleId?: string;
  roleName: string;
  isOwner: boolean;
  status: string;
  joinedAt: string;
}

export interface RoleJson {
  id: string;
  name: string;
  isSystem: boolean;
  isOwner: boolean;
  description: string;
  permissions: string[];
}

export interface TeamJson {
  id: string;
  orgId: string;
  name: string;
  description: string;
  createdAt: string;
}

export interface ApplicationJson {
  id: string;
  name: string;
  clientId: string;
  isConfidential: boolean;
  redirectUris: string[];
  applicationEnabled: boolean;
  secretPreview: string;
  createdAt: string;
}

export interface ServiceAccountJson {
  id: string;
  name: string;
  description: string;
  roleId?: string;
  roleName: string;
  status: string;
  createdAt: string;
}

export interface DeviceJson {
  id: string;
  name: string;
  teamId?: string;
  teamName?: string;
  status: string;
  enrolledAt: string;
  lastSeenAt?: string;
}

export interface AuditEventJson {
  id: string;
  eventType: string;
  actorType: string;
  actorId?: string;
  orgId?: string;
  targetType?: string;
  targetId?: string;
  ip?: string;
  userAgent?: string;
  metadata: Record<string, unknown>;
  occurredAt: string;
}

export interface AuditLogResponse {
  events: AuditEventJson[];
  total: number;
  limit: number;
  offset: number;
}

export interface ConsentInfo {
  client: { clientId: string; name: string };
  organization: { name: string; slug: string };
  scopes: string[];
  redirectUri: string;
  state?: string;
  user: UserJson;
}

export interface InvitationJson {
  id: string;
  email: string;
  roleId?: string;
  roleName: string;
  status: string;
  invitedBy: string;
  createdAt: string;
  expiresAt: string;
}
