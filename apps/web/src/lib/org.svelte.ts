/** Organization context store: resolves an org slug to its id and principal,
 * and gates navigation by role. The API remains the authority — this only
 * decides which links to show. */

import { api } from "$lib/api/client";
import { sessionState } from "$lib/session.svelte.ts";

export interface OrgPrincipal {
  orgId: string;
  orgName: string;
  orgSlug: string;
  roleName: string;
  isOwner: boolean;
  status: string;
}

interface OrgState {
  loading: boolean;
  error: string | null;
  principal: OrgPrincipal | null;
}

let state = $state<OrgState>({ loading: true, error: null, principal: null });

export function orgState() {
  return state;
}

export async function loadOrg(slug: string): Promise<OrgPrincipal | null> {
  const session = sessionState();
  const membership = session.me?.memberships.find((m) => m.orgSlug === slug);
  if (!membership) {
    state.loading = false;
    state.error = "You are not a member of this organization";
    state.principal = null;
    return null;
  }

  state.loading = true;
  state.error = null;
  state.principal = null;
  try {
    const resp = await api.get<{ principal: OrgPrincipal }>(`/api/orgs/${membership.orgId}`);
    state.loading = false;
    state.principal = {
      orgId: membership.orgId,
      orgName: membership.orgName,
      orgSlug: membership.orgSlug,
      roleName: resp.principal.roleName,
      isOwner: resp.principal.isOwner,
      status: resp.principal.status,
    };
    return state.principal;
  } catch (e) {
    state.loading = false;
    state.error = e instanceof Error ? e.message : "Could not load the organization";
    state.principal = null;
    return null;
  }
}

/** Whether the current principal may perform an admin action. The built-in
 * Administrator role and Owner are full; Member and Viewer (and custom
 * roles) get read-only access to most pages. The API enforces everything. */
export function canManage(): boolean {
  const p = state.principal;
  return !!p && (p.isOwner || p.roleName === "Administrator");
}
