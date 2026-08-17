<script lang="ts">
  import { Card, Pagination, Table } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { orgState } from "$lib/org.svelte.ts";
  import { EmptyState, PageHeader } from "$lib/ui";
  import type { AuditEventJson } from "$lib/api/types";

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const PAGE_SIZE = 50;
  const columns = [
    { key: "when", label: "When", pinned: true },
    { key: "event", label: "Event" },
    { key: "actor", label: "Actor" },
    { key: "details", label: "Details" },
  ];

  let events = $state<AuditEventJson[]>([]);
  let total = $state(0);
  let offset = $state(0);
  let loading = $state(true);
  let error = $state("");

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ events: AuditEventJson[]; total: number }>(
        `/api/orgs/${orgId}/audit-log?limit=${PAGE_SIZE}&offset=${offset}`,
      );
      events = resp.events;
      total = resp.total;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load the audit log";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  const pages = $derived(Math.max(1, Math.ceil(total / PAGE_SIZE)));
  const currentPage = $derived(Math.floor(offset / PAGE_SIZE) + 1);

  function go(pageNo: number) {
    offset = (pageNo - 1) * PAGE_SIZE;
  }

  const eventLabel: Record<string, string> = {
    "account.register": "Account registered",
    "account.email_verified": "Email verified",
    "auth.login": "Signed in",
    "auth.login_failed": "Sign-in failed",
    "auth.logout": "Signed out",
    "auth.passkey_login": "Signed in with passkey",
    "auth.reauth": "Reauthenticated",
    "auth.recovery_used": "Recovery code used",
    "auth.reset_requested": "Password reset requested",
    "account.password_reset": "Password reset",
    "account.password_changed": "Password changed",
    "org.created": "Organization created",
    "org.updated": "Organization updated",
    "org.ownership_transferred": "Ownership transferred",
    "member.role_changed": "Role changed",
    "member.suspended": "Member suspended",
    "member.unsuspended": "Member restored",
    "member.removed": "Member removed",
    "invite.created": "Invitation sent",
    "invite.accepted": "Invitation accepted",
    "invite.revoked": "Invitation revoked",
    "team.created": "Team created",
    "team.updated": "Team updated",
    "team.deleted": "Team deleted",
    "team.member_added": "Member added to team",
    "team.member_removed": "Member removed from team",
    "role.created": "Role created",
    "role.updated": "Role updated",
    "role.deleted": "Role deleted",
    "app.created": "Application registered",
    "app.updated": "Application updated",
    "app.secret_rotated": "Client secret rotated",
    "app.deleted": "Application deleted",
    "app.grant_revoked": "Access grant revoked",
    "sa.created": "Service account created",
    "sa.updated": "Service account updated",
    "sa.credential_rotated": "Service account credentials rotated",
    "sa.suspended": "Service account suspended",
    "sa.unsuspended": "Service account restored",
    "sa.deleted": "Service account deleted",
    "sa.token_issued": "Service account token issued",
    "device.enrollment_token_created": "Enrollment token created",
    "device.enrolled": "Device enrolled",
    "device.updated": "Device updated",
    "device.credential_rotated": "Device credentials rotated",
    "device.revoked": "Device revoked",
    "device.token_issued": "Device token issued",
    "oauth.consent_granted": "Consent granted",
    "oauth.consent_denied": "Consent denied",
    "oauth.token_issued": "Token issued",
    "oauth.token_refreshed": "Token refreshed",
    "oauth.refresh_token_reuse": "Refresh token reuse detected",
    "oauth.token_revoked": "Token revoked",
    "oauth.pkce_failed": "PKCE verification failed",
    "recovery_codes.generated": "Recovery codes generated",
    "passkey.registered": "Passkey registered",
    "passkey.deleted": "Passkey deleted",
    "session.revoke": "Session revoked",
    "session.revoke_others": "Other sessions revoked",
  };
</script>

<div class="aw-page">
  <PageHeader title="Audit log" description="Append-only record of security-relevant events in this organization." />

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading audit events…</p></Card>
  {:else if events.length === 0}
    <Card><EmptyState icon="file" title="No events yet" /></Card>
  {:else}
    <Card>
      <Table {columns} rows={events as unknown as Record<string, unknown>[]} rowKey={(row) => row.id as string}>
        {#snippet cell(row, column)}
          {@const event = row as unknown as AuditEventJson}
          {#if column.key === "when"}
            <span class="aw-muted">{new Date(event.occurredAt).toLocaleString()}</span>
          {:else if column.key === "event"}
            {eventLabel[event.eventType] ?? event.eventType}
            <code class="aw-meta aw-monospace">{event.eventType}</code>
          {:else if column.key === "actor"}
            <span class="aw-muted">{event.actorType}{event.actorId ? ` ${event.actorId.slice(0, 8)}…` : ""}</span>
          {:else if column.key === "details"}
            <code class="aw-muted aw-monospace">{JSON.stringify(event.metadata ?? {})}</code>
          {/if}
        {/snippet}
      </Table>
      <Pagination page={currentPage} pages={pages} onchange={(p) => go(p)} />
    </Card>
  {/if}
</div>
