<script lang="ts">
  import { Button, Card, Select, Table } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, Dialog, EmptyState, FormField, PageHeader, StatusBadge } from "$lib/ui";
  import type { MemberJson, RoleJson, InvitationJson } from "$lib/api/types";

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());

  let members = $state<MemberJson[]>([]);
  let roles = $state<RoleJson[]>([]);
  let invitations = $state<InvitationJson[]>([]);
  let loading = $state(true);
  let error = $state("");
  const columns = $derived([
    { key: "member", label: "Member", pinned: true },
    { key: "role", label: "Role" },
    { key: "status", label: "Status" },
    { key: "joined", label: "Joined" },
    ...(manage ? [{ key: "actions", label: "Actions" }] : []),
  ]);

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const [m, r, i] = await Promise.all([
        api.get<{ members: MemberJson[] }>(`/api/orgs/${orgId}/members`),
        api.get<{ roles: RoleJson[] }>(`/api/orgs/${orgId}/roles`),
        api.get<{ invitations: InvitationJson[] }>(`/api/orgs/${orgId}/invitations`),
      ]);
      members = m.members;
      roles = r.roles.filter((role) => !role.isOwner);
      invitations = i.invitations;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load members";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  async function setRole(member: MemberJson, roleId: string) {
    try {
      await api.post(`/api/orgs/${orgId}/members/${member.userId}/role`, { roleId });
      await load();
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not change the role";
    }
  }

  async function suspend(member: MemberJson) {
    await withReauth(async () => {
      await api.post(`/api/orgs/${orgId}/members/${member.userId}/${member.status === "active" ? "suspend" : "unsuspend"}`);
    });
    await load();
  }

  let removeTarget = $state<MemberJson | null>(null);
  let showRemove = $state(false);

  async function removeMember() {
    const target = removeTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/members/${target.userId}`);
    });
    showRemove = false;
    await load();
  }

  // Invite
  let showInvite = $state(false);
  let inviteEmail = $state("");
  let inviteRole = $state("");
  let inviteError = $state("");
  let inviteBusy = $state(false);

  async function invite() {
    inviteError = "";
    if (!inviteRole) {
      inviteError = "Choose a role";
      return;
    }
    inviteBusy = true;
    try {
      await api.post(`/api/orgs/${orgId}/invitations`, { email: inviteEmail.trim(), roleId: inviteRole });
      showInvite = false;
      inviteEmail = "";
      await load();
    } catch (e) {
      inviteError = e instanceof Error ? e.message : "Could not send the invitation";
    } finally {
      inviteBusy = false;
    }
  }

  let revokeInvite = $state<InvitationJson | null>(null);
  let showRevokeInvite = $state(false);

  async function revokeInvitation() {
    const target = revokeInvite;
    if (!target) return;
    await api.post(`/api/orgs/${orgId}/invitations/${target.id}/revoke`);
    showRevokeInvite = false;
    await load();
  }
</script>

<div class="aw-page">
  <PageHeader title="Members" description="People with access to this organization.">
    {#snippet actions()}
      {#if manage}
        <Button variant="primary" onclick={() => (showInvite = true)}>Invite member</Button>
      {/if}
    {/snippet}
  </PageHeader>

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading members…</p></Card>
  {:else if members.length === 0}
    <Card><EmptyState icon="list" title="No members yet" /></Card>
  {:else}
    <Table {columns} rows={members as unknown as Record<string, unknown>[]} rowKey={(row) => row.userId as string}>
      {#snippet cell(row, column)}
        {@const member = row as unknown as MemberJson}
        {#if column.key === "member"}
          <strong>{member.displayName}</strong>
          <span class="aw-meta aw-monospace">{member.email}</span>
        {:else if column.key === "role"}
          {#if manage && !member.isOwner}
            <Select value={member.roleId ?? ""} onchange={(event: Event) => setRole(member, (event.currentTarget as HTMLSelectElement).value)}>
              {#each roles as role}<option value={role.id}>{role.name}</option>{/each}
            </Select>
          {:else}
            {member.isOwner ? "Owner" : member.roleName}
          {/if}
        {:else if column.key === "status"}
          <StatusBadge status={member.status} />
        {:else if column.key === "joined"}
          <span class="aw-muted">{new Date(member.joinedAt).toLocaleDateString()}</span>
        {:else if column.key === "actions" && !member.isOwner}
          <div class="aw-table-actions">
            <Button variant={member.status === "active" ? "danger" : "secondary"} onclick={() => suspend(member)}>
              {member.status === "active" ? "Suspend" : "Restore"}
            </Button>
            <Button variant="danger" onclick={() => { removeTarget = member; showRemove = true; }}>Remove</Button>
          </div>
        {/if}
      {/snippet}
    </Table>
  {/if}

  {#if !loading}
    <h2 class="aw-section-title">Invitations</h2>
    {#if invitations.length === 0}
      <Card><p class="aw-muted">No pending invitations.</p></Card>
    {:else}
      <Card>
        <ul class="aw-list">
          {#each invitations as invitation}
            <li class="aw-list-item">
              <div class="aw-grow">
                <strong>{invitation.email}</strong>
                <span class="aw-muted aw-meta"> as {invitation.roleName}</span>
              </div>
              <StatusBadge status={invitation.status} active="pending" />
              {#if manage && invitation.status === "pending"}
                <Button variant="danger" onclick={() => { revokeInvite = invitation; showRevokeInvite = true; }}>Revoke</Button>
              {/if}
            </li>
          {/each}
        </ul>
      </Card>
    {/if}
  {/if}

  <Dialog bind:open={showInvite} title="Invite a member" closeOnScrim={true}>
    <FormField label="Email" type="email" bind:value={inviteEmail} placeholder="teammate@example.com" />
    <div class="aw-form-field">
      <label for="invite-role">Role</label>
      <Select id="invite-role" bind:value={inviteRole}>
        <option value="">Choose a role…</option>
        {#each roles as role}
          <option value={role.id}>{role.name}</option>
        {/each}
      </Select>
      <p class="aw-field-hint">Custom roles are managed under Roles &amp; permissions</p>
    </div>
    {#if inviteError}<p class="aw-field-error" role="alert">{inviteError}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={inviteBusy} onclick={() => (showInvite = false)}>Cancel</Button>
        <Button variant="primary" loading={inviteBusy} disabled={inviteBusy || !inviteEmail.trim()} onclick={invite}>Send invitation</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showRemove}
    title="Remove member?"
    description={`Remove ${removeTarget?.email ?? ""} from this organization? They will lose access immediately.`}
    confirmLabel="Remove member"
    onConfirm={removeMember}
  />

  <ConfirmDialog
    bind:open={showRevokeInvite}
    title="Revoke invitation?"
    description={`${revokeInvite?.email ?? ""} will no longer be able to accept the invitation.`}
    confirmLabel="Revoke invitation"
    onConfirm={revokeInvitation}
  />
</div>
