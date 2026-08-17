<script lang="ts">
  import { Button, Card, Select } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, Dialog, EmptyState, FormField, PageHeader } from "$lib/ui";
  import type { MemberJson, TeamJson } from "$lib/api/types";

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());

  let teams = $state<TeamJson[]>([]);
  let members = $state<MemberJson[]>([]);
  let loading = $state(true);
  let error = $state("");

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const [t, m] = await Promise.all([
        api.get<{ teams: TeamJson[] }>(`/api/orgs/${orgId}/teams`),
        api.get<{ members: MemberJson[] }>(`/api/orgs/${orgId}/members`),
      ]);
      teams = t.teams;
      members = m.members.filter((member) => member.status === "active");
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load teams";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  // Create / edit team
  let showEdit = $state(false);
  let editingId = $state("");
  let teamName = $state("");
  let teamDescription = $state("");
  let teamError = $state("");
  let teamBusy = $state(false);

  function openCreate() {
    editingId = "";
    teamName = "";
    teamDescription = "";
    showEdit = true;
  }

  function openEdit(team: TeamJson) {
    editingId = team.id;
    teamName = team.name;
    teamDescription = team.description;
    showEdit = true;
  }

  async function saveTeam() {
    teamError = "";
    teamBusy = true;
    try {
      if (editingId) {
        await api.patch(`/api/orgs/${orgId}/teams/${editingId}`, { name: teamName.trim(), description: teamDescription.trim() });
      } else {
        await api.post(`/api/orgs/${orgId}/teams`, { name: teamName.trim(), description: teamDescription.trim() });
      }
      showEdit = false;
      await load();
    } catch (e) {
      teamError = e instanceof Error ? e.message : "Could not save the team";
    } finally {
      teamBusy = false;
    }
  }

  // Team members
  type TeamMembers = { members: { userId: string; email: string; displayName: string }[] };
  let expanded = $state<Record<string, TeamMembers | undefined>>({});

  async function toggleExpand(team: TeamJson) {
    if (expanded[team.id]) {
      expanded = { ...expanded, [team.id]: undefined };
      return;
    }
    const resp = await api.get<{ members: { userId: string; email: string; displayName: string }[] }>(
      `/api/orgs/${orgId}/teams/${team.id}/members`,
    );
    expanded = { ...expanded, [team.id]: { members: resp.members } };
  }

  let addTarget = $state<TeamJson | null>(null);
  let addUserId = $state("");

  async function addMember() {
    const target = addTarget;
    const userId = addUserId;
    if (!target || !userId) return;
    try {
      await api.post(`/api/orgs/${orgId}/teams/${target.id}/members`, { userId });
      const resp = await api.get<TeamMembers>(`/api/orgs/${orgId}/teams/${target.id}/members`);
      expanded = { ...expanded, [target.id]: resp };
      addTarget = null;
      addUserId = "";
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not add the member";
    }
  }

  async function removeTeamMember(teamId: string, userId: string) {
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/teams/${teamId}/members/${userId}`);
    });
    const current = expanded[teamId];
    if (current) {
      current.members = current.members.filter((m) => m.userId !== userId);
    }
  }

  let deleteTarget = $state<TeamJson | null>(null);
  let showDelete = $state(false);

  async function deleteTeam() {
    const target = deleteTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/teams/${target.id}`);
    });
    showDelete = false;
    await load();
  }
</script>

<div class="aw-page">
  <PageHeader title="Teams" description="Simple teams or departments within this organization.">
    {#snippet actions()}
      {#if manage}<Button variant="primary" onclick={openCreate}>Create team</Button>{/if}
    {/snippet}
  </PageHeader>

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading teams…</p></Card>
  {:else if teams.length === 0}
    <Card><EmptyState icon="folder" title="No teams yet" description="Teams group members for easier access management." /></Card>
  {:else}
    <div class="aw-stack">
      {#each teams as team}
        <Card>
          <div class="aw-row">
            <div class="aw-grow">
              <strong>{team.name}</strong>
              {#if team.description}<p class="aw-meta">{team.description}</p>{/if}
            </div>
            {#if manage}
              <Button variant="secondary" onclick={() => toggleExpand(team)}>
                {expanded[team.id] ? "Hide members" : "Members"}
              </Button>
              <Button variant="secondary" onclick={() => openEdit(team)}>Edit</Button>
              <Button variant="danger" onclick={() => { deleteTarget = team; showDelete = true; }}>Delete</Button>
            {/if}
          </div>

          {#if expanded[team.id]}
            <div class="aw-subsection">
              <ul class="aw-list">
                {#each expanded[team.id]!.members as member}
                  <li class="aw-list-item">
                    <span class="aw-grow">{member.displayName} <span class="aw-muted aw-monospace">{member.email}</span></span>
                    {#if manage}
                      <Button variant="danger" onclick={() => removeTeamMember(team.id, member.userId)}>Remove</Button>
                    {/if}
                  </li>
                {/each}
              </ul>
              {#if manage}
                <div class="aw-row">
                  <Select bind:value={addUserId} aria-label="Member to add" class="aw-grow">
                    <option value="">Add a member…</option>
                    {#each members.filter((m) => !expanded[team.id]!.members.some((em) => em.userId === m.userId)) as member}
                      <option value={member.userId}>{member.displayName} ({member.email})</option>
                    {/each}
                  </Select>
                  <Button variant="secondary" disabled={!addUserId} onclick={() => { addTarget = team; addMember(); }}>Add</Button>
                </div>
              {/if}
            </div>
          {/if}
        </Card>
      {/each}
    </div>
  {/if}

  <Dialog bind:open={showEdit} title={editingId ? "Edit team" : "Create team"} closeOnScrim={true}>
    <FormField label="Team name" bind:value={teamName} placeholder="Engineering" />
    <FormField label="Description" bind:value={teamDescription} placeholder="What this team works on" />
    {#if teamError}<p class="aw-field-error" role="alert">{teamError}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={teamBusy} onclick={() => (showEdit = false)}>Cancel</Button>
        <Button variant="primary" loading={teamBusy} disabled={teamBusy || !teamName.trim()} onclick={saveTeam}>Save</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showDelete}
    title="Delete team?"
    description={`Delete "${deleteTarget?.name ?? ""}"? Members are not removed from the organization.`}
    confirmLabel="Delete team"
    onConfirm={deleteTeam}
  />
</div>
