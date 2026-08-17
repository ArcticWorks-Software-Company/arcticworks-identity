<script lang="ts">
  import { Badge, Button, Card, Checkbox } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, Dialog, EmptyState, FormField, PageHeader } from "$lib/ui";
  import type { RoleJson } from "$lib/api/types";

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());

  const catalog = [
    "org.overview.read",
    "org.members.read",
    "org.members.manage",
    "org.members.invite",
    "org.members.suspend",
    "org.members.remove",
    "org.teams.read",
    "org.teams.manage",
    "org.roles.read",
    "org.roles.manage",
    "org.apps.read",
    "org.apps.manage",
    "org.service-accounts.read",
    "org.service-accounts.manage",
    "org.devices.read",
    "org.devices.manage",
    "org.audit.read",
    "org.settings.read",
    "org.settings.manage",
  ];

  let roles = $state<RoleJson[]>([]);
  let loading = $state(true);
  let error = $state("");

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ roles: RoleJson[] }>(`/api/orgs/${orgId}/roles`);
      roles = resp.roles;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load roles";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  // Create / edit
  let showEdit = $state(false);
  let editing = $state<RoleJson | null>(null);
  let roleName = $state("");
  let roleDescription = $state("");
  let rolePermissions = $state<string[]>([]);
  let extraPermissions = $state("");
  let roleError = $state("");
  let roleBusy = $state(false);

  function openCreate() {
    editing = null;
    roleName = "";
    roleDescription = "";
    rolePermissions = ["org.overview.read"];
    extraPermissions = "";
    showEdit = true;
  }

  function openEdit(role: RoleJson) {
    editing = role;
    roleName = role.name;
    roleDescription = role.description;
    rolePermissions = [...role.permissions];
    extraPermissions = role.permissions.filter((p) => !catalog.includes(p)).join(", ");
    showEdit = true;
  }

  function togglePermission(permission: string) {
    rolePermissions = rolePermissions.includes(permission)
      ? rolePermissions.filter((p) => p !== permission)
      : [...rolePermissions, permission];
  }

  async function saveRole() {
    roleError = "";
    if (rolePermissions.length === 0) {
      roleError = "Choose at least one permission";
      return;
    }
    // Merge free-text product permissions (e.g. continuity.document.read).
    const extras = extraPermissions
      .split(/[, ]+/)
      .map((p) => p.trim())
      .filter((p) => p.length > 0 && !rolePermissions.includes(p));
    const permissions = [...rolePermissions, ...extras];
    roleBusy = true;
    try {
      if (editing) {
        await api.patch(`/api/orgs/${orgId}/roles/${editing.id}`, {
          name: roleName.trim(),
          description: roleDescription.trim(),
          permissions,
        });
      } else {
        await api.post(`/api/orgs/${orgId}/roles`, {
          name: roleName.trim(),
          description: roleDescription.trim(),
          permissions,
        });
      }
      showEdit = false;
      await load();
    } catch (e) {
      roleError = e instanceof Error ? e.message : "Could not save the role";
    } finally {
      roleBusy = false;
    }
  }

  let deleteTarget = $state<RoleJson | null>(null);
  let showDelete = $state(false);

  async function deleteRole() {
    const target = deleteTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/roles/${target.id}`);
    });
    showDelete = false;
    await load();
  }
</script>

<div class="aw-page">
  <PageHeader title="Roles & permissions" description="Permissions use product.resource.action identifiers. Deny by default.">
    {#snippet actions()}
      {#if manage}<Button variant="primary" onclick={openCreate}>Create role</Button>{/if}
    {/snippet}
  </PageHeader>

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading roles…</p></Card>
  {:else if roles.length === 0}
    <Card><EmptyState icon="filter" title="No roles yet" /></Card>
  {:else}
    <div class="aw-stack">
      {#each roles as role}
        <Card>
          <div class="aw-row">
            <div class="aw-grow">
              <strong>{role.name}</strong>
              {#if role.isOwner}
                <Badge variant="warning" dot>Owner — full access</Badge>
              {:else if role.isSystem}
                <Badge variant="neutral">Built-in</Badge>
              {/if}
              {#if role.description}<p class="aw-meta">{role.description}</p>{/if}
              <div class="aw-code-list">
                {#each role.permissions as permission}
                  <code class="aw-monospace aw-code-tag">{permission}</code>
                {/each}
              </div>
            </div>
            {#if manage && !role.isSystem && !role.isOwner}
              <Button variant="secondary" onclick={() => openEdit(role)}>Edit</Button>
              <Button variant="danger" onclick={() => { deleteTarget = role; showDelete = true; }}>Delete</Button>
            {/if}
          </div>
        </Card>
      {/each}
    </div>
  {/if}

  <Dialog bind:open={showEdit} title={editing ? `Edit ${editing.name}` : "Create role"} closeOnScrim={true}>
    <FormField label="Role name" bind:value={roleName} placeholder="Document Editor" />
    <FormField label="Description" bind:value={roleDescription} placeholder="What this role is for" />
    <FormField
      label="Additional permissions"
      bind:value={extraPermissions}
      placeholder="continuity.document.read, continuity.document.write"
      hint="Comma-separated product.resource.action identifiers not in the catalog"
    />
    <fieldset class="aw-fieldset">
      <legend>Permissions</legend>
      <div class="aw-permission-grid">
        {#each catalog as permission}
          <Checkbox checked={rolePermissions.includes(permission)} onchange={() => togglePermission(permission)}>
            <code class="aw-monospace">{permission}</code>
          </Checkbox>
        {/each}
      </div>
    </fieldset>
    {#if roleError}<p class="aw-field-error" role="alert">{roleError}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={roleBusy} onclick={() => (showEdit = false)}>Cancel</Button>
        <Button variant="primary" loading={roleBusy} disabled={roleBusy || !roleName.trim()} onclick={saveRole}>Save role</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showDelete}
    title="Delete role?"
    description={`Delete "${deleteTarget?.name ?? ""}"? Roles assigned to members or service accounts cannot be deleted.`}
    confirmLabel="Delete role"
    onConfirm={deleteRole}
  />
</div>
