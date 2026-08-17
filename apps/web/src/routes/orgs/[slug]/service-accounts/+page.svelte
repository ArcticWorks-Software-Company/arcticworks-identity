<script lang="ts">
  import { Badge, Button, Card, Select, Table } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, Dialog, EmptyState, FormField, PageHeader } from "$lib/ui";
  import type { RoleJson, ServiceAccountJson } from "$lib/api/types";

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());

  let accounts = $state<ServiceAccountJson[]>([]);
  let roles = $state<RoleJson[]>([]);
  let loading = $state(true);
  let error = $state("");
  let secret = $state("");
  const columns = $derived([
    { key: "account", label: "Service account", pinned: true },
    { key: "role", label: "Role" },
    { key: "status", label: "Status" },
    ...(manage ? [{ key: "actions", label: "Actions" }] : []),
  ]);

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const [a, r] = await Promise.all([
        api.get<{ serviceAccounts: ServiceAccountJson[] }>(`/api/orgs/${orgId}/service-accounts`),
        api.get<{ roles: RoleJson[] }>(`/api/orgs/${orgId}/roles`),
      ]);
      accounts = a.serviceAccounts;
      roles = r.roles.filter((role) => !role.isOwner);
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load service accounts";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  // Create
  let showCreate = $state(false);
  let saName = $state("");
  let saDescription = $state("");
  let saRole = $state("");
  let saError = $state("");
  let saBusy = $state(false);

  async function create() {
    saError = "";
    if (!saRole) {
      saError = "Choose a role";
      return;
    }
    saBusy = true;
    try {
      const resp = await api.post<{ clientSecret: string }>(`/api/orgs/${orgId}/service-accounts`, {
        name: saName.trim(),
        description: saDescription.trim(),
        roleId: saRole,
      });
      secret = resp.clientSecret;
      showCreate = false;
      saName = "";
      saDescription = "";
      await load();
    } catch (e) {
      saError = e instanceof Error ? e.message : "Could not create the service account";
    } finally {
      saBusy = false;
    }
  }

  async function toggleStatus(account: ServiceAccountJson) {
    await withReauth(async () => {
      await api.post(`/api/orgs/${orgId}/service-accounts/${account.id}/${account.status === "active" ? "suspend" : "unsuspend"}`);
    });
    await load();
  }

  async function rotate(account: ServiceAccountJson) {
    await withReauth(async () => {
      const resp = await api.post<{ clientSecret: string }>(`/api/orgs/${orgId}/service-accounts/${account.id}/credentials`);
      secret = resp.clientSecret;
    });
    await load();
  }

  let deleteTarget = $state<ServiceAccountJson | null>(null);
  let showDelete = $state(false);

  async function remove() {
    const target = deleteTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/service-accounts/${target.id}`);
    });
    showDelete = false;
    await load();
  }
</script>

<div class="aw-page">
  <PageHeader title="Service accounts" description="Machine identities for product backends and integrations.">
    {#snippet actions()}
      {#if manage}<Button variant="primary" onclick={() => (showCreate = true)}>Create service account</Button>{/if}
    {/snippet}
  </PageHeader>

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading service accounts…</p></Card>
  {:else if accounts.length === 0}
    <Card><EmptyState icon="terminal" title="No service accounts" description="Create one for backend services that call ArcticWorks APIs." /></Card>
  {:else}
    <Table {columns} rows={accounts as unknown as Record<string, unknown>[]} rowKey={(row) => row.id as string}>
      {#snippet cell(row, column)}
        {@const account = row as unknown as ServiceAccountJson}
        {#if column.key === "account"}
          <strong>{account.name}</strong>
          {#if account.description}<span class="aw-meta">{account.description}</span>{/if}
        {:else if column.key === "role"}
          {account.roleName}
        {:else if column.key === "status"}
          {#if account.status === "active"}<Badge variant="success" dot>Active</Badge>{:else}<Badge variant="danger" dot>Suspended</Badge>{/if}
        {:else if column.key === "actions"}
          <div class="aw-table-actions">
            <Button variant={account.status === "active" ? "danger" : "secondary"} onclick={() => toggleStatus(account)}>
              {account.status === "active" ? "Suspend" : "Restore"}
            </Button>
            <Button variant="danger" onclick={() => rotate(account)}>Rotate credentials</Button>
            <Button variant="danger" onclick={() => { deleteTarget = account; showDelete = true; }}>Delete</Button>
          </div>
        {/if}
      {/snippet}
    </Table>
  {/if}

  <Dialog bind:open={showCreate} title="Create a service account" closeOnScrim={true}>
    <FormField label="Name" bind:value={saName} placeholder="continuity-backend" />
    <FormField label="Description" bind:value={saDescription} placeholder="What this account is for" />
    <div class="aw-form-field">
      <label for="sa-role">Role</label>
      <Select id="sa-role" bind:value={saRole}>
        <option value="">Choose a role…</option>
        {#each roles as role}
          <option value={role.id}>{role.name}</option>
        {/each}
      </Select>
    </div>
    {#if saError}<p class="aw-field-error" role="alert">{saError}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={saBusy} onclick={() => (showCreate = false)}>Cancel</Button>
        <Button variant="primary" loading={saBusy} disabled={saBusy || !saName.trim()} onclick={create}>Create</Button>
      </div>
    {/snippet}
  </Dialog>

  <Dialog open={!!secret} title="Client credentials" closeOnScrim={false}>
    <p class="aw-muted">The client secret is shown only once. It expires automatically; rotate it before expiry.</p>
    <p><code class="aw-monospace aw-secret">{secret}</code></p>
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="primary" onclick={() => (secret = "")}>I've stored it</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showDelete}
    title="Delete service account?"
    description={`Delete "${deleteTarget?.name ?? ""}"? Its credentials stop working immediately.`}
    confirmLabel="Delete service account"
    onConfirm={remove}
  />
</div>
