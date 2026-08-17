<script lang="ts">
  import { Badge, Button, Card, Table } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, Dialog, EmptyState, PageHeader } from "$lib/ui";
  import type { DeviceJson } from "$lib/api/types";

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());

  let devices = $state<DeviceJson[]>([]);
  let loading = $state(true);
  let error = $state("");
  let token = $state("");
  const columns = $derived([
    { key: "device", label: "Device", pinned: true },
    { key: "team", label: "Team" },
    { key: "status", label: "Status" },
    { key: "enrolled", label: "Enrolled" },
    { key: "lastSeen", label: "Last seen" },
    ...(manage ? [{ key: "actions", label: "Actions" }] : []),
  ]);

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ devices: DeviceJson[] }>(`/api/orgs/${orgId}/devices`);
      devices = resp.devices;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load devices";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  async function createToken() {
    error = "";
    try {
      const resp = await api.post<{ token: string }>(`/api/orgs/${orgId}/enrollment-tokens`, {});
      token = resp.token;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not create an enrollment token";
    }
  }

  async function rotate(device: DeviceJson) {
    await withReauth(async () => {
      const resp = await api.post<{ clientSecret: string }>(`/api/orgs/${orgId}/devices/${device.id}/rotate-credential`);
      token = resp.clientSecret;
    });
    await load();
  }

  let revokeTarget = $state<DeviceJson | null>(null);
  let showRevoke = $state(false);

  async function revoke() {
    const target = revokeTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/devices/${target.id}`);
    });
    showRevoke = false;
    await load();
  }
</script>

<div class="aw-page">
  <PageHeader title="Devices" description="Enrolled devices that authenticate with ArcticWorks Identity.">
    {#snippet actions()}
      {#if manage}<Button variant="primary" onclick={createToken}>Create enrollment token</Button>{/if}
    {/snippet}
  </PageHeader>

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading devices…</p></Card>
  {:else if devices.length === 0}
    <Card>
      <EmptyState
        icon="cpu"
        title="No devices enrolled"
        description="Create a single-use enrollment token, then present it from the device at POST /api/enroll."
      />
    </Card>
  {:else}
    <Table {columns} rows={devices as unknown as Record<string, unknown>[]} rowKey={(row) => row.id as string}>
      {#snippet cell(row, column)}
        {@const device = row as unknown as DeviceJson}
        {#if column.key === "device"}
          <strong>{device.name}</strong>
        {:else if column.key === "team"}
          {device.teamName ?? "—"}
        {:else if column.key === "status"}
          {#if device.status === "active"}<Badge variant="success" dot>Active</Badge>{:else}<Badge variant="danger" dot>Revoked</Badge>{/if}
        {:else if column.key === "enrolled"}
          <span class="aw-muted">{new Date(device.enrolledAt).toLocaleDateString()}</span>
        {:else if column.key === "lastSeen"}
          <span class="aw-muted">{device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : "—"}</span>
        {:else if column.key === "actions" && device.status === "active"}
          <div class="aw-table-actions">
            <Button variant="danger" onclick={() => rotate(device)}>Rotate credentials</Button>
            <Button variant="danger" onclick={() => { revokeTarget = device; showRevoke = true; }}>Revoke</Button>
          </div>
        {/if}
      {/snippet}
    </Table>
  {/if}

  <Dialog open={!!token} title="Enrollment token" closeOnScrim={false}>
    <p class="aw-muted">Single-use, expires in 24 hours. Present it with the device name at POST /api/enroll.</p>
    <p><code class="aw-monospace aw-secret">{token}</code></p>
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="primary" onclick={() => (token = "")}>Done</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showRevoke}
    title="Revoke device?"
    description={`"${revokeTarget?.name ?? ""}" will no longer be able to authenticate.`}
    confirmLabel="Revoke device"
    onConfirm={revoke}
  />
</div>
