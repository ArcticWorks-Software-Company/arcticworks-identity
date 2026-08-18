<script lang="ts">
  import { Badge, Button, Card, Switch } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, Dialog, EmptyState, FormField, PageHeader } from "$lib/ui";

  interface WebhookJson {
    id: string;
    url: string;
    secretPreview: string;
    enabled: boolean;
    createdAt: string;
  }

  interface DeliveryJson {
    id: string;
    eventId: string;
    eventType: string;
    status: string;
    attempts: number;
    responseStatus?: number;
    createdAt: string;
  }

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());

  let webhooks = $state<WebhookJson[]>([]);
  let loading = $state(true);
  let error = $state("");
  let secret = $state("");

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ webhooks: WebhookJson[] }>(`/api/orgs/${orgId}/webhooks`);
      webhooks = resp.webhooks;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load webhooks";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  // Create
  let showCreate = $state(false);
  let webhookUrl = $state("");
  let webhookError = $state("");
  let webhookBusy = $state(false);

  async function createWebhook() {
    webhookError = "";
    webhookBusy = true;
    try {
      let createdSecret = "";
      await withReauth(async () => {
        const resp = await api.post<{ secret: string }>(`/api/orgs/${orgId}/webhooks`, {
          url: webhookUrl.trim(),
        });
        createdSecret = resp.secret;
      });
      secret = createdSecret;
      showCreate = false;
      webhookUrl = "";
      await load();
    } catch (e) {
      webhookError = e instanceof Error ? e.message : "Could not create the webhook";
    } finally {
      webhookBusy = false;
    }
  }

  async function toggleEnabled(webhook: WebhookJson) {
    await withReauth(async () => {
      await api.patch(`/api/orgs/${orgId}/webhooks/${webhook.id}`, { enabled: !webhook.enabled });
      await load();
    });
  }

  // Rotate secret
  let rotateTarget = $state<WebhookJson | null>(null);
  let showRotate = $state(false);

  async function rotateSecret() {
    const target = rotateTarget;
    if (!target) return;
    await withReauth(async () => {
      const resp = await api.post<{ secret: string }>(`/api/orgs/${orgId}/webhooks/${target.id}/rotate-secret`);
      secret = resp.secret;
    });
    showRotate = false;
    await load();
  }

  // Delete
  let deleteTarget = $state<WebhookJson | null>(null);
  let showDelete = $state(false);

  async function deleteWebhook() {
    const target = deleteTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/webhooks/${target.id}`);
    });
    showDelete = false;
    await load();
  }

  // Deliveries
  let deliveries = $state<DeliveryJson[]>([]);
  let deliveriesFor = $state<WebhookJson | null>(null);
  let showDeliveries = $state(false);

  async function openDeliveries(webhook: WebhookJson) {
    deliveriesFor = webhook;
    showDeliveries = true;
    try {
      const resp = await api.get<{ deliveries: DeliveryJson[] }>(
        `/api/orgs/${orgId}/webhooks/${webhook.id}/deliveries`,
      );
      deliveries = resp.deliveries;
    } catch (e) {
      deliveries = [];
      error = e instanceof Error ? e.message : "Could not load deliveries";
    }
  }
</script>

<div class="aw-page">
  <PageHeader title="Webhooks" description="Stream organization audit events to your own HTTP endpoints with HMAC signatures.">
    {#snippet actions()}
      {#if manage}<Button variant="primary" onclick={() => (showCreate = true)}>Add webhook</Button>{/if}
    {/snippet}
  </PageHeader>

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading webhooks…</p></Card>
  {:else if webhooks.length === 0}
    <Card><EmptyState icon="terminal" title="No webhooks yet" description="Webhooks receive every audited event from this organization." /></Card>
  {:else}
    <div class="aw-stack">
      {#each webhooks as webhook}
        <Card>
          <div class="aw-row">
            <div class="aw-grow">
              <div class="aw-row aw-wrap">
                <strong>{webhook.url}</strong>
                {#if !webhook.enabled}<Badge variant="danger" dot>Disabled</Badge>{/if}
              </div>
              <p class="aw-meta">
                Secret {webhook.secretPreview} · created {new Date(webhook.createdAt).toLocaleString()}
              </p>
            </div>
            {#if manage}
              <Switch checked={webhook.enabled} onchange={() => toggleEnabled(webhook)}>Enabled</Switch>
              <Button variant="secondary" onclick={() => openDeliveries(webhook)}>Deliveries</Button>
              <Button variant="danger" onclick={() => { rotateTarget = webhook; showRotate = true; }}>Rotate secret</Button>
              <Button variant="danger" onclick={() => { deleteTarget = webhook; showDelete = true; }}>Delete</Button>
            {/if}
          </div>
        </Card>
      {/each}
    </div>
  {/if}

  <Dialog bind:open={showCreate} title="Add webhook" closeOnScrim={true}>
    <FormField label="URL" bind:value={webhookUrl} name="webhookUrl" placeholder="https://hooks.example.com/arcticworks" hint="Must be http(s). The signing secret is returned once." />
    {#if webhookError}<p class="aw-field-error" role="alert">{webhookError}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={webhookBusy} onclick={() => (showCreate = false)}>Cancel</Button>
        <Button variant="primary" loading={webhookBusy} disabled={webhookBusy || !webhookUrl.trim()} onclick={createWebhook}>Create</Button>
      </div>
    {/snippet}
  </Dialog>

  <Dialog open={!!secret} title="Webhook signing secret" closeOnScrim={false}>
    <p class="aw-muted">Shown only once. Verify the <code>x-arcticworks-signature</code> header on every delivery with HMAC-SHA256 over <code>t</code> and the raw body.</p>
    <p><code class="aw-monospace aw-secret">{secret}</code></p>
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="primary" onclick={() => (secret = "")}>I've stored it</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showRotate}
    title="Rotate webhook secret?"
    description={`Deliveries to "${rotateTarget?.url ?? ""}" signed with the old secret should be treated as invalid immediately.`}
    confirmLabel="Rotate secret"
    onConfirm={rotateSecret}
  />

  <ConfirmDialog
    bind:open={showDelete}
    title="Delete webhook?"
    description={`Delete "${deleteTarget?.url ?? ""}"? Deliveries stop immediately.`}
    confirmLabel="Delete webhook"
    onConfirm={deleteWebhook}
  />

  <Dialog open={showDeliveries} title={`Deliveries — ${deliveriesFor?.url ?? ""}`} closeOnScrim={true}>
    {#if deliveries.length === 0}
      <p class="aw-muted">No deliveries yet.</p>
    {:else}
      <ul class="aw-stack aw-stack--sm">
        {#each deliveries as delivery}
          <li class="aw-meta">
            {delivery.eventType}
            {#if delivery.status === "success"}<Badge variant="success" dot>delivered</Badge>{:else}<Badge variant="danger" dot>failed</Badge>{/if}
            · attempts {delivery.attempts}{#if delivery.responseStatus} · HTTP {delivery.responseStatus}{/if}
            · {new Date(delivery.createdAt).toLocaleString()}
          </li>
        {/each}
      </ul>
    {/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" onclick={() => (showDeliveries = false)}>Close</Button>
      </div>
    {/snippet}
  </Dialog>
</div>
