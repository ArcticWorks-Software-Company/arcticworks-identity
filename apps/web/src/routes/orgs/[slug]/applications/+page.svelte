<script lang="ts">
  import { Badge, Button, Card, Checkbox, Switch, Textarea } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, Dialog, EmptyState, FormField, PageHeader } from "$lib/ui";
  import type { ApplicationJson } from "$lib/api/types";

  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());

  let apps = $state<ApplicationJson[]>([]);
  let loading = $state(true);
  let error = $state("");
  let secret = $state("");

  async function load() {
    if (!orgId) return;
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ applications: ApplicationJson[] }>(`/api/orgs/${orgId}/applications`);
      apps = resp.applications;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load applications";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  async function toggleEnabled(app: ApplicationJson) {
    await withReauth(async () => {
      await api.patch(`/api/orgs/${orgId}/applications/${app.clientId}`, { applicationEnabled: !app.applicationEnabled });
      await load();
    });
  }

  // Create
  let showCreate = $state(false);
  let appName = $state("");
  let appUris = $state("");
  let appLogoutUris = $state("");
  let appConfidential = $state(true);
  let appError = $state("");
  let appBusy = $state(false);

  async function createApp() {
    appError = "";
    const uris = appUris.split("\n").map((u) => u.trim()).filter((u) => u.length > 0);
    if (uris.length === 0) {
      appError = "Enter at least one redirect URI";
      return;
    }
    const logoutUris = appLogoutUris.split("\n").map((u) => u.trim()).filter((u) => u.length > 0);
    appBusy = true;
    try {
      const resp = await api.post<{ clientSecret?: string }>(`/api/orgs/${orgId}/applications`, {
        name: appName.trim(),
        redirectUris: uris,
        isConfidential: appConfidential,
        postLogoutRedirectUris: logoutUris,
      });
      if (resp.clientSecret) secret = resp.clientSecret;
      showCreate = false;
      appName = "";
      appUris = "";
      appLogoutUris = "";
      await load();
    } catch (e) {
      appError = e instanceof Error ? e.message : "Could not create the application";
    } finally {
      appBusy = false;
    }
  }

  // Rotate secret
  let rotateTarget = $state<ApplicationJson | null>(null);
  let showRotate = $state(false);

  async function rotateSecret() {
    const target = rotateTarget;
    if (!target) return;
    await withReauth(async () => {
      const resp = await api.post<{ clientSecret: string }>(`/api/orgs/${orgId}/applications/${target.clientId}/rotate-secret`);
      secret = resp.clientSecret;
    });
    showRotate = false;
    await load();
  }

  let deleteTarget = $state<ApplicationJson | null>(null);
  let showDelete = $state(false);

  async function deleteApp() {
    const target = deleteTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/orgs/${orgId}/applications/${target.clientId}`);
    });
    showDelete = false;
    await load();
  }
</script>

<div class="aw-page">
  <PageHeader title="Applications" description="OIDC clients that sign in users through ArcticWorks Identity.">
    {#snippet actions()}
      {#if manage}<Button variant="primary" onclick={() => (showCreate = true)}>Register application</Button>{/if}
    {/snippet}
  </PageHeader>

  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#if loading}
    <Card><p class="aw-muted" role="status">Loading applications…</p></Card>
  {:else if apps.length === 0}
    <Card><EmptyState icon="grid" title="No applications yet" description="Products and tools sign users in through OIDC applications." /></Card>
  {:else}
    <div class="aw-stack">
      {#each apps as app}
        <Card>
          <div class="aw-row">
            <div class="aw-grow">
              <div class="aw-row aw-wrap">
                <strong>{app.name}</strong>
                {#if app.isConfidential}
                  <Badge variant="neutral">Confidential</Badge>
                {:else}
                  <Badge variant="neutral">Public</Badge>
                {/if}
                {#if !app.applicationEnabled}<Badge variant="danger" dot>Disabled</Badge>{/if}
              </div>
              <p class="aw-meta aw-monospace">{app.clientId}</p>
              <p class="aw-meta">
                Redirect URIs: {app.redirectUris.join(", ")}
              </p>
              {#if app.postLogoutRedirectUris?.length}
                <p class="aw-meta">
                  Post-logout redirect URIs: {app.postLogoutRedirectUris.join(", ")}
                </p>
              {/if}
              {#if app.isConfidential}
                <p class="aw-meta">
                  Secret {app.secretPreview} · {manage ? "rotate to change" : ""}
                </p>
              {/if}
            </div>
            {#if manage}
              <Switch checked={app.applicationEnabled} onchange={() => toggleEnabled(app)}>Enabled</Switch>
              {#if app.isConfidential}
                <Button variant="danger" onclick={() => { rotateTarget = app; showRotate = true; }}>Rotate secret</Button>
              {/if}
              <Button variant="danger" onclick={() => { deleteTarget = app; showDelete = true; }}>Delete</Button>
            {/if}
          </div>
        </Card>
      {/each}
    </div>
  {/if}

  <Dialog bind:open={showCreate} title="Register an application" closeOnScrim={true}>
    <FormField label="Name" bind:value={appName} placeholder="Continuity" />
    <div class="aw-form-field">
      <label for="app-uris">Redirect URIs</label>
      <Textarea id="app-uris" bind:value={appUris} rows={3} placeholder="https://app.example.com/callback" />
      <p class="aw-field-hint">One per line. Must be https (http allowed for localhost).</p>
    </div>
    <div class="aw-form-field">
      <label for="app-logout-uris">Post-logout redirect URIs</label>
      <Textarea id="app-logout-uris" bind:value={appLogoutUris} rows={2} placeholder="https://app.example.com/logged-out" />
      <p class="aw-field-hint">Optional. Where the browser lands after RP-initiated logout (OIDC end-session). One per line.</p>
    </div>
    <Checkbox bind:checked={appConfidential}>Confidential client (has a secret)</Checkbox>
    {#if appError}<p class="aw-field-error" role="alert">{appError}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={appBusy} onclick={() => (showCreate = false)}>Cancel</Button>
        <Button variant="primary" loading={appBusy} disabled={appBusy || !appName.trim()} onclick={createApp}>Register</Button>
      </div>
    {/snippet}
  </Dialog>

  <Dialog open={!!secret} title="Client secret" closeOnScrim={false}>
    <p class="aw-muted">This secret is shown only once. Store it securely — it is stored hashed and cannot be recovered.</p>
    <p><code class="aw-monospace aw-secret">{secret}</code></p>
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="primary" onclick={() => (secret = "")}>I've stored it</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showRotate}
    title="Rotate client secret?"
    description={`The current secret for "${rotateTarget?.name ?? ""}" will stop working immediately.`}
    confirmLabel="Rotate secret"
    onConfirm={rotateSecret}
  />

  <ConfirmDialog
    bind:open={showDelete}
    title="Delete application?"
    description={`Delete "${deleteTarget?.name ?? ""}"? All users' access grants for it will be revoked.`}
    confirmLabel="Delete application"
    onConfirm={deleteApp}
  />
</div>
