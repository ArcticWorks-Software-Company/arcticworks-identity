<script lang="ts">
  import { Button, Card } from "@arcticworks/svelte";
  import { api } from "$lib/api/client";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, EmptyState, PageHeader } from "$lib/ui";

  interface AuthorizedApp {
    id: string;
    clientId: string;
    name: string;
    scopes: string[];
    orgName?: string;
    grantedAt: string;
  }

  let apps = $state<AuthorizedApp[]>([]);
  let loading = $state(true);
  let error = $state("");
  let revokeTarget = $state<AuthorizedApp | null>(null);
  let showRevoke = $state(false);

  async function load() {
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ applications: AuthorizedApp[] }>("/api/account/applications");
      apps = resp.applications;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load applications";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  async function revoke() {
    const target = revokeTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.post(`/api/account/applications/${target.id}/revoke`);
    });
    showRevoke = false;
    await load();
  }
</script>

<div class="aw-page--narrow">
  <PageHeader title="Authorized applications" description="Applications that can act on your behalf." />

  {#if loading}
    <Card><p class="aw-muted" role="status">Loading applications…</p></Card>
  {:else if error && apps.length === 0}
    <Card><p class="aw-field-error" role="alert">{error}</p></Card>
  {:else if apps.length === 0}
    <Card>
      <EmptyState icon="grid" title="No authorized applications" description="Applications you sign in to will appear here." />
    </Card>
  {:else}
    <Card>
      <ul class="aw-list">
        {#each apps as app}
          <li class="aw-list-item">
            <div class="aw-grow">
              <p class="aw-flush list-title">{app.name}</p>
              <p class="aw-meta">
                {app.orgName ? `${app.orgName} · ` : ""}Granted {new Date(app.grantedAt).toLocaleDateString()}
              </p>
              <p class="aw-meta aw-monospace">{app.scopes.join(", ")}</p>
            </div>
            <Button variant="danger" onclick={() => { revokeTarget = app; showRevoke = true; }}>Revoke access</Button>
          </li>
        {/each}
      </ul>
    </Card>
  {/if}

  <ConfirmDialog
    bind:open={showRevoke}
    title="Revoke access?"
    description={`"${revokeTarget?.name ?? ""}" will no longer be able to access your account.`}
    confirmLabel="Revoke access"
    onConfirm={revoke}
  />
</div>

<style>
  .list-title { font-weight: var(--aw-font-weight-medium); }
</style>
