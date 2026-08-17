<script lang="ts">
  import { Button, Card, Icon, IconButton } from "@arcticworks/svelte";
  import { api } from "$lib/api/client";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { ConfirmDialog, EmptyState, PageHeader } from "$lib/ui";
  import type { SessionJson } from "$lib/api/types";

  let sessions = $state<SessionJson[]>([]);
  let loading = $state(true);
  let error = $state("");
  let revokeTarget = $state<SessionJson | null>(null);
  let showRevoke = $state(false);

  async function load() {
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ sessions: SessionJson[] }>("/api/account/sessions");
      sessions = resp.sessions;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load sessions";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  function openRevoke(session: SessionJson) {
    revokeTarget = session;
    showRevoke = true;
  }

  async function revoke() {
    const target = revokeTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.post(`/api/account/sessions/${target.id}/revoke`);
    });
    showRevoke = false;
    await load();
  }

  async function revokeOthers() {
    await withReauth(async () => {
      await api.post("/api/account/sessions/revoke-others");
    });
    await load();
  }

  function describe(session: SessionJson): string {
    const parts: string[] = [];
    if (session.userAgent) {
      const clean = session.userAgent.replace(/\s+/g, " ").slice(0, 80);
      parts.push(clean);
    }
    if (session.ip) parts.push(session.ip);
    parts.push(`started ${new Date(session.createdAt).toLocaleString()}`);
    parts.push(`expires ${new Date(session.expiresAt).toLocaleDateString()}`);
    return parts.join(" · ");
  }
</script>

<div class="aw-page--narrow">
  <PageHeader title="Sessions" description="Devices and browsers signed in to your account.">
    {#snippet actions()}
      <Button variant="danger" disabled={sessions.length <= 1} onclick={revokeOthers}>Sign out other sessions</Button>
    {/snippet}
  </PageHeader>

  {#if loading}
    <Card><p class="aw-muted" role="status">Loading sessions…</p></Card>
  {:else if error && sessions.length === 0}
    <Card><p class="aw-field-error" role="alert">{error}</p></Card>
  {:else if sessions.length === 0}
    <Card><EmptyState icon="shield" title="No active sessions" /></Card>
  {:else}
    <Card>
      <ul class="aw-list">
        {#each sessions as session}
          <li class="aw-list-item">
            <Icon name="terminal" size={18} aria-hidden="true" />
            <div class="aw-grow">
              <p class="aw-flush list-title">
                {session.isCurrent ? "This device" : "Another device"}
              </p>
              <p class="aw-meta">{describe(session)}</p>
            </div>
            {#if !session.isCurrent}
              <Button variant="danger" onclick={() => openRevoke(session)}>Revoke</Button>
            {/if}
          </li>
        {/each}
      </ul>
    </Card>
  {/if}

  <ConfirmDialog
    bind:open={showRevoke}
    title="Revoke this session?"
    description="The device will be signed out immediately."
    confirmLabel="Revoke session"
    onConfirm={revoke}
  />
</div>

<style>
  .list-title { font-weight: var(--aw-font-weight-medium); }
</style>
