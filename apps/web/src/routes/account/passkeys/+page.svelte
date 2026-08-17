<script lang="ts">
  import { Button, Card, Icon, IconButton, Input } from "@arcticworks/svelte";
  import { api } from "$lib/api/client";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { registerPasskey, supportsPasskeys } from "$lib/passkeys";
  import { ConfirmDialog, Dialog, EmptyState, PageHeader } from "$lib/ui";
  import type { PasskeyJson } from "$lib/api/types";

  let passkeys = $state<PasskeyJson[]>([]);
  let loading = $state(true);
  let error = $state("");
  let success = $state("");

  let registering = $state(false);
  let showRename = $state(false);
  let showDelete = $state(false);
  let renameName = $state("");
  let renameId = $state("");
  let deleteTarget = $state<PasskeyJson | null>(null);

  async function load() {
    loading = true;
    error = "";
    try {
      const resp = await api.get<{ passkeys: PasskeyJson[] }>("/api/passkeys");
      passkeys = resp.passkeys;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load passkeys";
    } finally {
      loading = false;
    }
  }

  $effect(() => void load());

  async function register() {
    registering = true;
    error = "";
    try {
      await registerPasskey("My passkey");
      success = "Passkey registered";
      await load();
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not register a passkey";
    } finally {
      registering = false;
    }
  }

  function openRename(passkey: PasskeyJson) {
    renameId = passkey.id;
    renameName = passkey.name;
    showRename = true;
  }

  async function rename() {
    if (!renameName.trim()) return;
    try {
      await api.post(`/api/passkeys/${renameId}/rename`, { name: renameName.trim() });
      showRename = false;
      await load();
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not rename the passkey";
    }
  }

  function openDelete(passkey: PasskeyJson) {
    deleteTarget = passkey;
    showDelete = true;
  }

  async function remove() {
    const target = deleteTarget;
    if (!target) return;
    await withReauth(async () => {
      await api.del(`/api/passkeys/${target.id}`);
    });
    showDelete = false;
    await load();
  }
</script>

<div class="aw-page--narrow">
  <PageHeader title="Passkeys" description="Sign in on this device without a password.">
    {#snippet actions()}
      {#if supportsPasskeys()}
        <Button variant="primary" loading={registering} disabled={registering} onclick={register}>
          <Icon name="plus" size={16} aria-hidden="true" /> Add passkey
        </Button>
      {/if}
    {/snippet}
  </PageHeader>

  {#if !supportsPasskeys()}
    <Card><p class="aw-muted">This browser does not support passkeys.</p></Card>
  {:else if loading}
    <Card><p class="aw-muted" role="status">Loading passkeys…</p></Card>
  {:else if error && passkeys.length === 0}
    <Card><p class="aw-field-error" role="alert">{error}</p></Card>
  {:else if passkeys.length === 0}
    <Card>
      <EmptyState
        icon="shield"
        title="No passkeys yet"
        description="Add a passkey to sign in with Face ID, Windows Hello or your device's security key."
      />
    </Card>
  {:else}
    <Card>
      <ul class="aw-list">
        {#each passkeys as passkey}
          <li class="aw-list-item">
            <Icon name="shield" size={18} aria-hidden="true" />
            <div class="aw-grow">
              <p class="aw-flush list-title">{passkey.name}</p>
              <p class="aw-meta">
                Registered {new Date(passkey.createdAt).toLocaleDateString()}
                {#if passkey.lastUsedAt}· last used {new Date(passkey.lastUsedAt).toLocaleDateString()}{/if}
              </p>
            </div>
            <IconButton icon="copy" label="Rename" onclick={() => openRename(passkey)} />
            <IconButton icon="trash" label="Delete" onclick={() => openDelete(passkey)} />
          </li>
        {/each}
      </ul>
    </Card>
  {/if}

  {#if success}<p class="aw-field-success" role="status">{success}</p>{/if}

  <Dialog bind:open={showRename} title="Rename passkey" closeOnScrim={true}>
    <Input bind:value={renameName} placeholder="Passkey name" />
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" onclick={() => (showRename = false)}>Cancel</Button>
        <Button variant="primary" disabled={!renameName.trim()} onclick={rename}>Save</Button>
      </div>
    {/snippet}
  </Dialog>

  <ConfirmDialog
    bind:open={showDelete}
    title="Delete passkey?"
    description={`Remove "${deleteTarget?.name ?? ""}"? You can add a new passkey at any time.`}
    confirmLabel="Delete passkey"
    onConfirm={remove}
  />
</div>

<style>
  .list-title { font-weight: var(--aw-font-weight-medium); }
</style>
