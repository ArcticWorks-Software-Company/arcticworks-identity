<script lang="ts">
  import { Button, Card, Select } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { canManage, loadOrg, orgState } from "$lib/org.svelte.ts";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { sessionState } from "$lib/session.svelte.ts";
  import { Dialog, FormField, PageHeader } from "$lib/ui";
  import type { MemberJson } from "$lib/api/types";

  const slug = $derived(page.params.slug ?? "");
  const org = orgState();
  const orgId = $derived(org.principal?.orgId ?? "");
  const manage = $derived(canManage());
  const session = sessionState();

  let name = $state(org.principal?.orgName ?? "");
  let orgSlug = $state(org.principal?.orgSlug ?? "");
  let error = $state("");
  let success = $state("");
  let busy = $state(false);

  $effect(() => {
    name = org.principal?.orgName ?? "";
    orgSlug = org.principal?.orgSlug ?? "";
  });

  async function save() {
    busy = true;
    error = "";
    success = "";
    try {
      await api.patch(`/api/orgs/${orgId}`, { name: name.trim(), slug: orgSlug.trim().toLowerCase() });
      await loadOrg(slug);
      success = "Organization updated";
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not update the organization";
    } finally {
      busy = false;
    }
  }

  // Ownership transfer (Owner only)
  let members = $state<MemberJson[]>([]);
  let transferTarget = $state("");
  let showTransfer = $state(false);
  let transferBusy = $state(false);
  let transferError = $state("");

  async function loadMembers() {
    if (!orgId) return;
    try {
      const resp = await api.get<{ members: MemberJson[] }>(`/api/orgs/${orgId}/members`);
      members = resp.members.filter((m) => !m.isOwner);
    } catch {
      /* settings stays usable without the member list */
    }
  }

  $effect(() => {
    if (org.principal?.isOwner) void loadMembers();
  });

  async function doTransfer() {
    if (!transferTarget) return;
    transferBusy = true;
    transferError = "";
    try {
      await withReauth(async () => {
        await api.post(`/api/orgs/${orgId}/transfer`, { newOwnerUserId: transferTarget });
      });
      showTransfer = false;
      await loadOrg(slug);
    } catch (e) {
      transferError = e instanceof Error ? e.message : "Could not transfer ownership";
    } finally {
      transferBusy = false;
    }
  }

  const isOwner = $derived(!!org.principal?.isOwner);
</script>

<div class="aw-page--narrow">
  <PageHeader title="Settings" description="Organization details." />

  {#if manage}
    <Card>
      <form
        onsubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <FormField label="Organization name" bind:value={name} placeholder="Acme Corp" />
        <FormField label="Slug" bind:value={orgSlug} placeholder="acme-corp" hint="Lowercase letters, digits and hyphens" />
        {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
        {#if success}<p class="aw-field-success" role="status">{success}</p>{/if}
        <div class="aw-form-actions">
          <Button type="submit" variant="primary" loading={busy} disabled={busy || !name.trim() || !orgSlug.trim()}>Save changes</Button>
        </div>
      </form>
    </Card>
  {:else}
    <Card>
      <p class="aw-muted">You need the Administrator role to change organization settings.</p>
    </Card>
  {/if}

  {#if isOwner}
    <h2 class="aw-section-title">Ownership</h2>
    <Card>
      <p class="aw-muted aw-body-copy aw-flush">
        Transfer ownership to another active member. You will become an Administrator.
      </p>
      <Button variant="danger" onclick={() => (showTransfer = true)} disabled={members.length === 0}>Transfer ownership…</Button>
    </Card>
  {/if}

  <Dialog bind:open={showTransfer} title="Transfer ownership?" closeOnScrim={true}>
    <p class="aw-muted">The new owner will have full control. You will become an Administrator.</p>
    <div class="aw-form-field">
      <label for="transfer-target">New owner</label>
      <Select id="transfer-target" bind:value={transferTarget}>
        <option value="">Choose a member…</option>
        {#each members as member}
          <option value={member.userId}>{member.displayName} ({member.email})</option>
        {/each}
      </Select>
    </div>
    {#if transferError}<p class="aw-field-error" role="alert">{transferError}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={transferBusy} onclick={() => (showTransfer = false)}>Cancel</Button>
        <Button variant="danger" loading={transferBusy} disabled={transferBusy || !transferTarget} onclick={doTransfer}>
          Transfer ownership
        </Button>
      </div>
    {/snippet}
  </Dialog>
</div>
