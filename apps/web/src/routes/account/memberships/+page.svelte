<script lang="ts">
  import { Button, Card, Input } from "@arcticworks/svelte";
  import { goto } from "$app/navigation";
  import { api } from "$lib/api/client";
  import { refreshSession, sessionState } from "$lib/session.svelte.ts";
  import { Dialog, EmptyState, FormField, PageHeader, StatusBadge } from "$lib/ui";
  import type { MembershipJson } from "$lib/api/types";

  const session = sessionState();

  let showCreate = $state(false);
  let name = $state("");
  let slug = $state("");
  let error = $state("");
  let busy = $state(false);

  async function switchOrg(orgId: string) {
    try {
      await api.post(`/api/orgs/${orgId}/switch`);
      await refreshSession();
      goto("/account/memberships", { invalidateAll: true });
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not switch organization";
    }
  }

  async function createOrg() {
    busy = true;
    error = "";
    try {
      const resp = await api.post<{ organization: { slug: string } }>("/api/orgs", {
        name: name.trim(),
        slug: slug.trim().toLowerCase(),
      });
      await refreshSession();
      showCreate = false;
      goto(`/orgs/${resp.organization.slug}`, { invalidateAll: true });
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not create the organization";
    } finally {
      busy = false;
    }
  }

  const memberships = $derived<MembershipJson[]>(session.me?.memberships ?? []);
</script>

<div class="aw-page--narrow">
  <PageHeader title="Organization memberships" description="Organizations you belong to across ArcticWorks.">
    {#snippet actions()}
      <Button variant="primary" onclick={() => (showCreate = true)}>Create organization</Button>
    {/snippet}
  </PageHeader>

  {#if memberships.length === 0}
    <Card>
      <EmptyState icon="folder" title="No organizations yet" description="Create an organization to get started, or accept an invitation." />
    </Card>
  {:else}
    <Card>
      <ul class="aw-list">
        {#each memberships as membership}
          <li class="aw-list-item">
            <div class="aw-grow">
              <p class="aw-flush list-title">
                {membership.orgName} <span class="aw-muted">({membership.orgSlug})</span>
                {#if membership.isCurrent}<span class="aw-muted">· current</span>{/if}
              </p>
              <p class="aw-meta">
                {membership.isOwner ? "Owner" : membership.roleName}
              </p>
            </div>
            <StatusBadge status={membership.status} />
            <Button variant="secondary" disabled={membership.isCurrent || membership.status !== "active"} onclick={() => switchOrg(membership.orgId)}>
              Switch
            </Button>
          </li>
        {/each}
      </ul>
    </Card>
  {/if}

  <Dialog bind:open={showCreate} title="Create an organization" closeOnScrim={true}>
    <FormField label="Organization name" bind:value={name} placeholder="Acme Corp" />
    <FormField label="Slug" bind:value={slug} placeholder="acme-corp" hint="Lowercase letters, digits and hyphens" />
    {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
    {#snippet footer()}
      <div class="aw-dialog-actions">
        <Button variant="secondary" disabled={busy} onclick={() => (showCreate = false)}>Cancel</Button>
        <Button variant="primary" loading={busy} disabled={busy || !name.trim() || !slug.trim()} onclick={createOrg}>Create</Button>
      </div>
    {/snippet}
  </Dialog>
</div>

<style>
  .list-title { font-weight: var(--aw-font-weight-medium); }
</style>
