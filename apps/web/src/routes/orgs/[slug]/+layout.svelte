<script lang="ts">
  import { Button, Select, Sidebar } from "@arcticworks/svelte";

  import { page } from "$app/state";
  import { goto } from "$app/navigation";
  import { api } from "$lib/api/client";
  import { refreshSession, sessionState } from "$lib/session.svelte.ts";
  import { canManage, loadOrg, orgState } from "$lib/org.svelte.ts";
  import { ReauthDialog } from "$lib/ui";

  let { children } = $props();

  const slug = $derived(page.params.slug ?? "");
  const session = sessionState();
  const org = orgState();

  $effect(() => {
    void loadOrg(slug);
  });

  const manage = $derived(canManage());

  const items = $derived<Array<{ id: string; label: string; icon?: "home" | "list" | "folder" | "filter" | "grid" | "terminal" | "cpu" | "file" | "gear" }>>([
    { id: `/orgs/${slug}`, label: "Overview", icon: "home" },
    { id: `/orgs/${slug}/members`, label: "Members", icon: "list" },
    { id: `/orgs/${slug}/teams`, label: "Teams", icon: "folder" },
    { id: `/orgs/${slug}/roles`, label: "Roles & permissions", icon: "filter" },
    { id: `/orgs/${slug}/applications`, label: "Applications", icon: "grid" },
    { id: `/orgs/${slug}/service-accounts`, label: "Service accounts", icon: "terminal" },
    { id: `/orgs/${slug}/devices`, label: "Devices", icon: "cpu" },
    { id: `/orgs/${slug}/audit`, label: "Audit log", icon: "file" },
    { id: `/orgs/${slug}/settings`, label: "Settings", icon: "gear" },
  ]);

  const memberships = $derived(session.me?.memberships ?? []);
  const selectedOrg = $derived(org.principal?.orgId ?? "");

  async function switchOrg(orgId: string) {
    if (!orgId) return;
    await api.post(`/api/orgs/${orgId}/switch`);
    await refreshSession();
    const target = memberships.find((m) => m.orgId === orgId);
    if (target) goto(`/orgs/${target.orgSlug}`, { invalidateAll: true });
  }
</script>

{#if org.loading}
  <div class="aw-page"><p class="aw-muted">Loading organization…</p></div>
{:else if org.error}
  <div class="aw-page">
    <h1 class="aw-page-title">Organization unavailable</h1>
    <p class="aw-field-error" role="alert">{org.error}</p>
    <Button variant="secondary" href="/account/memberships">Back to my memberships</Button>
  </div>
{:else if org.principal}
  <div class="org-shell" data-density="compact">
    <aside class="org-sidebar">
      <div class="org-brand">
        <strong>{org.principal.orgName}</strong>
        <span class="aw-muted aw-monospace">{org.principal.orgSlug}</span>
      </div>

      {#if memberships.length > 1}
        <label class="aw-muted aw-meta" for="org-switch">Organization</label>
        <Select id="org-switch" value={selectedOrg} onchange={(e: Event) => switchOrg((e.currentTarget as HTMLSelectElement).value)}>
          {#each memberships as membership}
            <option value={membership.orgId}>{membership.orgName}</option>
          {/each}
        </Select>
      {/if}

      <Sidebar
        items={items}
        active={page.url.pathname}
        onselect={(id) => goto(id)}
        label="Organization navigation"
      />

      <div class="org-sidebar-footer">
        <p class="aw-muted aw-flush">
          {org.principal.isOwner ? "Owner" : org.principal.roleName} {#if manage}· can manage{/if}
        </p>
        <a href="/account" class="aw-muted">My account</a>
      </div>
    </aside>
    <main class="org-content">{@render children()}</main>
  </div>
  <ReauthDialog />
{/if}
