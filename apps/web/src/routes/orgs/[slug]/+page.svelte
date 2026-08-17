<script lang="ts">
  import { Card, Spinner } from "@arcticworks/svelte";
  import { api } from "$lib/api/client";
  import { orgState } from "$lib/org.svelte.ts";
  import { PageHeader } from "$lib/ui";
  import type { AuditEventJson } from "$lib/api/types";

  const org = orgState();

  let counts = $state({ members: 0, teams: 0, applications: 0, serviceAccounts: 0, devices: 0 });
  let events = $state<AuditEventJson[]>([]);
  let loading = $state(true);
  let error = $state("");

  $effect(() => {
    const orgId = org.principal?.orgId;
    if (!orgId) return;
    loading = true;
    error = "";
    void (async () => {
      try {
        const [members, teams, apps, sas, devices, audit] = await Promise.all([
          api.get<{ members: unknown[] }>(`/api/orgs/${orgId}/members`),
          api.get<{ teams: unknown[] }>(`/api/orgs/${orgId}/teams`),
          api.get<{ applications: unknown[] }>(`/api/orgs/${orgId}/applications`),
          api.get<{ serviceAccounts: unknown[] }>(`/api/orgs/${orgId}/service-accounts`),
          api.get<{ devices: unknown[] }>(`/api/orgs/${orgId}/devices`),
          api.get<{ events: AuditEventJson[] }>(`/api/orgs/${orgId}/audit-log?limit=8`),
        ]);
        counts = {
          members: members.members.length,
          teams: teams.teams.length,
          applications: apps.applications.length,
          serviceAccounts: sas.serviceAccounts.length,
          devices: devices.devices.length,
        };
        events = audit.events;
      } catch (caught) {
        error = caught instanceof Error ? caught.message : "Could not load the organization overview";
      } finally {
        loading = false;
      }
    })();
  });
</script>

<div class="aw-page">
  <PageHeader title="Overview" description={`Everything about ${org.principal?.orgName ?? "this organization"}.`} />

  {#if loading}
    <div class="aw-row" role="status"><Spinner label="Loading" /> <span class="aw-muted">Loading overview…</span></div>
  {:else if error}
    <Card><p class="aw-field-error" role="alert">{error}</p></Card>
  {:else}
    <div class="aw-stat-grid">
      <Card><strong class="aw-stat-value">{counts.members}</strong><p class="aw-muted aw-flush">Members</p></Card>
      <Card><strong class="aw-stat-value">{counts.teams}</strong><p class="aw-muted aw-flush">Teams</p></Card>
      <Card><strong class="aw-stat-value">{counts.applications}</strong><p class="aw-muted aw-flush">Applications</p></Card>
      <Card><strong class="aw-stat-value">{counts.serviceAccounts}</strong><p class="aw-muted aw-flush">Service accounts</p></Card>
      <Card><strong class="aw-stat-value">{counts.devices}</strong><p class="aw-muted aw-flush">Devices</p></Card>
    </div>

    <h2 class="aw-section-title">Recent activity</h2>
    {#if events.length === 0}
      <Card><p class="aw-muted">No events yet.</p></Card>
    {:else}
      <Card>
        <ul class="aw-list">
          {#each events as event}
            <li class="aw-list-item">
              <code class="aw-grow">{event.eventType}</code>
              <span class="aw-muted aw-meta">{new Date(event.occurredAt).toLocaleString()}</span>
            </li>
          {/each}
        </ul>
      </Card>
    {/if}
  {/if}
</div>
