<script lang="ts">
  import { Badge, Button, Card } from "@arcticworks/svelte";
  import { api } from "$lib/api/client";
  import { refreshSession, sessionState } from "$lib/session.svelte.ts";
  import { FormField, PageHeader } from "$lib/ui";
  import type { UserJson } from "$lib/api/types";

  const session = sessionState();

  let displayName = $state(session.me?.user.displayName ?? "");
  let error = $state("");
  let success = $state("");
  let busy = $state(false);
  let initialized = $state(false);

  $effect(() => {
    if (!initialized && session.me) {
      displayName = session.me.user.displayName;
      initialized = true;
    }
  });

  async function save() {
    busy = true;
    error = "";
    success = "";
    try {
      const user = await api.post<UserJson>("/api/account/profile", { displayName });
      await refreshSession();
      displayName = user.displayName;
      success = "Profile updated";
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not update your profile";
    } finally {
      busy = false;
    }
  }
</script>

<div class="aw-page--narrow">
  <PageHeader title="Profile" description="Your identity across ArcticWorks products." />

  {#if session.me}
    <Card>
      <form
        onsubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <FormField label="Email address" value={session.me.user.email} disabled hint="Your email cannot be changed" />
        <FormField label="Display name" bind:value={displayName} name="displayName" autocomplete="name" />
        <div class="aw-row">
          <p class="aw-muted aw-flush">Email status:</p>
          {#if session.me.user.emailVerified}
            <Badge variant="success" dot>Verified</Badge>
          {:else}
            <Badge variant="warning" dot>Unverified</Badge>
          {/if}
        </div>
        {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
        {#if success}<p class="aw-field-success" role="status">{success}</p>{/if}
        <div class="aw-form-actions">
          <Button type="submit" variant="primary" loading={busy} disabled={busy || displayName.trim() === ""}>Save changes</Button>
        </div>
      </form>
    </Card>
  {:else}
    <p class="aw-muted" role="status">Loading profile…</p>
  {/if}
</div>
