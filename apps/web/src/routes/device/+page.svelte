<script lang="ts">
  import { Badge, Button, Card } from "@arcticworks/svelte";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { ensureSessionLoaded, sessionState } from "$lib/session.svelte.ts";
  import { FormField, PageHeader } from "$lib/ui";

  const session = sessionState();
  const prefill = $derived(page.url.searchParams.get("user_code") ?? "");

  let userCode = $state("");
  let error = $state("");
  let busy = $state(false);
  let info = $state<{ client: { name: string }; scopes: string[] } | null>(null);
  let outcome = $state<"approved" | "denied" | "">("");

  // Device verification requires a signed-in user.
  $effect(() => {
    void ensureSessionLoaded().then((me) => {
      if (!me) {
        const continueUrl = window.location.pathname + window.location.search;
        goto(`/login?continue=${encodeURIComponent(continueUrl)}`);
      }
    });
  });

  $effect(() => {
    if (!userCode && prefill) {
      userCode = prefill;
      void lookup();
    }
  });

  async function lookup() {
    error = "";
    busy = true;
    info = null;
    outcome = "";
    try {
      info = await api.get<{ client: { name: string }; scopes: string[] }>(
        `/api/oidc/device-info?user_code=${encodeURIComponent(userCode.trim())}`,
      );
    } catch (e) {
      info = null;
      error = e instanceof Error ? e.message : "Could not look up that code";
    } finally {
      busy = false;
    }
  }

  async function decide(decision: "approve" | "deny") {
    error = "";
    busy = true;
    try {
      await api.post("/api/oidc/device-approve", { userCode: userCode.trim(), decision });
      outcome = decision === "approve" ? "approved" : "denied";
      info = null;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not record your decision";
    } finally {
      busy = false;
    }
  }
</script>

<div class="aw-page--narrow">
  <PageHeader title="Device sign-in" description="Confirm the code shown on your device." />

  {#if session.me}
    <Card>
      <form
        onsubmit={(e) => {
          e.preventDefault();
          lookup();
        }}
      >
        <FormField
          label="Device code"
          name="userCode"
          autocomplete="one-time-code"
          placeholder="ABCD2345"
          bind:value={userCode}
          hint="The eight-character code shown by the application on your device."
        />
        {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}

        {#if info}
          <div class="aw-stack aw-stack--sm">
            <p class="aw-flush">
              <strong>{info.client.name}</strong> wants to sign in as you and requests:
            </p>
            <div class="aw-row aw-wrap">
              {#each info.scopes as scope}
                <Badge variant="neutral">{scope}</Badge>
              {/each}
            </div>
            <div class="aw-form-actions">
              <Button variant="primary" loading={busy} disabled={busy} onclick={() => decide("approve")}>
                Approve
              </Button>
              <Button variant="danger" loading={busy} disabled={busy} onclick={() => decide("deny")}>
                Deny
              </Button>
            </div>
          </div>
        {:else if !error}
          <div class="aw-form-actions">
            <Button type="submit" variant="primary" loading={busy} disabled={busy || userCode.trim().length === 0}>
              Continue
            </Button>
          </div>
        {/if}
      </form>
    </Card>

    {#if outcome === "approved"}
      <Card>
        <p class="aw-field-success" role="status">Device approved — you can return to your device now.</p>
      </Card>
    {:else if outcome === "denied"}
      <Card>
        <p class="aw-muted" role="status">Device denied. No access was granted.</p>
      </Card>
    {/if}
  {/if}
</div>
