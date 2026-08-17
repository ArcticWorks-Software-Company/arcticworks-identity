<script lang="ts">
  import { Button, Spinner } from "@arcticworks/svelte";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { ensureSessionLoaded, refreshSession, sessionState } from "$lib/session.svelte.ts";
  import { AuthLayout } from "$lib/ui";

  const token = $derived(page.params.token ?? "");
  const continueUrl = $derived(`/invite/${token}`);

  const session = sessionState();
  const ready = $derived(!session.loading);

  let busy = $state(false);
  let error = $state("");
  let status = $state<"idle" | "joined" | "error">("idle");

  $effect(() => {
    if (ready) void ensureSessionLoaded();
  });

  async function accept() {
    busy = true;
    error = "";
    try {
      const resp = await api.post<{ organization: { id: string; name: string; slug: string } }>(
        `/api/invitations/${token}/accept`,
      );
      await refreshSession();
      status = "joined";
      setTimeout(() => goto(`/orgs/${resp.organization.slug}`), 1200);
    } catch (e) {
      status = "error";
      error = e instanceof Error ? e.message : "Could not accept the invitation";
    } finally {
      busy = false;
    }
  }
</script>

{#if !ready}
  <AuthLayout title="…"><div class="aw-row aw-center"><Spinner label="Loading" /></div></AuthLayout>
{:else if !session.me}
  <AuthLayout title="You've been invited" subtitle="Sign in or create an account to join the organization.">
    <div class="aw-form-actions aw-stack aw-stack--sm">
      <Button variant="primary" href={`/login?continue=${encodeURIComponent(continueUrl)}`}>Sign in</Button>
      <Button variant="secondary" href={`/register?continue=${encodeURIComponent(continueUrl)}`}>Create an account</Button>
    </div>
  </AuthLayout>
{:else if status === "joined"}
  <AuthLayout title="Welcome!" subtitle="You've joined the organization. Taking you there…">
    <p class="aw-muted">Signed in as {session.me.user.email}</p>
  </AuthLayout>
{:else}
  <AuthLayout
    title="Accept the invitation"
    subtitle={status === "error" ? error : `Signed in as ${session.me.user.email}. Accepting joins the organization.`}
  >
    {#if status === "error"}
      <p class="aw-field-error" role="alert">{error}</p>
    {:else}
      <div class="aw-form-actions">
        <Button variant="primary" loading={busy} disabled={busy} onclick={accept}>Accept invitation</Button>
      </div>
    {/if}
    {#snippet footer()}
      {#if status !== "error"}
        <p>Not you? <a href="/login?continue={encodeURIComponent(continueUrl)}">Sign in with a different account</a></p>
      {:else}
        <p><a href="/account">Go to my account</a></p>
      {/if}
    {/snippet}
  </AuthLayout>
{/if}
