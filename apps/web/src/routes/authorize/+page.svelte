<script lang="ts">
  import { Button, Spinner } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api, ApiError, apiBase } from "$lib/api/client";
  import { ensureSessionLoaded, sessionState } from "$lib/session.svelte.ts";
  import { AuthLayout } from "$lib/ui";
  import type { ConsentInfo } from "$lib/api/types";

  const params = $derived(page.url.searchParams);
  const continueUrl = $derived(page.url.pathname + page.url.search);

  const session = sessionState();
  const ready = $derived(!session.loading);

  let info = $state<ConsentInfo | null>(null);
  let loading = $state(true);
  let error = $state("");
  let busy = $state(false);

  async function load() {
    loading = true;
    error = "";
    try {
      await ensureSessionLoaded();
      if (!session.me) return; // not signed in — show sign-in prompt
      const query = new URLSearchParams({
        client_id: params.get("client_id") ?? "",
        redirect_uri: params.get("redirect_uri") ?? "",
        scope: params.get("scope") ?? "",
      });
      const state = params.get("state");
      const nonce = params.get("nonce");
      if (state) query.set("state", state);
      if (nonce) query.set("nonce", nonce);
      info = await api.get<ConsentInfo>(`/api/oidc/consent-info?${query}`);
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not load the authorization request";
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (ready) load();
  });

  let consentForm = $state<HTMLFormElement | null>(null);
  let pendingDecision = $state("");

  // Native form submission: the browser follows the 303 → callback chain as
  // a top-level navigation (no CORS), carrying the session cookie.
  function decide(decision: "approve" | "deny") {
    pendingDecision = decision;
    consentForm?.submit();
  }

  const scopeLabels: Record<string, string> = {
    openid: "Sign in with your ArcticWorks identity",
    profile: "View your display name",
    email: "View your email address",
    offline_access: "Keep you signed in and refresh your session",
  };
</script>

{#if loading}
  <AuthLayout title="Authorizing…">
    <div class="aw-row aw-center"><Spinner label="Loading" /></div>
  </AuthLayout>
{:else if !session.me}
  <AuthLayout title="Sign in required" subtitle="This application needs you to be signed in to continue.">
    <div class="aw-form-actions aw-stack aw-stack--sm">
      <Button variant="primary" href={`/login?continue=${encodeURIComponent(continueUrl)}`}>Sign in</Button>
      <Button variant="secondary" href={`/register?continue=${encodeURIComponent(continueUrl)}`}>Create an account</Button>
    </div>
  </AuthLayout>
{:else if info}
  <AuthLayout title="Authorize application" subtitle={`${info.client.name} wants access to your ArcticWorks account`}>
    <div class="consent-details">
      <section>
        <h2>Application</h2>
        <p class="consent-value">{info.client.name}</p>
        <p class="aw-meta aw-monospace">{info.client.clientId}</p>
      </section>
      <section>
        <h2>Organization</h2>
        <p class="aw-flush">{info.organization.name} <span class="aw-muted">({info.organization.slug})</span></p>
      </section>
      <section>
        <h2>This will allow the application to</h2>
        <ul class="consent-scopes">
          {#each info.scopes as scope}
            <li>{scopeLabels[scope] ?? scope}</li>
          {/each}
        </ul>
      </section>
      <section>
        <h2>Redirecting to</h2>
        <p class="aw-muted aw-monospace consent-uri">{info.redirectUri}</p>
      </section>
    </div>

    {#if error}<p class="aw-field-error aw-form-actions" role="alert">{error}</p>{/if}

    <form
      method="post"
      action={`${apiBase()}/oidc/consent`}
      bind:this={consentForm}
      aria-label="Authorization decision"
    >
      <input type="hidden" name="client_id" value={params.get("client_id") ?? ""} />
      <input type="hidden" name="redirect_uri" value={params.get("redirect_uri") ?? ""} />
      <input type="hidden" name="scope" value={params.get("scope") ?? ""} />
      <input type="hidden" name="state" value={params.get("state") ?? ""} />
      <input type="hidden" name="nonce" value={params.get("nonce") ?? ""} />
      <input type="hidden" name="code_challenge" value={params.get("code_challenge") ?? ""} />
      <input type="hidden" name="code_challenge_method" value={params.get("code_challenge_method") ?? ""} />
      <input type="hidden" name="decision" value={pendingDecision} />
      <div class="aw-form-actions aw-inline-actions">
        <Button type="submit" variant="primary" onclick={() => decide("approve")}>Authorize</Button>
        <Button type="submit" variant="secondary" onclick={() => decide("deny")}>Deny</Button>
      </div>
    </form>
  </AuthLayout>
{:else}
  <AuthLayout title="Request failed" subtitle={error}>
    <p class="aw-muted">Close this window and try signing in to the application again.</p>
  </AuthLayout>
{/if}

<style>
  .consent-details {
    display: flex;
    flex-direction: column;
    gap: var(--aw-space-4);
  }

  .consent-details h2 {
    margin: 0 0 var(--aw-space-2);
    color: var(--aw-color-text-secondary);
    font-size: var(--aw-font-size-sm);
  }

  .consent-value {
    margin: 0;
    font-weight: var(--aw-font-weight-semibold);
  }

  .consent-scopes {
    margin: 0;
    padding-left: var(--aw-space-5);
    line-height: var(--aw-line-height-body);
  }

  .consent-uri {
    margin: 0;
    overflow-wrap: anywhere;
  }
</style>
