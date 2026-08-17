<script lang="ts">
  import { Button } from "@arcticworks/svelte";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { api, ApiError } from "$lib/api/client";
  import { refreshSession, sessionState } from "$lib/session.svelte.ts";
  import { authenticatePasskey, supportsPasskeys } from "$lib/passkeys";
  import { AuthLayout, FormField } from "$lib/ui";
  import { safeContinue } from "$lib/util";

  const continueUrl = $derived(safeContinue(page.url.searchParams.get("continue")));
  const session = sessionState();

  let email = $state("");
  let password = $state("");
  let error = $state("");
  let busy = $state(false);
  let passkeyBusy = $state(false);
  let mfaToken = $state("");
  let mfaCode = $state("");

  // Continue after login: in-app navigations use goto; the OAuth
  // continuation is an absolute URL on the Identity API origin and needs a
  // full-page navigation so the browser follows the redirect chain back to
  // the application.
  function navigateAfterLogin() {
    if (continueUrl) {
      if (continueUrl.startsWith("http")) {
        window.location.href = continueUrl;
      } else {
        goto(continueUrl, { invalidateAll: true });
      }
    } else {
      goto("/account", { invalidateAll: true });
    }
  }

  async function submit() {
    busy = true;
    error = "";
    try {
      const resp = await api.post<{ mfaRequired?: boolean; mfaToken?: string }>("/api/auth/login", {
        email: email.trim(),
        password,
      });
      if (resp.mfaRequired && resp.mfaToken) {
        mfaToken = resp.mfaToken;
        return;
      }
      await refreshSession();
      navigateAfterLogin();
    } catch (e) {
      if (e instanceof ApiError && e.code === "email_not_verified") {
        goto(`/verify-email?email=${encodeURIComponent(email.trim())}`);
        return;
      }
      error = e instanceof Error ? e.message : "Login failed";
    } finally {
      busy = false;
    }
  }

  async function submitMfa() {
    busy = true;
    error = "";
    try {
      await api.post("/api/auth/mfa", { token: mfaToken, code: mfaCode });
      await refreshSession();
      navigateAfterLogin();
    } catch (e) {
      error = e instanceof Error ? e.message : "Verification failed";
    } finally {
      busy = false;
    }
  }

  async function passkeyLogin() {
    passkeyBusy = true;
    error = "";
    try {
      await authenticatePasskey();
      await refreshSession();
      navigateAfterLogin();
    } catch (e) {
      error = e instanceof Error ? e.message : "Passkey sign-in failed";
    } finally {
      passkeyBusy = false;
    }
  }
</script>

<AuthLayout title="Sign in" subtitle="Continue to your ArcticWorks account">
  {#if mfaToken}
    <form
      onsubmit={(e) => {
        e.preventDefault();
        submitMfa();
      }}
    >
      <p class="aw-body-copy">
        Enter the six-digit code from your authenticator app.
      </p>
      <FormField
        label="Authentication code"
        name="mfaCode"
        autocomplete="one-time-code"
        placeholder="123456"
        bind:value={mfaCode}
      />

      {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}

      <div class="aw-form-actions aw-stack aw-stack--sm">
        <Button type="submit" variant="primary" loading={busy} disabled={busy || mfaCode.length !== 6}>Verify</Button>
        <Button type="button" variant="secondary" disabled={busy} onclick={() => { mfaToken = ""; mfaCode = ""; error = ""; }}>
          Back
        </Button>
      </div>
    </form>
  {:else}
  <form
    onsubmit={(e) => {
      e.preventDefault();
      submit();
    }}
  >
    <FormField label="Email" name="email" type="email" autocomplete="username" bind:value={email} placeholder="you@example.com" />
    <FormField label="Password" name="password" type="password" autocomplete="current-password" bind:value={password} />

    {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}

    <div class="aw-form-actions aw-stack aw-stack--sm">
      <Button type="submit" variant="primary" loading={busy} disabled={busy || !email || !password}>Sign in</Button>
      {#if supportsPasskeys()}
        <Button type="button" variant="secondary" loading={passkeyBusy} disabled={passkeyBusy} onclick={passkeyLogin}>
          Sign in with a passkey
        </Button>
      {/if}
    </div>
  </form>
  {/if}

  {#snippet footer()}
    <p>
      <a href="/forgot-password">Forgot your password?</a>
    </p>
    <p class="aw-form-actions">
      New to ArcticWorks? <a href={`/register${continueUrl ? `?continue=${encodeURIComponent(continueUrl)}` : ""}`}>Create an account</a>
    </p>
  {/snippet}
</AuthLayout>
