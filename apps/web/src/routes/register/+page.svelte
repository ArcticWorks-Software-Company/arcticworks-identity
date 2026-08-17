<script lang="ts">
  import { Button } from "@arcticworks/svelte";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { api, ApiError } from "$lib/api/client";
  import { AuthLayout, FormField } from "$lib/ui";
  import { safeContinue } from "$lib/util";

  const continueUrl = $derived(safeContinue(page.url.searchParams.get("continue")));

  let email = $state("");
  let displayName = $state("");
  let password = $state("");
  let confirm = $state("");
  let error = $state("");
  let busy = $state(false);
  let done = $state(false);

  async function submit() {
    error = "";
    if (password.length < 8) {
      error = "Password must be at least 8 characters";
      return;
    }
    if (password !== confirm) {
      error = "Passwords do not match";
      return;
    }
    busy = true;
    try {
      await api.post("/api/auth/register", { email: email.trim(), password, displayName: displayName.trim() });
      done = true;
    } catch (e) {
      error = e instanceof Error ? e.message : "Registration failed";
    } finally {
      busy = false;
    }
  }
</script>

{#if done}
  <AuthLayout title="Check your email" subtitle={`We sent a verification link to ${email.trim()}.`}>
    <p class="aw-muted aw-body-copy">
      You'll need to verify your email address before you can sign in. The link expires in 24 hours.
    </p>
    <div class="aw-form-actions">
      <Button variant="secondary" href={`/verify-email?email=${encodeURIComponent(email.trim())}`}>Resend verification email</Button>
    </div>
    {#snippet footer()}
      <p>Already verified? <a href="/login">Sign in</a></p>
    {/snippet}
  </AuthLayout>
{:else}
  <AuthLayout title="Create your account" subtitle="One account for every ArcticWorks product">
    <form
      onsubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <FormField label="Email" name="email" type="email" autocomplete="username" bind:value={email} placeholder="you@example.com" />
      <FormField label="Display name" name="displayName" autocomplete="name" bind:value={displayName} placeholder="Your name" />
      <FormField
        label="Password"
        name="password"
        type="password"
        autocomplete="new-password"
        bind:value={password}
        hint="At least 8 characters"
      />
      <FormField label="Confirm password" name="confirm" type="password" autocomplete="new-password" bind:value={confirm} />

      {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}

      <div class="aw-form-actions">
        <Button type="submit" variant="primary" loading={busy} disabled={busy || !email || !password}>Create account</Button>
      </div>
    </form>
    {#snippet footer()}
      <p>
        Already have an account? <a href="/login">Sign in</a>
      </p>
    {/snippet}
  </AuthLayout>
{/if}
