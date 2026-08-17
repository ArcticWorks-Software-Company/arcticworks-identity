<script lang="ts">
  import { Button } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { api } from "$lib/api/client";
  import { AuthLayout, FormField } from "$lib/ui";

  const token = $derived(page.url.searchParams.get("token") ?? "");

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
      await api.post("/api/auth/reset-password", { token, password });
      done = true;
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not reset your password";
    } finally {
      busy = false;
    }
  }
</script>

{#if !token}
  <AuthLayout title="Invalid link" subtitle="This password reset link is missing its token.">
    <p class="aw-muted">Request a new link from the sign-in page.</p>
    <div class="aw-form-actions">
      <Button variant="secondary" href="/forgot-password">Request a new link</Button>
    </div>
  </AuthLayout>
{:else if done}
  <AuthLayout title="Password updated" subtitle="You can now sign in with your new password.">
    <div class="aw-form-actions">
      <Button variant="primary" href="/login">Sign in</Button>
    </div>
  </AuthLayout>
{:else}
  <AuthLayout title="Choose a new password" subtitle="All other sessions have been signed out.">
    <form
      onsubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <FormField label="New password" name="password" type="password" autocomplete="new-password" bind:value={password} hint="At least 8 characters" />
      <FormField label="Confirm password" name="confirm" type="password" autocomplete="new-password" bind:value={confirm} />
      {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
      <div class="aw-form-actions">
        <Button type="submit" variant="primary" loading={busy} disabled={busy || !password}>Update password</Button>
      </div>
    </form>
  </AuthLayout>
{/if}
