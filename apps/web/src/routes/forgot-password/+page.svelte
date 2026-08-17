<script lang="ts">
  import { Button } from "@arcticworks/svelte";
  import { api } from "$lib/api/client";
  import { AuthLayout, FormField } from "$lib/ui";

  let email = $state("");
  let sent = $state(false);
  let error = $state("");
  let busy = $state(false);

  async function submit() {
    busy = true;
    error = "";
    try {
      // Identical response whether or not the account exists.
      await api.post("/api/auth/forgot-password", { email: email.trim() });
      sent = true;
    } catch (e) {
      error = e instanceof Error ? e.message : "Something went wrong";
    } finally {
      busy = false;
    }
  }
</script>

{#if sent}
  <AuthLayout title="Check your email" subtitle="If an account exists for that address, you'll receive a reset link.">
    <p class="aw-muted aw-body-copy">
      The link expires in 30 minutes. If you don't see it, check your spam folder.
    </p>
    <div class="aw-form-actions">
      <Button variant="secondary" href="/login">Back to sign in</Button>
    </div>
  </AuthLayout>
{:else}
  <AuthLayout title="Reset your password" subtitle="We'll email you a link to set a new password.">
    <form
      onsubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <FormField label="Email" name="email" type="email" autocomplete="username" bind:value={email} placeholder="you@example.com" />
      {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
      <div class="aw-form-actions">
        <Button type="submit" variant="primary" loading={busy} disabled={busy || !email}>Send reset link</Button>
      </div>
    </form>
    {#snippet footer()}
      <p><a href="/login">Back to sign in</a></p>
    {/snippet}
  </AuthLayout>
{/if}
