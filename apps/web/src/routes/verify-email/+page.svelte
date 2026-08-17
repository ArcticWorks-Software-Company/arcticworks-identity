<script lang="ts">
  import { Button } from "@arcticworks/svelte";
  import { page } from "$app/state";
  import { browser } from "$app/environment";
  import { api, ApiError } from "$lib/api/client";
  import { AuthLayout, FormField } from "$lib/ui";

  const tokenParam = $derived(page.url.searchParams.get("token"));
  const emailParam = $derived(page.url.searchParams.get("email") ?? "");

  let email = $state("");
  let status = $state<"idle" | "verifying" | "verified" | "error">("idle");
  let error = $state("");

  $effect(() => {
    email = emailParam;
  });
  let busy = $state(false);

  async function verify(token: string) {
    status = "verifying";
    try {
      await api.post("/api/auth/verify-email", { token });
      status = "verified";
    } catch (e) {
      status = "error";
      error = e instanceof Error ? e.message : "Verification failed";
    }
  }

  // Consume the token exactly once, in the browser. The token is single-use,
  // so this must not run during SSR (it would be spent before hydration).
  $effect(() => {
    if (browser && tokenParam) void verify(tokenParam);
  });

  async function resend() {
    busy = true;
    error = "";
    try {
      await api.post("/api/auth/resend-verification", { email: email.trim() });
      status = "idle";
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not resend";
    } finally {
      busy = false;
    }
  }
</script>

{#if status === "verified"}
  <AuthLayout title="Email verified" subtitle="Your account is ready.">
    <p class="aw-muted">You can now sign in with your email and password.</p>
    <div class="aw-form-actions">
      <Button variant="primary" href="/login">Sign in</Button>
    </div>
  </AuthLayout>
{:else if status === "verifying"}
  <AuthLayout title="Verifying your email…">
    <p class="aw-muted">Please wait.</p>
  </AuthLayout>
{:else}
  <AuthLayout
    title={status === "error" ? "Verification failed" : "Verify your email"}
    subtitle={status === "error" ? error : "Enter the email you registered with to receive a new link."}
  >
    <form
      onsubmit={(e) => {
        e.preventDefault();
        resend();
      }}
    >
      <FormField label="Email" name="email" type="email" autocomplete="username" bind:value={email} />
      <div class="aw-form-actions">
        <Button type="submit" variant="primary" loading={busy} disabled={busy || !email}>Send verification email</Button>
      </div>
    </form>
    {#snippet footer()}
      <p><a href="/login">Back to sign in</a></p>
    {/snippet}
  </AuthLayout>
{/if}
