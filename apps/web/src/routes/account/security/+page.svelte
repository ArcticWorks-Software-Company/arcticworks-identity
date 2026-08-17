<script lang="ts">
  import { Button, Card } from "@arcticworks/svelte";
  import { api } from "$lib/api/client";
  import { withReauth } from "$lib/reauth.svelte.ts";
  import { Dialog, FormField, PageHeader } from "$lib/ui";

  // Change password
  let currentPassword = $state("");
  let newPassword = $state("");
  let confirmPassword = $state("");
  let passwordError = $state("");
  let passwordSuccess = $state("");
  let passwordBusy = $state(false);

  async function changePassword() {
    passwordError = "";
    passwordSuccess = "";
    if (newPassword.length < 8) {
      passwordError = "New password must be at least 8 characters";
      return;
    }
    if (newPassword !== confirmPassword) {
      passwordError = "New passwords do not match";
      return;
    }
    passwordBusy = true;
    try {
      await withReauth(async () => {
        await api.post("/api/account/password", {
          currentPassword,
          newPassword,
        });
      });
      currentPassword = "";
      newPassword = "";
      confirmPassword = "";
      passwordSuccess = "Password changed. Other sessions were signed out.";
    } catch (e) {
      passwordError = e instanceof Error ? e.message : "Could not change your password";
    } finally {
      passwordBusy = false;
    }
  }

  // Recovery codes
  let codes = $state<string[] | null>(null);
  let codesError = $state("");
  let codesBusy = $state(false);

  async function generateCodes() {
    codesError = "";
    codesBusy = true;
    try {
      await withReauth(async () => {
        const resp = await api.get<{ codes: string[] }>("/api/account/recovery-codes");
        codes = resp.codes;
      });
    } catch (e) {
      codesError = e instanceof Error ? e.message : "Could not generate recovery codes";
    } finally {
      codesBusy = false;
    }
  }
</script>

<div class="aw-page--narrow">
  <PageHeader title="Security" description="Password and account recovery." />

  <h2 class="aw-section-title">Change password</h2>
  <Card>
    <form
      onsubmit={(e) => {
        e.preventDefault();
        changePassword();
      }}
    >
      <FormField label="Current password" name="currentPassword" type="password" autocomplete="current-password" bind:value={currentPassword} />
      <FormField label="New password" name="newPassword" type="password" autocomplete="new-password" bind:value={newPassword} hint="At least 8 characters" />
      <FormField label="Confirm new password" name="confirmPassword" type="password" autocomplete="new-password" bind:value={confirmPassword} />
      {#if passwordError}<p class="aw-field-error" role="alert">{passwordError}</p>{/if}
      {#if passwordSuccess}<p class="aw-field-success" role="status">{passwordSuccess}</p>{/if}
      <div class="aw-form-actions">
        <Button type="submit" variant="primary" loading={passwordBusy} disabled={passwordBusy || !currentPassword || !newPassword}>
          Change password
        </Button>
      </div>
    </form>
  </Card>

  <h2 class="aw-section-title">Recovery codes</h2>
  <Card>
    <p class="aw-muted aw-body-copy aw-flush">
      Recovery codes let you sign in if you lose access to your password and passkeys. Each code works once; generating a new set invalidates the previous one. You will only see the codes once.
    </p>
    {#if codesError}<p class="aw-field-error" role="alert">{codesError}</p>{/if}

    {#if codes}
      <Dialog open={true} title="Your recovery codes" closeOnScrim={false}>
        <p class="aw-muted">Store these somewhere safe. They will not be shown again.</p>
        <ul class="aw-recovery-codes">
          {#each codes as code}
            <li>{code}</li>
          {/each}
        </ul>
        {#snippet footer()}
          <div class="aw-dialog-actions">
            <Button variant="primary" onclick={() => (codes = null)}>I've saved them</Button>
          </div>
        {/snippet}
      </Dialog>
    {:else}
      <Button variant="secondary" loading={codesBusy} disabled={codesBusy} onclick={generateCodes}>Generate recovery codes</Button>
    {/if}
  </Card>
</div>
