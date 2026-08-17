<script lang="ts">
  import { Button, Input } from "@arcticworks/svelte";
  import Dialog from "./Dialog.svelte";
  import { reauthState, submitReauth, closeReauth } from "$lib/reauth.svelte.ts";

  const reauth = reauthState();
  let password = $state("");
</script>

<Dialog open={reauth.pending !== null} title="Confirm your password" closeOnScrim={false}>
  <p class="aw-muted">For your security, please confirm your password to continue.</p>
  {#if reauth.error}<p class="aw-field-error" role="alert">{reauth.error}</p>{/if}
  {#snippet footer()}
    <div class="aw-dialog-actions">
      <Button variant="secondary" disabled={reauth.busy} onclick={() => { closeReauth(); password = ""; }}>Cancel</Button>
      <Button
        variant="primary"
        loading={reauth.busy}
        disabled={reauth.busy || !password}
        onclick={async () => {
          await submitReauth(password);
          password = "";
        }}
      >
        Confirm
      </Button>
    </div>
  {/snippet}
  <Input type="password" autocomplete="current-password" placeholder="Password" bind:value={password} />
</Dialog>
