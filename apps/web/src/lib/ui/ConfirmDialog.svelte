<script lang="ts">
  import { Button } from "@arcticworks/svelte";
  import Dialog from "./Dialog.svelte";

  let { open = $bindable(false), title, description, confirmLabel = "Confirm", cancelLabel = "Cancel", danger = true, onConfirm } = $props();
  let busy = $state(false);
  let error = $state("");
</script>

<Dialog bind:open {title} closeOnScrim={!busy}>
  {#if description}<p class="aw-muted">{description}</p>{/if}
  {#if error}<p class="aw-field-error" role="alert">{error}</p>{/if}
  {#snippet footer()}
    <div class="aw-dialog-actions">
      <Button variant="secondary" disabled={busy} onclick={() => (open = false)}>{cancelLabel}</Button>
      <Button
        variant={danger ? "danger" : "primary"}
        loading={busy}
        disabled={busy}
        onclick={async () => {
          busy = true;
          error = "";
          try {
            await onConfirm();
            open = false;
          } catch (e) {
            error = e instanceof Error ? e.message : "Something went wrong";
          } finally {
            busy = false;
          }
        }}
      >
        {confirmLabel}
      </Button>
    </div>
  {/snippet}
</Dialog>
