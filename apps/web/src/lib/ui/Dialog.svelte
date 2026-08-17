<script lang="ts">
  import { IconButton } from "@arcticworks/svelte";
  import { tick } from "svelte";
  import type { Snippet } from "svelte";

  let {
    open = $bindable(false),
    title,
    closeOnScrim = true,
    children,
    footer = undefined,
  }: {
    open?: boolean;
    title: string;
    closeOnScrim?: boolean;
    children: Snippet;
    footer?: Snippet;
  } = $props();

  let dialogElement = $state<HTMLDivElement>();
  let previouslyFocused: HTMLElement | null = null;

  const focusableSelector = [
    "button:not([disabled])",
    "a[href]",
    "input:not([disabled])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    '[tabindex]:not([tabindex="-1"])',
  ].join(",");
  const initialFocusSelector = [
    "input:not([disabled])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    "button:not([disabled]):not(.dialog-close)",
    "a[href]",
  ].join(",");

  function close() {
    if (closeOnScrim) open = false;
  }

  function handleKeydown(event: KeyboardEvent) {
    if (!open) return;
    if (event.key === "Escape") {
      if (closeOnScrim) {
        event.preventDefault();
        open = false;
      }
      return;
    }
    if (event.key !== "Tab" || !dialogElement) return;

    const focusable = [...dialogElement.querySelectorAll<HTMLElement>(focusableSelector)];
    if (focusable.length === 0) {
      event.preventDefault();
      dialogElement.focus();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  $effect(() => {
    if (open) {
      previouslyFocused = document.activeElement as HTMLElement | null;
      void tick().then(() => {
        const firstControl = dialogElement?.querySelector<HTMLElement>(initialFocusSelector);
        (firstControl ?? dialogElement)?.focus();
      });
    } else if (previouslyFocused) {
      previouslyFocused.focus();
      previouslyFocused = null;
    }
  });
</script>

{#if open}
  <div class="dialog-overlay">
    {#if closeOnScrim}
      <button class="dialog-scrim" type="button" tabindex="-1" aria-label="Close dialog" onclick={close}></button>
    {:else}
      <div class="dialog-scrim"></div>
    {/if}
    <div
      class="aw-dialog"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      bind:this={dialogElement}
      onkeydown={handleKeydown}
    >
      <header class="dialog-header">
        <h2>{title}</h2>
        {#if closeOnScrim}
          <IconButton icon="x" label="Close" class="dialog-close" onclick={close} />
        {/if}
      </header>
      <div class="dialog-body">{@render children()}</div>
      {#if footer}<footer class="dialog-footer">{@render footer()}</footer>{/if}
    </div>
  </div>
{/if}

<style>
  .dialog-overlay {
    position: fixed;
    inset: 0;
    z-index: var(--aw-z-dialog);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--aw-space-6);
  }

  .dialog-scrim {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    padding: 0;
    border: 0;
    background: var(--aw-color-scrim);
  }

  .aw-dialog {
    display: flex;
    width: min(100%, var(--aw-dialog-width));
    max-height: calc(100dvh - (2 * var(--aw-space-6)));
    flex-direction: column;
    overflow: hidden;
    border: var(--aw-border-width) solid var(--aw-color-border-strong);
    border-radius: var(--aw-radius-xl);
    background: var(--aw-color-surface-3);
    box-shadow: var(--aw-shadow-3);
    position: relative;
  }

  .dialog-header,
  .dialog-footer {
    display: flex;
    align-items: center;
    gap: var(--aw-space-2);
    padding-inline: var(--aw-space-5);
  }

  .dialog-header {
    padding-top: var(--aw-space-4);
  }

  .dialog-header h2 {
    flex: 1;
    margin: 0;
    font-size: var(--aw-font-size-base);
    font-weight: var(--aw-font-weight-semibold);
  }

  .dialog-body {
    display: flex;
    flex-direction: column;
    gap: var(--aw-space-3);
    overflow: auto;
    padding: var(--aw-space-4) var(--aw-space-5);
    color: var(--aw-color-text-secondary);
    font-size: var(--aw-font-size-sm);
  }

  .dialog-footer {
    justify-content: flex-end;
    padding-bottom: var(--aw-space-4);
  }

  @media (max-width: 768px) {
    .dialog-overlay {
      align-items: flex-end;
      padding: var(--aw-space-3);
    }
  }
</style>
