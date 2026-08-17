<script lang="ts">
  import { Icon } from "@arcticworks/svelte";
  import type { IconName } from "@arcticworks/svelte";
  import type { Snippet } from "svelte";

  let { icon = "folder", title, description, action }: {
    icon?: IconName;
    title: string;
    description?: string;
    action?: Snippet;
  } = $props();
</script>

<div class="empty" role="status">
  <span class="empty-icon"><Icon name={icon} size={20} aria-hidden="true" /></span>
  <p class="empty-title">{title}</p>
  {#if description}<p class="empty-description">{description}</p>{/if}
  {#if action}<div class="empty-action">{@render action()}</div>{/if}
</div>

<style>
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    padding: var(--aw-space-12) var(--aw-space-4);
    color: var(--aw-color-text-secondary);
  }
  .empty-icon {
    opacity: 0.7;
  }
  .empty-title {
    margin: var(--aw-space-3) 0 var(--aw-space-1);
    font-weight: var(--aw-font-weight-semibold);
    color: var(--aw-color-text-primary);
  }
  .empty-description {
    margin: 0;
    font-size: var(--aw-font-size-sm);
    max-width: var(--aw-content-readable-width);
  }
  .empty-action {
    margin-top: var(--aw-space-4);
  }
</style>
