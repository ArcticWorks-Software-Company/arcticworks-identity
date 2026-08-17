<script lang="ts">
  let { title, description, actions = undefined } = $props();
</script>

<header class="page-header">
  <div>
    <h1 class="aw-page-title">{title}</h1>
    {#if description}<p class="aw-page-description">{description}</p>{/if}
  </div>
  {#if actions}<div class="page-actions">{@render actions()}</div>{/if}
</header>

<style>
  .page-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--aw-space-4);
    margin-bottom: var(--aw-space-6);
  }
  .page-actions {
    display: flex;
    gap: var(--aw-space-2);
    flex-shrink: 0;
  }

  @media (max-width: 768px) {
    .page-header {
      flex-direction: column;
    }

    .page-actions,
    .page-actions :global(.aw-btn) {
      width: 100%;
    }
  }
</style>
