<script lang="ts">
  import { Icon } from "@arcticworks/svelte";

  let { children, title, subtitle = undefined, footer = undefined } = $props();
</script>

<div class="auth-layout" data-density="comfortable">
  <div class="auth-card">
    <div class="auth-brand">
      <Icon name="shield" size={20} aria-hidden="true" />
      <span class="auth-brand-name">ArcticWorks Identity</span>
    </div>
    {#if title}<h1 class="auth-title">{title}</h1>{/if}
    {#if subtitle}<p class="auth-subtitle">{subtitle}</p>{/if}
    {@render children()}
    {#if footer}
    <div class="auth-footer">
      {@render footer()}
    </div>
  {/if}
  </div>
</div>

<style>
  .auth-layout {
    min-height: 100dvh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--aw-space-6);
  }
  .auth-card {
    width: 100%;
    max-width: var(--aw-auth-card-width);
    background: var(--aw-color-surface-2);
    border: var(--aw-border-width) solid var(--aw-color-border-default);
    border-radius: var(--aw-radius-lg);
    padding: var(--aw-space-8);
  }
  .auth-brand {
    display: flex;
    align-items: center;
    gap: var(--aw-space-2);
    margin-bottom: var(--aw-space-6);
    color: var(--aw-color-text-primary);
  }
  .auth-brand-name {
    font-weight: var(--aw-font-weight-semibold);
    font-size: var(--aw-font-size-lg);
  }
  .auth-title {
    font-size: var(--aw-font-size-xl);
    margin: 0 0 var(--aw-space-1);
  }
  .auth-subtitle {
    margin: 0 0 var(--aw-space-6);
    color: var(--aw-color-text-secondary);
    font-size: var(--aw-font-size-sm);
  }
  .auth-footer {
    margin-top: var(--aw-space-5);
    font-size: var(--aw-font-size-sm);
    color: var(--aw-color-text-secondary);
    text-align: center;
  }

  @media (max-width: 768px) {
    .auth-layout {
      align-items: flex-start;
      padding: var(--aw-space-4);
    }

    .auth-card {
      padding: var(--aw-space-6);
    }
  }
</style>
