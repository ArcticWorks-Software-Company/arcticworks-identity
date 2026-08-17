<script lang="ts">
  import { Input } from "@arcticworks/svelte";

  let {
    label,
    error = undefined,
    hint = undefined,
    value = $bindable(""),
    type = "text",
    autocomplete = undefined,
    name = undefined,
    placeholder = undefined,
    disabled = false,
  } = $props();

  // Label/input association needs a stable id even when no name is given.
  const controlId = $derived(
    name ?? (label ? label.toLowerCase().replace(/[^a-z0-9]+/g, "-") : undefined),
  );
</script>

<div class="aw-form-field">
  {#if label}<label for={controlId}>{label}</label>{/if}
  <Input
    {name}
    id={controlId}
    {type}
    {placeholder}
    {autocomplete}
    {disabled}
    bind:value
    error={!!error}
    aria-invalid={error ? "true" : undefined}
    aria-describedby={error ? `${controlId}-error` : hint ? `${controlId}-hint` : undefined}
  />
  {#if hint && !error}<p class="aw-field-hint" id={`${controlId}-hint`}>{hint}</p>{/if}
  {#if error}<p class="aw-field-error" id={`${controlId}-error`}>{error}</p>{/if}
</div>

<style>
  .aw-field-hint {
    margin: var(--aw-space-1) 0 0;
    font-size: var(--aw-font-size-sm);
    color: var(--aw-color-text-secondary);
  }
</style>
