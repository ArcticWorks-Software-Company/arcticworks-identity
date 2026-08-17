<script lang="ts">
  let { form }: { form?: { error?: string } | null } = $props();
</script>

<form method="POST">
  <button
    type="submit"
    style="padding: 0.6rem 1.2rem; background: #2563eb; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 1rem"
    >Sign in with ArcticWorks</button
  >
  {#if form?.error}<p style="color: #b91c1c">{form.error}</p>{/if}
</form>
