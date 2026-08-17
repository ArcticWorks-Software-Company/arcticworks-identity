<script lang="ts">
  let { children } = $props();
</script>

<main style="max-width: 720px; margin: 3rem auto; padding: 0 1rem; font-family: system-ui, sans-serif; line-height: 1.5">
  <h1 style="font-size: 1.6rem">Continuity (mock application)</h1>
  <p style="color: #666">
    A mock ArcticWorks product demonstrating OIDC login and permission checks
    against ArcticWorks Identity. It authenticates directly through Identity —
    nothing else.
  </p>
  {@render children()}
</main>
