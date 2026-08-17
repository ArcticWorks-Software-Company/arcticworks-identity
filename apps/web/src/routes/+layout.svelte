<script lang="ts">
  import "@arcticworks/design/themes/dark.css";
  import { Toaster } from "@arcticworks/svelte";
  import "../app.css";
  import { ensureSessionLoaded } from "$lib/session.svelte.ts";
  import { browser } from "$app/environment";

  let { children } = $props();

  if (browser) {
    // Prime the session store once; guarded pages await it themselves.
    void ensureSessionLoaded();
  }
</script>

{@render children()}
<Toaster />
