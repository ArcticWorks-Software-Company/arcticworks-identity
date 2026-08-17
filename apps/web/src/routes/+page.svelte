<script lang="ts">
  import { Spinner } from "@arcticworks/svelte";
  import { browser } from "$app/environment";
  import { goto } from "$app/navigation";
  import { ensureSessionLoaded } from "$lib/session.svelte.ts";

  if (browser) {
    void ensureSessionLoaded().then((me) => {
      goto(me ? "/account" : "/login", { replaceState: true });
    });
  }
</script>

<div class="aw-page">
  <div class="aw-row" role="status"><Spinner label="Loading" /> <span class="aw-muted">Loading…</span></div>
</div>
