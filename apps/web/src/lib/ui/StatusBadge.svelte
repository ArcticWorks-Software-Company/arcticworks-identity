<script lang="ts">
  import { Badge } from "@arcticworks/svelte";

  let { status, active = "active" } = $props();
  const variant = $derived(
    status === "active" ? "success" : status === "suspended" || status === "revoked" ? "danger" : "neutral",
  );
  const label = $derived(status === active ? "Active" : status);
</script>

<Badge {variant} dot>{label}</Badge>
