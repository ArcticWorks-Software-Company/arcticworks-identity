<script lang="ts">
  import { browser } from "$app/environment";
  import { api } from "$lib/api/client";
  import { ensureSessionLoaded, sessionState, signOut } from "$lib/session.svelte.ts";
  import { ReauthDialog } from "$lib/ui";
  import { page } from "$app/state";
  import { goto } from "$app/navigation";
  import { Button } from "@arcticworks/svelte";

  let { children } = $props();

  const session = sessionState();

  if (browser) {
    void ensureSessionLoaded().then((me) => {
      if (!me) {
        const continueUrl = page.url.pathname + page.url.search;
        goto(`/login?continue=${encodeURIComponent(continueUrl)}`);
      }
    });
  }

  let loggingOut = $state(false);

  async function logout() {
    loggingOut = true;
    try {
      await api.post("/api/auth/logout");
    } finally {
      signOut();
      goto("/login", { invalidateAll: true });
    }
  }

  const tabs = [
    { href: "/account", label: "Profile" },
    { href: "/account/security", label: "Security" },
    { href: "/account/passkeys", label: "Passkeys" },
    { href: "/account/sessions", label: "Sessions" },
    { href: "/account/applications", label: "Applications" },
    { href: "/account/memberships", label: "Memberships" },
  ];
</script>

<div class="aw-page account" data-density="comfortable">
  <p class="account-context">My account</p>
  <p class="aw-page-description">
    {#if session.me}
      Signed in as <strong>{session.me.user.email}</strong>
    {/if}
  </p>

  <nav class="account-tabs" aria-label="Account sections">
    {#each tabs as tab}
      <a href={tab.href} class="account-tab" class:active={page.url.pathname === tab.href}>{tab.label}</a>
    {/each}
    <span class="aw-spacer"></span>
    <Button variant="secondary" loading={loggingOut} disabled={loggingOut} onclick={logout}>Sign out</Button>
  </nav>

  {@render children()}
  <ReauthDialog />
</div>

<style>
  .account-tabs {
    display: flex;
    gap: var(--aw-space-1);
    border-bottom: var(--aw-border-width) solid var(--aw-color-border-default);
    margin-bottom: var(--aw-space-6);
    flex-wrap: wrap;
  }
  .account-tab {
    padding: var(--aw-space-2) var(--aw-space-3);
    color: var(--aw-color-text-secondary);
    text-decoration: none;
    font-size: var(--aw-font-size-sm);
    font-weight: var(--aw-font-weight-medium);
    border-bottom: var(--aw-border-width) solid transparent;
    white-space: nowrap;
  }
  .account-tab:hover {
    color: var(--aw-color-text-primary);
  }
  .account-tab.active {
    color: var(--aw-color-text-primary);
    border-bottom-color: var(--aw-color-interactive-primary);
  }

  .account-context {
    margin: 0 0 var(--aw-space-1);
    font-size: var(--aw-font-size-sm);
    font-weight: var(--aw-font-weight-semibold);
    color: var(--aw-color-text-secondary);
    text-transform: uppercase;
    letter-spacing: var(--aw-space-0-5);
  }

  @media (max-width: 768px) {
    .account-tabs {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      padding-bottom: var(--aw-space-3);
    }

    .account-tab {
      border: var(--aw-border-width) solid var(--aw-color-border-default);
      border-radius: var(--aw-tabs-radius);
      text-align: center;
    }

    .account-tab.active {
      border-color: var(--aw-color-interactive-primary);
      background: var(--aw-color-interactive-subtle);
    }

    .account-tabs :global(.aw-btn),
    .account-tabs .aw-spacer {
      grid-column: 1 / -1;
      width: 100%;
    }
  }
</style>
