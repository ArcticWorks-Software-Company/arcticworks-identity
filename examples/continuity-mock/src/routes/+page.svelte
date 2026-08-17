<script lang="ts">
  let { data } = $props();
</script>

{#if !data.signedIn && data.loginError}
  <div role="alert" style="margin-top: 1.5rem; padding: 0.75rem 1rem; border: 1px solid var(--aw-color-status-danger, #f87171); border-radius: 6px; background: var(--aw-color-status-danger-subtle, #2a1215); color: var(--aw-color-status-danger, #f87171)">
    <strong>Sign-in failed</strong>
    <p style="margin: 0.25rem 0 0">{data.loginError}</p>
    <p style="margin: 0.25rem 0 0; font-size: 0.85rem">
      Applications are scoped to an organization — ask an administrator to invite you to the application's organization.
    </p>
  </div>
{/if}

{#if !data.signedIn}
  <div style="margin-top: 2rem">
    <p>You are not signed in. Sign in with your ArcticWorks Identity account to continue.</p>
    <a
      href="/login"
      style="display: inline-block; margin-top: 1rem; padding: 0.6rem 1.2rem; background: #2563eb; color: #fff; border-radius: 6px; text-decoration: none"
      >Sign in with ArcticWorks</a
    >
  </div>
{:else}
  <section style="margin-top: 2rem">
    <h2 style="font-size: 1.1rem">Signed in</h2>
    <dl style="display: grid; grid-template-columns: max-content 1fr; gap: 0.4rem 1rem">
      <dt>Subject</dt><dd><code>{data.claims?.sub}</code></dd>
      {#if data.claims?.name}<dt>Name</dt><dd>{data.claims.name}</dd>{/if}
      {#if data.claims?.email}<dt>Email</dt><dd>{data.claims.email} ({data.claims.email_verified ? "verified" : "unverified"})</dd>{/if}
      {#if data.claims?.org}<dt>Organization</dt><dd><code>{data.claims.org}</code></dd>{/if}
      <dt>Access token (truncated)</dt><dd><code>{data.session?.accessToken.slice(0, 40)}…</code></dd>
    </dl>

    <h2 style="font-size: 1.1rem; margin-top: 1.5rem">Permission check</h2>
    {#if data.checked}
      <p>
        <code>{data.permission}</code> →
        <strong>{data.allowed ? "ALLOWED" : "DENIED"}</strong>
      </p>
      <p style="color: #666; font-size: 0.9rem">
        Checked through <code>POST /api/v1/authorize/check</code> with the product's service account.
      </p>
    {:else}
      <p style="color: #666">The id_token carries no organization context — nothing to check.</p>
    {/if}

    <a href="/logout" style="display: inline-block; margin-top: 1.5rem; color: #b91c1c">Sign out</a>
  </section>
{/if}
