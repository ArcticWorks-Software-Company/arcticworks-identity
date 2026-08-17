/**
 * UI-level tenant isolation and privilege gating: a Viewer cannot reach
 * administrative controls, and a non-member cannot enter an organization.
 */

import { expect, test } from "@playwright/test";
import { PASSWORD, WEB, acceptInvitation, latestLink, registerAndLogin } from "./helpers";

test("viewer cannot reach administrative controls", async ({ browser }) => {
  const adminContext = await browser.newContext();
  const admin = await adminContext.newPage();
  const adminEmail = await registerAndLogin(admin, "iso-admin");
  const orgSlug = `iso-${Date.now().toString(36)}`;

  await admin.goto(`${WEB}/account/memberships`);
  await admin.getByRole("button", { name: "Create organization" }).click();
  await admin.getByLabel("Organization name").fill("Isolation Corp");
  await admin.getByLabel("Slug").fill(orgSlug);
  await admin.getByRole("button", { name: "Create", exact: true }).click();
  await expect(admin).toHaveURL(new RegExp(`/orgs/${orgSlug}$`));

  // Non-member: the org shell refuses entry.
  const strangerContext = await browser.newContext();
  const stranger = await strangerContext.newPage();
  await registerAndLogin(stranger, "iso-stranger");
  await stranger.goto(`${WEB}/orgs/${orgSlug}`);
  await expect(stranger.getByRole("heading", { name: "Organization unavailable" })).toBeVisible();
  await strangerContext.close();

  // Viewer registers first, then the admin invites that address.
  const viewerContext = await browser.newContext();
  const viewer = await viewerContext.newPage();
  const viewerEmail = await registerAndLogin(viewer, "iso-viewer");

  await admin.goto(`${WEB}/orgs/${orgSlug}/members`);
  await admin.getByRole("button", { name: "Invite member" }).click();
  await admin.getByLabel("Email").fill(viewerEmail);
  await admin.getByLabel("Role").selectOption({ label: "Viewer" });
  await admin.getByRole("button", { name: "Send invitation" }).click();
  await expect(admin.getByText(viewerEmail).first()).toBeVisible();

  await acceptInvitation(viewer, await latestLink(viewerEmail, "invited"));

  // Viewer sees the read-only shell: no administrative actions.
  await viewer.goto(`${WEB}/orgs/${orgSlug}/members`);
  await expect(viewer.getByText(viewerEmail).first()).toBeVisible();
  await expect(viewer.getByRole("button", { name: "Invite member" })).toHaveCount(0);
  await expect(viewer.getByRole("button", { name: "Suspend", exact: true })).toHaveCount(0);

  await viewer.goto(`${WEB}/orgs/${orgSlug}/roles`);
  await expect(viewer.getByRole("button", { name: "Create role" })).toHaveCount(0);

  await viewer.goto(`${WEB}/orgs/${orgSlug}/applications`);
  await expect(viewer.getByRole("button", { name: "Register application" })).toHaveCount(0);

  await viewer.goto(`${WEB}/orgs/${orgSlug}/settings`);
  await expect(viewer.getByText(/need the Administrator role/)).toBeVisible();

  await viewerContext.close();
  await adminContext.close();
});
