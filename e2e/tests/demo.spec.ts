/**
 * The ArcticWorks Identity demonstration, end to end, as one serial flow:
 *
 *   registration → email verification → passkey setup → organization
 *   creation → member invitation → role assignment → OIDC login from the
 *   mock Continuity app → permission check → session revocation → device
 *   enrollment → audit events.
 *
 * Requires the full stack: API (8080), Identity web (5173), mock app (5174),
 * Postgres/Valkey/Mailpit in containers, and `npm run db:seed` once.
 */

import { expect, test } from "@playwright/test";
import {
  API,
  MOCK,
  PASSWORD,
  WEB,
  acceptInvitation,
  apiPost,
  createOrg,
  installVirtualAuthenticator,
  latestLink,
  registerAndLogin,
  uniqueEmail,
} from "./helpers";

test("the full demonstration flow", async ({ browser }) => {
  test.setTimeout(240_000);

  // ---- Step 1: admin registration + email verification ----------------
  const adminContext = await browser.newContext();
  const admin = await adminContext.newPage();
  const adminEmail = await registerAndLogin(admin, "admin");
  await expect(admin.getByText(adminEmail)).toBeVisible();

  // ---- Step 2: passkey setup ------------------------------------------
  await installVirtualAuthenticator(adminContext, admin);
  await admin.goto(`${WEB}/account/passkeys`);
  await admin.getByRole("button", { name: "Add passkey" }).click();
  await expect(admin.getByText("My passkey")).toBeVisible();

  // Sign out, then sign back in with the passkey.
  await admin.goto(`${WEB}/login`);
  await admin.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(admin).toHaveURL(/\/account/);

  // ---- Step 3: organization creation ----------------------------------
  const orgSlug = `acme-${Date.now().toString(36)}`;
  await createOrg(admin, "Acme Corp", orgSlug);
  await expect(admin.getByRole("heading", { name: "Overview" })).toBeVisible();

  // ---- Step 3.5: join the seeded org (the mock client lives there) -----
  // The mock Continuity client belongs to the seeded "arcticworks" org, so
  // the e2e admin joins it as Administrator (invited by the seeded admin).
  const seedContext = await browser.newContext();
  const seedAdmin = await seedContext.newPage();
  await seedAdmin.goto(`${WEB}/login`);
  await seedAdmin.getByLabel("Email").fill("admin@arcticworks.dev");
  await seedAdmin.getByLabel("Password").fill("ChangeMe-1234");
  await seedAdmin.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(seedAdmin).toHaveURL(/\/account/);
  await seedAdmin.goto(`${WEB}/orgs/arcticworks/members`);
  await seedAdmin.getByRole("button", { name: "Invite member" }).click();
  await seedAdmin.getByLabel("Email").fill(adminEmail);
  await seedAdmin.getByLabel("Role").selectOption({ label: "Administrator" });
  await seedAdmin.getByRole("button", { name: "Send invitation" }).click();
  await expect(seedAdmin.getByText(adminEmail).first()).toBeVisible();
  await seedContext.close();

  await admin.goto(await latestLink(adminEmail, "invited"));
  await acceptInvitation(admin, await latestLink(adminEmail, "invited"));

  // ---- Step 4: member invitation + acceptance -------------------------
  const memberEmail = uniqueEmail("member");
  await admin.goto(`${WEB}/orgs/${orgSlug}/members`);
  await admin.getByRole("button", { name: "Invite member" }).click();
  await admin.getByLabel("Email").fill(memberEmail);
  await admin.getByLabel("Role").selectOption({ index: 1 }); // Member
  await admin.getByRole("button", { name: "Send invitation" }).click();
  await expect(admin.getByText(memberEmail).first()).toBeVisible();

  const memberContext = await browser.newContext();
  const member = await memberContext.newPage();
  await member.goto(`${WEB}/register`);
  await member.getByLabel("Email").fill(memberEmail);
  await member.getByLabel("Display name").fill("Member");
  await member.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await member.getByLabel("Confirm password").fill(PASSWORD);
  await member.getByRole("button", { name: "Create account" }).click();
  await member.goto(await latestLink(memberEmail, "Verify")); // verification email
  await expect(member.getByRole("heading", { name: "Email verified" })).toBeVisible();
  // Sign in, then accept the invitation.
  await member.goto(`${WEB}/login`);
  await member.getByLabel("Email").fill(memberEmail);
  await member.getByLabel("Password").fill(PASSWORD);
  await member.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(member).toHaveURL(/\/account/);
  const acmeInvite = await latestInviteLink(memberEmail);
  await acceptInvitation(member, acmeInvite);

  // ---- Step 4.5: member joins the seeded org too ----------------------
  await admin.goto(`${WEB}/orgs/arcticworks/members`);
  await admin.getByRole("button", { name: "Invite member" }).click();
  await admin.getByLabel("Email").fill(memberEmail);
  await admin.getByLabel("Role").selectOption({ label: "Member" });
  await admin.getByRole("button", { name: "Send invitation" }).click();
  await expect(admin.getByText(memberEmail).first()).toBeVisible();
  // Accept the SECOND invitation (the seeded org's), skipping the used one.
  await acceptInvitation(member, await latestInviteLink(memberEmail, acmeInvite));

  // ---- Step 5: role assignment ----------------------------------------
  // Admin changes the member's role to Viewer via the UI (sensitive action:
  // the reauthentication dialog appears and must be confirmed).
  await admin.goto(`${WEB}/orgs/${orgSlug}/members`);
  await admin
    .locator("tr", { hasText: memberEmail })
    .locator("select")
    .selectOption({ label: "Viewer" });
  await expect(admin.getByText("Confirm your password").first()).toBeVisible();
  await admin.getByPlaceholder("Password").fill(PASSWORD);
  await admin.getByRole("button", { name: "Confirm" }).click();
  await expect(admin.getByText(memberEmail).first()).toBeVisible();

  // A Viewer cannot manage teams — the create button is absent.
  await member.goto(`${WEB}/orgs/${orgSlug}/teams`);
  await expect(member.getByRole("button", { name: "Create team" })).toHaveCount(0);

  // The product permission must be granted in the seeded org (where the
  // mock client and its permission-check service account live).
  await admin.goto(`${WEB}/orgs/arcticworks/roles`);
  await admin.getByRole("button", { name: "Create role" }).click();
  await admin.getByLabel("Role name").fill("Document Reader");
  await admin.getByLabel("Additional permissions").fill("continuity.document.read");
  await admin.getByLabel("Additional permissions").press("Tab"); // blur: stop focus-scroll fighting the click
  await admin.getByRole("button", { name: "Save role" }).click();
  await expect(admin.getByText("Document Reader")).toBeVisible();

  await admin.goto(`${WEB}/orgs/arcticworks/members`);
  await admin.locator("tr", { hasText: memberEmail }).locator("select").selectOption({ label: "Document Reader" });
  await expect(admin.getByText("Confirm your password").first()).toBeVisible();
  await admin.getByPlaceholder("Password").fill(PASSWORD);
  await admin.getByRole("button", { name: "Confirm" }).click();

  // ---- Step 6: OIDC login from the mock Continuity app ----------------
  await member.goto(`${MOCK}/`);
  await member.getByRole("link", { name: "Sign in with ArcticWorks" }).click();
  // The mock's login page starts the OIDC flow.
  await expect(member).toHaveURL(/localhost:5174\/login/);
  await member.getByRole("button", { name: "Sign in with ArcticWorks" }).click();

  // Identity consent screen (first grant for this client).
  await expect(member).toHaveURL(/localhost:5173\/authorize/);
  await expect(member.getByText("Continuity (mock)").first()).toBeVisible();
  await member.getByRole("button", { name: "Authorize" }).click();

  // Back in the mock: claims + permission check through the documented API.
  await expect(member).toHaveURL(`${MOCK}/`);
  await expect(member.getByText("Signed in", { exact: true })).toBeVisible();
  await expect(member.getByText(memberEmail)).toBeVisible();
  await expect(member.getByText("continuity.document.read")).toBeVisible();
  await expect(member.getByText("ALLOWED", { exact: true })).toBeVisible();

  // ---- Step 7: session revocation -------------------------------------
  // Second session for the member, then revoke it from the first.
  const otherContext = await browser.newContext();
  const other = await otherContext.newPage();
  await other.goto(`${WEB}/login`);
  await other.getByLabel("Email").fill(memberEmail);
  await other.getByLabel("Password").fill(PASSWORD);
  await other.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(other).toHaveURL(/\/account/);

  await member.goto(`${WEB}/account/sessions`);
  await expect(member.getByText("Another device")).toBeVisible();
  await member.getByRole("button", { name: "Revoke", exact: true }).first().click();
  await member.getByRole("button", { name: "Revoke session" }).click();

  // Sensitive action requires reauthentication.
  await expect(member.getByText("Confirm your password").first()).toBeVisible();
  await member.getByPlaceholder("Password").fill(PASSWORD);
  await member.getByRole("button", { name: "Confirm" }).click();
  await expect(member.getByText("Another device")).toHaveCount(0);

  await other.reload();
  await expect(other).toHaveURL(/\/login/);
  await otherContext.close();

  // ---- Step 8: device enrollment --------------------------------------
  await admin.goto(`${WEB}/orgs/${orgSlug}/devices`);
  await admin.getByRole("button", { name: "Create enrollment token" }).click();
  await expect(admin.getByRole("dialog", { name: "Enrollment token" })).toBeVisible();
  const token = (await admin.locator("code").first().textContent())!.trim();

  const enrollResp = await apiPost(adminContext, "/api/enroll", { token, name: "sensor-01" });
  expect(enrollResp.status).toBe(201);
  const device = (await enrollResp.json()) as { device: { name: string } };
  expect(device.device.name).toBe("sensor-01");

  const reuseResp = await apiPost(adminContext, "/api/enroll", { token, name: "sensor-02" });
  expect(reuseResp.status).toBe(401); // single-use token

  await admin.goto(`${WEB}/orgs/${orgSlug}/devices`);
  await expect(admin.getByText("sensor-01")).toBeVisible();

  // ---- Step 9: audit events -------------------------------------------
  await admin.goto(`${WEB}/orgs/${orgSlug}/audit`);
  for (const event of ["org.created", "invite.created", "invite.accepted", "member.role_changed", "device.enrolled", "device.enrollment_token_created"]) {
    await expect(admin.getByText(event, { exact: true })).toBeVisible();
  }

  await adminContext.close();
  await memberContext.close();
});

/** The invitation email link (Mailpit may also hold the verification mail). */
async function latestInviteLink(to: string, excludeLink?: string): Promise<string> {
  return latestLink(to, "invited", excludeLink);
}

export const API_URL = API;
