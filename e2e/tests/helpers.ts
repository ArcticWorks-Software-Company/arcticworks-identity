/** Shared helpers for the e2e suite: unique accounts, Mailpit links,
 * WebAuthn virtual authenticator, API calls with session cookies. */

import type { BrowserContext, Page } from "@playwright/test";
import { expect } from "@playwright/test";

export const API = "http://localhost:8080";
export const WEB = "http://localhost:5173";
export const MOCK = "http://localhost:5174";
export const MAILPIT = "http://localhost:8025";

let counter = 0;

/** A unique email for this run (registration is rate-limited per address). */
export function uniqueEmail(prefix: string): string {
  counter += 1;
  return `${prefix}-${Date.now().toString(36)}-${counter}@arcticworks.dev`;
}

export const PASSWORD = "Correct-Horse-123";

/** Fetch the latest email for an address (optionally filtered by a subject
 * keyword) from Mailpit and return the first https?:// link found in it. */
export async function latestLink(
  to: string,
  subjectKeyword?: string,
  excludeLink?: string,
): Promise<string> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const query = subjectKeyword
      ? `to:"${to}" subject:"${subjectKeyword}"`
      : `to:"${to}"`;
    const resp = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(query)}`);
    const data = (await resp.json()) as { messages: { ID: string }[] };
    const messages = [...data.messages].sort((a, b) => (a.ID < b.ID ? 1 : -1));
    for (const msg of messages) {
      const detail = (await (await fetch(`${MAILPIT}/api/v1/message/${msg.ID}`)).json()) as {
        HTML?: string;
        Text?: string;
      };
      const body = detail.HTML ?? detail.Text ?? "";
      const href = body.match(/href="([^"]+)"/)?.[1] ?? body.match(/https?:\/\/[^\s<"]+/)?.[0];
      if (href && href !== excludeLink) return href;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`no email received for ${to}`);
}

/** Install a WebAuthn virtual authenticator on the context (Chromium CDP). */
export async function installVirtualAuthenticator(context: BrowserContext, page: Page): Promise<void> {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
}

/** Register + verify + log in a fresh account via the UI. Returns the email. */
export async function registerAndLogin(page: Page, prefix: string): Promise<string> {
  const email = uniqueEmail(prefix);
  await page.goto(`${WEB}/register`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Display name").fill(prefix);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();

  // Verification email → click the link.
  const link = await latestLink(email);
  await page.goto(link);
  await expect(page.getByRole("heading", { name: "Email verified" })).toBeVisible();

  await page.goto(`${WEB}/login`);
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/account/);
  return email;
}

/** Create an organization via the memberships page. */
export async function createOrg(page: Page, name: string, slug: string): Promise<void> {
  await page.goto(`${WEB}/account/memberships`);
  await page.getByRole("button", { name: "Create organization" }).click();
  await page.getByLabel("Organization name").fill(name);
  await page.getByLabel("Slug").fill(slug);
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/orgs/${slug}$`));
}

/** Accept an invitation link in the given (logged-in) context. */
export async function acceptInvitation(page: Page, link: string): Promise<void> {
  await page.goto(link);
  await expect(page.getByRole("heading", { name: /Accept the invitation|Welcome!/ })).toBeVisible();
  const accept = page.getByRole("button", { name: "Accept invitation" });
  if (await accept.isVisible()) {
    await accept.click();
  }
  await expect(page).toHaveURL(/\/orgs\/|Welcome!/);
}

/** API helper: POST JSON with the context's cookies. */
export async function apiPost(
  context: BrowserContext,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: () => Promise<unknown> }> {
  const resp = await context.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "content-type": "application/json" },
  });
  return { status: resp.status(), json: () => resp.json() };
}
