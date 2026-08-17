/**
 * Regression: the OAuth continuation must survive the Identity login.
 *
 * Starts the Continuity flow with NO Identity session. The API redirects the
 * browser to the Identity login page with an absolute continuation URL
 * (the authorize endpoint); after login the browser must be navigated back
 * through authorize → consent → callback → Continuity, signed in.
 */

import { expect, test } from "@playwright/test";
import { MOCK, WEB } from "./helpers";

test("continuity login works from a cold start", async ({ page }) => {
  // Cold start: this context has no Identity session cookie.
  await page.goto(`${MOCK}/`);
  await expect(page.getByText("You are not signed in")).toBeVisible();

  await page.getByRole("link", { name: "Sign in with ArcticWorks" }).click();
  await expect(page).toHaveURL(/localhost:5174\/login/);
  await page.getByRole("button", { name: "Sign in with ArcticWorks" }).click();

  // The API sends the browser to the Identity login page with the authorize
  // URL as the continuation.
  await expect(page).toHaveURL(/localhost:5173\/login\?continue=http/);
  const continueParam = new URL(page.url()).searchParams.get("continue") ?? "";
  expect(continueParam).toMatch(/^http:\/\/localhost:8080\/oidc\/authorize/);

  await page.getByLabel("Email").fill("admin@arcticworks.dev");
  await page.getByLabel("Password").fill("ChangeMe-1234");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();

  // The full redirect chain runs: authorize → (existing grant) → callback →
  // Continuity home, signed in.
  await expect(page).toHaveURL(`${MOCK}/`, { timeout: 20_000 });
  await expect(page.getByText("Signed in", { exact: true })).toBeVisible();
  await expect(page.getByText("admin@arcticworks.dev")).toBeVisible();
  await expect(page.getByText("continuity.document.read")).toBeVisible();
  await expect(page.getByText("ALLOWED", { exact: true })).toBeVisible();
});
