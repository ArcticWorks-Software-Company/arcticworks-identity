import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const srcRoot = fileURLToPath(new URL(".", import.meta.url));

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return [".svelte", ".css"].includes(extname(entry.name)) ? [path] : [];
  });
}

const files = sourceFiles(srcRoot);
const sources = files.map((path) => ({ path, content: readFileSync(path, "utf8") }));
const appCss = readFileSync(join(srcRoot, "app.css"), "utf8");
const confirmDialog = readFileSync(join(srcRoot, "lib", "ui", "ConfirmDialog.svelte"), "utf8");
const dialog = readFileSync(join(srcRoot, "lib", "ui", "Dialog.svelte"), "utf8");

describe("ArcticWorks UI contracts", () => {
  it("keeps component markup token-driven", () => {
    for (const source of sources.filter(({ path }) => path.endsWith(".svelte"))) {
      expect(source.content, source.path).not.toMatch(/\sstyle=/);
    }
  });

  it("uses the component library instead of raw form and table controls", () => {
    for (const source of sources.filter(({ path }) => path.endsWith(".svelte"))) {
      expect(source.content, source.path).not.toMatch(/<(table|select|textarea)\b/);
      expect(source.content, source.path).not.toMatch(/type=["']checkbox["']/);
    }
  });

  it("does not import the package dialog with its unsafe dismissal behavior", () => {
    for (const source of sources.filter(({ path }) => path.endsWith(".svelte"))) {
      expect(source.content, source.path).not.toMatch(/import\s*\{[^}]*\bDialog\b[^}]*\}\s*from\s*["']@arcticworks\/svelte["']/s);
    }
  });

  it("two-way binds parent-owned mutable dialog state", () => {
    for (const source of sources.filter(({ path }) => path.endsWith(".svelte"))) {
      expect(source.content, source.path).not.toMatch(/<Dialog\s+open=\{show[A-Z][A-Za-z]*\}/);
    }
  });

  it("uses the correct typography token without overriding package focus styles", () => {
    expect(appCss).toContain("font-family: var(--aw-font-family-sans)");
    expect(appCss).not.toMatch(/:focus-visible/);
  });

  it("implements the organization shell and narrow-viewport adaptation", () => {
    expect(appCss).toContain(".org-shell");
    expect(appCss).toContain("grid-template-columns: var(--aw-layout-sidebar-width) minmax(0, 1fr)");
    expect(appCss).toMatch(/@media \(max-width: 768px\)[\s\S]*\.org-shell/);
  });

  it("renders destructive confirmations as disabled danger actions while busy", () => {
    expect(confirmDialog).toContain('variant={danger ? "danger" : "primary"}');
    expect(confirmDialog).toContain("disabled={busy}");
    expect(confirmDialog).not.toMatch(/^\s*\{(?:danger|busy)\}\s*$/m);
  });

  it("traps dialog focus and prevents dismissal when dismissal is disabled", () => {
    expect(dialog).toContain('event.key !== "Tab"');
    expect(dialog).toContain('event.key === "Escape"');
    expect(dialog).toContain("if (closeOnScrim)");
    expect(dialog).toMatch(/\{#if closeOnScrim\}[\s\S]*IconButton/);
  });
});
