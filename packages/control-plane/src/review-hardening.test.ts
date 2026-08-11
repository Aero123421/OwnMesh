import { strict as assert } from "node:assert";
import test from "node:test";

import { MCP_TOOLS, PUBLISHED_MCP_TOOLS } from "./mcp.ts";
import { AUTH_PAGE_CSP, authPage } from "./auth-ui.ts";
import { ownerPasskeyScript } from "./owner-auth.ts";

// --- MCP catalog: aliases stay callable but are not advertised ------------

test("published tool catalog contains no duplicate aliases", () => {
  const published = PUBLISHED_MCP_TOOLS.map((t) => t.name);
  assert.equal(new Set(published).size, published.length, "published names must be unique");
  for (const tool of PUBLISHED_MCP_TOOLS) {
    assert.equal(tool.aliasOf, undefined, `${tool.name} is an alias and must not be published`);
  }
});

test("every alias points at a published canonical tool and keeps its contract", () => {
  const aliases = MCP_TOOLS.filter((t) => t.aliasOf);
  assert.ok(aliases.length > 0, "expected the historical aliases to still be callable");
  const published = new Map(PUBLISHED_MCP_TOOLS.map((t) => [t.name, t]));

  for (const alias of aliases) {
    const canonical = published.get(alias.aliasOf!);
    assert.ok(canonical, `${alias.name} points at unknown canonical ${alias.aliasOf}`);
    // An alias must not quietly grant more than the tool it stands in for.
    assert.equal(alias.scope, canonical!.scope, `${alias.name} scope drifted from its canonical`);
    assert.equal(alias.risk, canonical!.risk, `${alias.name} risk drifted from its canonical`);
    assert.deepEqual(
      alias.annotations,
      canonical!.annotations,
      `${alias.name} annotations drifted from its canonical`,
    );
  }
});

test("aliases remain resolvable so existing clients keep working", () => {
  const byName = new Map(MCP_TOOLS.map((t) => [t.name, t]));
  for (const legacy of [
    "ownmesh_list_files",
    "ownmesh_read_file",
    "ownmesh_write_file",
    "ownmesh_run_command",
    "ownmesh_run_shell",
    "ownmesh_open_session",
  ]) {
    const tool = byName.get(legacy);
    assert.ok(tool, `${legacy} must stay callable via tools/call`);
    assert.ok(tool!.aliasOf, `${legacy} must be marked as an alias`);
    assert.ok(
      !PUBLISHED_MCP_TOOLS.some((t) => t.name === legacy),
      `${legacy} must be withheld from tools/list`,
    );
  }
});

/**
 * Two published tools may legitimately share a schema when they do different
 * things — `ownmesh_session_close` (graceful close via the controller lease)
 * and `ownmesh_session_terminate` (kill the live process tree) take the same
 * arguments but are not interchangeable. What a model cannot work with is two
 * entries whose schema *and* description are the same; that was the alias
 * problem. So the guard is: identical contract implies distinguishable prose.
 */
test("published tools that share a contract are still distinguishable by description", () => {
  const byFingerprint = new Map<string, (typeof PUBLISHED_MCP_TOOLS)[number][]>();
  for (const tool of PUBLISHED_MCP_TOOLS) {
    const fingerprint = JSON.stringify({
      inputSchema: tool.inputSchema,
      annotations: tool.annotations,
      scope: tool.scope,
      risk: tool.risk,
    });
    byFingerprint.set(fingerprint, [...(byFingerprint.get(fingerprint) ?? []), tool]);
  }

  const normalize = (text: string) => text.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  for (const group of byFingerprint.values()) {
    if (group.length < 2) continue;
    const descriptions = group.map((t) => normalize(t.description));
    assert.equal(
      new Set(descriptions).size,
      group.length,
      `${group.map((t) => t.name).join(" and ")} share a contract and a description; ` +
        "mark one as aliasOf the other, or say what makes them different",
    );
  }
});

// --- Auth page contrast ---------------------------------------------------

/** WCAG 2.1 relative luminance. */
function luminance(hex: string): number {
  const value = hex.replace("#", "");
  const channels = [0, 2, 4].map((i) => {
    const c = Number.parseInt(value.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0]! + 0.7152 * channels[1]! + 0.0722 * channels[2]!;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

function token(css: string, name: string): string {
  const match = css.match(new RegExp(`--${name}:(#[0-9a-fA-F]{6})`));
  assert.ok(match, `token --${name} not found`);
  return match![1]!;
}

test("auth page body text meets WCAG AA on every panel surface", () => {
  const page = authPage({
    title: "t",
    eyebrow: "e",
    heading: "h",
    intro: "i",
    body: "<p>b</p>",
  });
  // --dim carries 11-14px labels, so it needs the 4.5:1 normal-text floor, not
  // the 3:1 large-text one.
  for (const surface of ["bg", "panel", "panel-2"]) {
    const ratio = contrast(token(page, "dim"), token(page, surface));
    assert.ok(
      ratio >= 4.5,
      `--dim on --${surface} is ${ratio.toFixed(2)}:1, below the WCAG AA 4.5:1 floor`,
    );
    const mutedRatio = contrast(token(page, "muted"), token(page, surface));
    assert.ok(mutedRatio >= 4.5, `--muted on --${surface} is ${mutedRatio.toFixed(2)}:1`);
  }
});

test("auth page escapes caller-supplied text and keeps its strict CSP", () => {
  const page = authPage({
    title: '"><script>alert(1)</script>',
    eyebrow: "e",
    heading: "h",
    intro: "i",
    body: "<p>trusted</p>",
  });
  assert.ok(!page.includes("<script>alert(1)</script>"), "title must be escaped");
  assert.ok(AUTH_PAGE_CSP.includes("default-src 'none'"));
  assert.ok(AUTH_PAGE_CSP.includes("frame-ancestors 'none'"));
});

// --- Passkey failure messages --------------------------------------------

test("passkey script distinguishes cancellation and named server errors", async () => {
  const script = await ownerPasskeyScript().text();

  // A dismissed authenticator prompt is not a failure.
  assert.ok(script.includes("NotAllowedError"), "must recognise a dismissed prompt");
  assert.ok(script.includes("AbortError"));
  assert.ok(
    script.includes("Passkey prompt dismissed"),
    "cancellation must not be reported as verification failure",
  );

  // The most common real mistake during first-run: a mistyped owner code.
  assert.ok(
    script.includes("bootstrap_denied"),
    "an unaccepted owner code must be named specifically",
  );
  assert.ok(script.includes("owner_already_registered"));

  // The catch-all still exists for unknown codes.
  assert.ok(script.includes("Passkey verification failed"));
});
