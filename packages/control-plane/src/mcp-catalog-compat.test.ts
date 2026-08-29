import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  MCP_CATALOG_COMPATIBILITY,
  MCP_CATALOG_VERSION,
  MCP_TOOLS,
  mcpCatalogRevision,
} from "./mcp.ts";

type BaselineTool = {
  name: string;
  required: string[];
  properties: Record<string, string>;
  additional_properties: boolean;
  annotations: Record<string, unknown> | null;
};

type CatalogBaseline = {
  schema_version: number;
  catalog_version: number;
  release: string;
  catalog_revision: string;
  tools: BaselineTool[];
};

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

async function baseline(): Promise<CatalogBaseline> {
  const path = new URL("../../../release/mcp-catalog-baseline-v1.json", import.meta.url);
  return JSON.parse(await readFile(path, "utf8")) as CatalogBaseline;
}

async function currentReceipt(): Promise<Pick<CatalogBaseline, "schema_version" | "catalog_version" | "catalog_revision">> {
  const path = new URL("../../../release/mcp-catalog-current.json", import.meta.url);
  return JSON.parse(await readFile(path, "utf8")) as Pick<
    CatalogBaseline,
    "schema_version" | "catalog_version" | "catalog_revision"
  >;
}

/**
 * ChatGPT published plugins invoke a reviewed metadata snapshot until the
 * publisher scans, submits, and publishes a replacement. This gate models a
 * snapshot-A client against server B: every old name stays callable, and its
 * old arguments retain their meaning. Additive optional fields/tools pass;
 * new required fields, removed properties, or changed property semantics do
 * not. A deliberate break requires a new catalog major and baseline, not a
 * test edit that silently blesses the break.
 */
test("current catalog receipt exactly matches the published registry", async () => {
  const current = await currentReceipt();
  assert.equal(current.schema_version, 1);
  assert.equal(current.catalog_version, MCP_CATALOG_VERSION);
  assert.equal(current.catalog_revision, await mcpCatalogRevision());
});

test("published catalog remains callable and schema-compatible with the release baseline", async () => {
  const previous = await baseline();
  assert.equal(previous.schema_version, 1);
  assert.ok(previous.catalog_version >= MCP_CATALOG_COMPATIBILITY.min_version);
  assert.ok(previous.catalog_version <= MCP_CATALOG_COMPATIBILITY.max_version);
  assert.equal(MCP_CATALOG_VERSION, previous.catalog_version);

  const callable = new Map(MCP_TOOLS.map((tool) => [tool.name, tool]));
  for (const old of previous.tools) {
    const current = callable.get(old.name);
    assert.ok(current, `${old.name} was removed from tools/call (snapshot client break)`);
    const currentRequired = new Set(
      Array.isArray(current.inputSchema.required)
        ? current.inputSchema.required.filter((field): field is string => typeof field === "string")
        : [],
    );
    const oldRequired = new Set(old.required);
    for (const field of currentRequired) {
      assert.ok(oldRequired.has(field), `${old.name} added required field ${field}`);
    }
    const currentProperties = current.inputSchema.properties
      && typeof current.inputSchema.properties === "object"
      && !Array.isArray(current.inputSchema.properties)
      ? current.inputSchema.properties as Record<string, unknown>
      : {};
    for (const [field, oldDigest] of Object.entries(old.properties)) {
      assert.ok(field in currentProperties, `${old.name} removed snapshot field ${field}`);
      assert.equal(
        digest(currentProperties[field]),
        oldDigest,
        `${old.name}.${field} changed semantics; add a versioned tool instead`,
      );
    }
    assert.equal(
      current.inputSchema.additionalProperties ?? true,
      old.additional_properties,
      `${old.name} changed additionalProperties semantics`,
    );
    assert.deepEqual(
      current.annotations ?? null,
      old.annotations,
      `${old.name} changed reviewed effect annotations`,
    );
  }
});
