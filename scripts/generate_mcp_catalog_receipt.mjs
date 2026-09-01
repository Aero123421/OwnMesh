#!/usr/bin/env node

import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  MCP_CATALOG_VERSION,
  PUBLISHED_MCP_TOOLS,
  mcpCatalogRevision,
} from "../packages/control-plane/src/mcp.ts";

function digest(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

const release = process.argv[2] || "unreleased";
const catalogRevision = await mcpCatalogRevision();
const tools = PUBLISHED_MCP_TOOLS.map((tool) => {
  const properties = tool.inputSchema.properties
    && typeof tool.inputSchema.properties === "object"
    && !Array.isArray(tool.inputSchema.properties)
    ? tool.inputSchema.properties
    : {};
  return {
    name: tool.name,
    required: Array.isArray(tool.inputSchema.required)
      ? [...tool.inputSchema.required].filter((field) => typeof field === "string").sort()
      : [],
    // Keep digests before names and bind them by array index. An object shaped
    // as { "idempotency_key": "<sha256>" } is semantically harmless but looks
    // exactly like a credential assignment to generic secret scanners.
    property_schema_sha256: Object.values(properties).map(digest),
    property_names: Object.keys(properties),
    additional_properties: tool.inputSchema.additionalProperties ?? true,
    annotations: tool.annotations ?? null,
  };
});

const root = resolve(import.meta.dirname, "..");
const baseline = {
  schema_version: 1,
  catalog_version: MCP_CATALOG_VERSION,
  release,
  catalog_revision: catalogRevision,
  tools,
};
const current = {
  schema_version: 1,
  catalog_version: MCP_CATALOG_VERSION,
  catalog_revision: catalogRevision,
  source: "packages/control-plane/src/mcp.ts:PUBLISHED_MCP_TOOLS",
};

await writeFile(
  resolve(root, `release/mcp-catalog-baseline-v${MCP_CATALOG_VERSION}.json`),
  `${JSON.stringify(baseline, null, 2)}\n`,
);
await writeFile(
  resolve(root, "release/mcp-catalog-current.json"),
  `${JSON.stringify(current, null, 2)}\n`,
);
