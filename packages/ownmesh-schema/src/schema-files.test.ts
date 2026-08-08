import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { SCHEMAS_DIR } from "./paths.ts";

const REQUIRED_SCHEMAS = [
  "domain-ids.schema.json",
  "domain-entities.schema.json",
  "common-types.schema.json",
  "errors.schema.json",
  "protocol-envelope.schema.json",
  "operation-envelope.schema.json",
];

describe("JSON Schema corpus", () => {
  for (const name of REQUIRED_SCHEMAS) {
    it(`parses ${name}`, () => {
      const raw = fs.readFileSync(path.join(SCHEMAS_DIR, name), "utf8");
      const json = JSON.parse(raw) as { $id?: string; $schema?: string };
      assert.ok(json.$schema?.includes("json-schema.org"));
      assert.ok(json.$id?.includes("ownmesh.dev/schemas/"));
    });
  }
});
