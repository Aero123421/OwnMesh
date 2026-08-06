import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Shared fixtures consumed by both Rust and TypeScript tests. */
export const FIXTURES_DIR = path.resolve(here, "../../../spec-bundle/examples/fixtures");

/** JSON Schema documents. */
export const SCHEMAS_DIR = path.resolve(here, "../../../spec-bundle/schemas");
