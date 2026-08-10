import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const pnpmScript = process.env.npm_execpath;
const command = pnpmScript ? process.execPath : process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const prefix = pnpmScript ? [pnpmScript] : [];

function run(args, options = {}) {
  const result = spawnSync(command, [...prefix, "exec", "wrangler", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    windowsHide: true,
    ...options,
  });
  if (result.error) {
    process.stderr.write(`${result.error.message}\n`);
    process.exit(1);
  }
  if (result.status !== 0) {
    if (result.stdout) process.stderr.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exit(result.status || 1);
  }
  return result.stdout || "";
}

const listed = run(["secret", "list", "--format", "json"]);
let existing;
try {
  existing = JSON.parse(listed);
} catch {
  process.stderr.write("Could not read Worker secrets. Deploy the Worker first with `pnpm run deploy`.\n");
  process.exit(1);
}

const names = new Set(existing.map((entry) => entry.name));
const ownerCode = `own_${randomBytes(24).toString("base64url")}`;
const secrets = {
  OWNER_TOKEN_HASH: createHash("sha256").update(ownerCode, "utf8").digest("hex"),
};
if (!names.has("SESSION_SECRET")) {
  secrets.SESSION_SECRET = randomBytes(32).toString("hex");
}

run(["secret", "bulk"], { input: JSON.stringify(secrets), stdio: ["pipe", "inherit", "inherit"] });

const config = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");
const issuer = /"OAUTH_ISSUER"\s*:\s*"([^"]+)"/.exec(config)?.[1] || "https://<your-worker>.workers.dev";
process.stdout.write("\nOwnMesh owner authentication is ready.\n");
process.stdout.write("Save this owner code now; it cannot be recovered from Cloudflare.\n\n");
process.stdout.write(`  ${ownerCode}\n\n`);
process.stdout.write(`Sign in:          ${issuer}/login\n`);
process.stdout.write(`Connect ChatGPT:  ${issuer}/connect/chatgpt\n`);
