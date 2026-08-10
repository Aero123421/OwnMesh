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
const resetPasskey = process.argv.includes("--reset-passkey");
const ownerCode = `own_${randomBytes(24).toString("base64url")}`;
const secrets = {
  OWNER_TOKEN_HASH: createHash("sha256").update(ownerCode, "utf8").digest("hex"),
};
if (!names.has("SESSION_SECRET") || resetPasskey) {
  secrets.SESSION_SECRET = randomBytes(32).toString("hex");
}

run(["secret", "bulk"], { input: JSON.stringify(secrets), stdio: ["pipe", "inherit", "inherit"] });

if (resetPasskey) {
  run([
    "d1",
    "execute",
    "DB",
    "--remote",
    "--command",
    "DELETE FROM owner_auth_challenges; DELETE FROM owner_passkeys WHERE principal_id = 'prin_owner'; DELETE FROM oauth_auth_codes WHERE principal_id = 'prin_owner'; UPDATE oauth_tokens SET revoked = 1 WHERE principal_id = 'prin_owner'; UPDATE principals SET credential_generation = credential_generation + 1 WHERE id = 'prin_owner';",
  ], { stdio: ["ignore", "inherit", "inherit"] });
}

const config = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");
const issuer = /"OAUTH_ISSUER"\s*:\s*"([^"]+)"/.exec(config)?.[1] || "https://<your-worker>.workers.dev";
process.stdout.write("\nOwnMesh owner passkey bootstrap is ready.\n");
process.stdout.write("Open the sign-in URL, enter this code once, and create your passkey.\n\n");
process.stdout.write(`  ${ownerCode}\n\n`);
process.stdout.write(`Create passkey:   ${issuer}/login\n`);
process.stdout.write(`ChatGPT MCP URL:  ${issuer}/mcp\n`);
process.stdout.write("\nAfter registration, daily sign-in uses only the passkey.\n");
process.stdout.write("If every passkey is lost, run `pnpm run owner:init -- --reset-passkey`.\n");
