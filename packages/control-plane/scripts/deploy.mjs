import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const pnpmScript = process.env.npm_execpath;
const command = pnpmScript ? process.execPath : process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const prefix = pnpmScript ? [pnpmScript] : [];

function wrangler(args, { capture = false, combined = false, env = process.env } = {}) {
  const result = spawnSync(command, [...prefix, "exec", "wrangler", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    windowsHide: true,
    env,
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (capture) {
      if (result.stdout) process.stderr.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
    }
    process.exit(result.status || 1);
  }
  return combined
    ? `${result.stdout || ""}${result.stderr || ""}`
    : result.stdout || "";
}

function d1Databases() {
  const raw = wrangler(["d1", "list", "--json"], { capture: true });
  try {
    const value = JSON.parse(raw);
    if (!Array.isArray(value)) throw new Error("not an array");
    return value;
  } catch (error) {
    process.stderr.write(`Could not parse Wrangler D1 output: ${error.message}\n`);
    process.exit(1);
  }
}

process.stdout.write("\nOwnMesh Cloudflare setup\n\n");
const whoami = spawnSync(command, [...prefix, "exec", "wrangler", "whoami"], {
  cwd: process.cwd(),
  encoding: "utf8",
  windowsHide: true,
});
if (whoami.status !== 0) {
  process.stdout.write("Opening Cloudflare sign-in...\n");
  wrangler(["login"]);
}

const matches = d1Databases().filter((database) => database?.name === "ownmesh");
if (matches.length > 1) {
  process.stderr.write("More than one D1 database is named 'ownmesh'. Rename duplicates before deploying.\n");
  process.exit(1);
}
if (matches.length === 0) {
  process.stdout.write("Creating D1 database 'ownmesh'...\n");
  wrangler(["d1", "create", "ownmesh"]);
}

process.stdout.write("Applying database migrations...\n");
wrangler(["d1", "migrations", "apply", "DB", "--remote"]);

process.stdout.write("Deploying Worker and Durable Objects...\n");
const deployOutput = wrangler(["deploy"], { capture: true, combined: true });
process.stdout.write(deployOutput);
const issuer = deployOutput.match(/https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.workers\.dev/i)?.[0];
if (!issuer) {
  process.stderr.write("Deployment succeeded, but its workers.dev URL was not found in Wrangler output.\n");
  process.stderr.write("Run `pnpm run owner:init` after setting OWNMESH_ISSUER to the deployed origin.\n");
  process.exit(1);
}

process.stdout.write("Creating the owner bootstrap and signing secrets...\n");
const ownerInit = spawnSync(process.execPath, [
  fileURLToPath(new URL("./init-owner.mjs", import.meta.url)),
  "--if-missing",
], {
  cwd: process.cwd(),
  encoding: "utf8",
  windowsHide: true,
  env: { ...process.env, OWNMESH_ISSUER: issuer },
  stdio: "inherit",
});
if (ownerInit.error) throw ownerInit.error;
if (ownerInit.status !== 0) process.exit(ownerInit.status || 1);

process.stdout.write(`\nHealth check:      ${issuer}/health\n`);
process.stdout.write(`ChatGPT MCP URL:   ${issuer}/mcp\n`);
// The issuer is the one value the next step needs, so hand it over ready to
// paste rather than sending the operator back to the README to assemble it.
process.stdout.write("\nNext, connect a machine to this control plane:\n\n");
process.stdout.write(`  ownmesh setup --control-plane-url ${issuer} --quickstart\n`);
process.stdout.write("\nOn a headless or SSH machine, add --device-login --non-interactive --force.\n");
