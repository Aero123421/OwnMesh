import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

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

// #158: a deploy that reports success while the edge still serves an older
// Worker leaves clients on a catalog generation this release no longer
// publishes. Verify the deployed build before telling the operator it is live.
process.stdout.write("Verifying the deployed build...\n");
const expected = await verifyDeployedBuild(issuer);
if (!expected) process.exit(1);

process.stdout.write(`\nLiveness check:    ${issuer}/health\n`);
process.stdout.write(`Readiness check:   ${issuer}/health/ready\n`);
process.stdout.write(`ChatGPT MCP URL:   ${issuer}/mcp\n`);
// The issuer is the one value the next step needs, so hand it over ready to
// paste rather than sending the operator back to the README to assemble it.
process.stdout.write("\nNext, connect a machine to this control plane:\n\n");
process.stdout.write(`  ownmesh setup --control-plane-url ${issuer} --quickstart\n`);
process.stdout.write("\nOn a headless or SSH machine, add --device-login --non-interactive --force.\n");

/**
 * Confirm the origin now serving traffic is the build this deploy published.
 *
 * A Worker rollout is not instantaneous, and a partially applied deploy will
 * happily answer requests from the previous version. Comparing the deployed
 * `SERVICE_VERSION` and MCP catalog revision against this checkout is what
 * turns "wrangler exited 0" into "the release is live" (#158).
 */
async function verifyDeployedBuild(origin) {
  const localVersion = readLocalServiceVersion();
  if (!localVersion) {
    process.stderr.write("Could not read SERVICE_VERSION from src/util.ts.\n");
    return false;
  }
  // #158: version equality alone cannot catch a deploy that changes the tool
  // catalog without moving the release train — which is the common case, since
  // a description or inputSchema edit does not bump SERVICE_VERSION. The
  // catalog revision is the value that actually distinguishes those builds, so
  // it has to be compared, not just printed.
  const localRevision = await readLocalCatalogRevision();
  if (!localRevision) {
    process.stderr.write(
      "Could not compute the local MCP catalog revision; refusing to verify a deploy\n" +
        "against version equality alone (a catalog-only change would pass silently).\n",
    );
    return false;
  }

  let health;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    // Reset per attempt: a later failure must not leave a stale body behind,
    // or the mismatch message below reports a version nobody just observed.
    health = undefined;
    try {
      const response = await fetch(`${origin}/health`, { headers: { accept: "application/json" } });
      if (response.ok) {
        health = await response.json();
        if (health?.version === localVersion && health?.mcp_catalog?.revision === localRevision) {
          break;
        }
      }
    } catch {
      // Propagation and DNS warm-up both look like a transport error here.
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  if (!health) {
    process.stderr.write(`Could not read ${origin}/health after deployment.\n`);
    return false;
  }
  if (health.version !== localVersion) {
    process.stderr.write(
      `Deployed Worker advertises version ${health.version}, but this release is ${localVersion}.\n` +
        "Refusing to report success: clients would keep an older tool catalog.\n",
    );
    return false;
  }
  const deployedRevision = health?.mcp_catalog?.revision;
  if (deployedRevision !== localRevision) {
    process.stderr.write(
      `Deployed MCP catalog revision ${deployedRevision ?? "(absent)"} does not match this ` +
        `release (${localRevision}).\n` +
        "The edge is still serving an older build; clients would keep a stale tool catalog.\n",
    );
    return false;
  }
  process.stdout.write(
    `Deployed ${health.version} (MCP catalog ${deployedRevision}, ` +
      `${health?.mcp_catalog?.tools ?? "?"} tools).\n` +
      "Compare that revision against the client's loaded catalog when tools look stale.\n",
  );
  return true;
}

/**
 * Expected catalog revision for this checkout.
 *
 * Computed in a child Node with type stripping enabled rather than from a
 * generated file, so there is no second copy to fall out of sync with
 * `PUBLISHED_MCP_TOOLS`.
 */
async function readLocalCatalogRevision() {
  const entry = fileURLToPath(new URL("../src/mcp.ts", import.meta.url));
  const child = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--no-warnings",
      "-e",
      `const m = await import(${JSON.stringify(pathToFileURL(entry).href)});` +
        "process.stdout.write(await m.mcpCatalogRevision());",
    ],
    { encoding: "utf8", windowsHide: true },
  );
  if (child.status !== 0) {
    if (child.stderr) process.stderr.write(child.stderr);
    return undefined;
  }
  const revision = (child.stdout || "").trim();
  return /^[0-9a-f]{16}$/.test(revision) ? revision : undefined;
}

/** Read SERVICE_VERSION straight from the source of truth. */
function readLocalServiceVersion() {
  const source = readFileSync(fileURLToPath(new URL("../src/util.ts", import.meta.url)), "utf8");
  return source.match(/export const SERVICE_VERSION\s*=\s*"([^"]+)"/)?.[1];
}
