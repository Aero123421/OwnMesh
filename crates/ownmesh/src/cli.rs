//! Clap command tree for `ownmesh` (specification §16.2).
//!
//! This module is the **final owner** of the CLI registration table. Later tickets
//! implement command bodies without reshaping the tree.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// `OwnMesh` command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh",
    version,
    about = "OwnMesh — capability runtime for user-owned PCs",
    long_about = "OwnMesh CLI. Run without a subcommand in an interactive terminal to launch the bundled OwnMesh TUI."
)]
pub struct Cli {
    /// Emit machine-readable JSON on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// UI / message language tag (e.g. en-US, ja-JP).
    #[arg(long, global = true, env = "OWNMESH_LANG")]
    pub lang: Option<String>,

    /// Subcommand. When omitted in an interactive terminal, launches the bundled TUI.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Top-level commands (specification §16.2).
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Interactive or non-interactive first-run setup wizard.
    Setup(SetupArgs),
    /// Authenticate the human user (browser or device code).
    Login(LoginArgs),
    /// Clear local human credentials.
    Logout,
    /// Show daemon / device status via local IPC.
    Status,
    /// Run local diagnostics (read-only).
    Doctor(DoctorArgs),
    /// Emergency lockdown of the local agent.
    Lockdown,
    /// Lift emergency lockdown (local recovery).
    Unlock(UnlockArgs),
    /// Local / control-plane token controls.
    #[command(subcommand)]
    Tokens(TokensCmd),
    /// Configuration helpers.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Control-plane instance management.
    #[command(subcommand)]
    Instance(InstanceCmd),
    /// Device enrollment and lifecycle.
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Workspace management.
    #[command(subcommand)]
    Workspace(WorkspaceCmd),

    /// Query device log providers (audit, journald, Docker, process; Windows Event Log on Windows).
    #[command(subcommand)]
    Logs(LogsCmd),
    /// Run a structured command on a device.
    Exec(ExecArgs),
    /// Background process control.
    #[command(subcommand)]
    Process(ProcessCmd),
    /// Interactive / detached sessions.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Coding-agent profile operations.
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Approval queue.
    #[command(subcommand)]
    Approval(ApprovalCmd),
    /// Policy inspection and editing.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Peer-to-peer transfer.
    #[command(subcommand)]
    Transfer(TransferCmd),
    /// User-level service lifecycle for ownmeshd.
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Privileged broker lifecycle.
    #[command(subcommand)]
    Privileged(PrivilegedCmd),
    /// Update OwnMesh. With no subcommand, securely updates this machine.
    Update(UpdateArgs),
    /// Internal detached update worker. Not a public CLI surface.
    #[command(name = "__update-worker", hide = true)]
    UpdateWorker(UpdateWorkerArgs),
    /// MCP helpers.
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Shell completion scripts.
    Completion(CompletionArgs),
}

/// `ownmesh setup` arguments.
// These are independent command-line switches, not persistent product state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Parser)]
pub struct SetupArgs {
    /// Control-plane base URL (https://…; http:// loopback only).
    #[arg(long, value_name = "URL")]
    pub control_plane_url: Option<String>,

    /// Local instance alias for the control plane (default: `default`).
    #[arg(long, value_name = "ID")]
    pub instance_id: Option<String>,

    /// Policy preset: workspace_only | recommended | full_user_access | full_access.
    #[arg(long, value_name = "NAME")]
    pub policy_preset: Option<String>,

    /// UI / CLI language tag (e.g. en-US, ja-JP).
    #[arg(long)]
    pub language: Option<String>,

    /// Read setup options from a JSON object (path, or `-` for stdin).
    #[arg(long, value_name = "PATH")]
    pub from_json: Option<String>,

    /// Overwrite an existing config without prompting.
    #[arg(long)]
    pub force: bool,

    /// Never prompt; fail closed when required values are missing (implied when stdin is not a TTY).
    #[arg(long)]
    pub non_interactive: bool,

    /// Sign in after writing the local configuration.
    #[arg(long)]
    pub login: bool,

    /// Use the device-code login flow (for SSH/headless servers; implies --login).
    #[arg(long)]
    pub device_login: bool,

    /// Enroll this machine after login (or using an existing login).
    #[arg(long)]
    pub enroll: bool,

    /// Complete login, device enrollment, and current-user service installation.
    #[arg(long)]
    pub quickstart: bool,
}

/// `ownmesh doctor` arguments.
#[derive(Debug, Clone, Parser)]
pub struct DoctorArgs {
    /// Probe the configured control plane over the network (off by default).
    #[arg(long)]
    pub check_network: bool,

    /// Never touch the network, even with --check-network in a shell alias.
    #[arg(long)]
    pub offline: bool,
}

/// `ownmesh login` arguments.
#[derive(Debug, Clone, Parser)]
pub struct LoginArgs {
    /// Use OAuth device authorization flow instead of browser callback.
    #[arg(long)]
    pub device: bool,
}

/// `ownmesh config` subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Get a config value by key path.
    Get {
        /// Dotted key path (e.g. `lang`).
        key: String,
    },
    /// Set a config value.
    Set {
        /// Dotted key path.
        key: String,
        /// New value.
        value: String,
    },
    /// Open config in $EDITOR.
    Edit,
    /// Validate config and policy files.
    Validate,
}

/// `ownmesh instance` subcommands.
#[derive(Debug, Subcommand)]
pub enum InstanceCmd {
    /// Add a control-plane instance.
    Add {
        /// Local alias.
        id: String,
        /// Base URL.
        base_url: String,
    },
    /// List configured instances.
    List,
    /// Select the active instance.
    Use {
        /// Instance id.
        id: String,
    },
    /// Remove an instance.
    Remove {
        /// Instance id.
        id: String,
    },
}

/// `ownmesh device` subcommands.
#[derive(Debug, Subcommand)]
pub enum DeviceCmd {
    /// Enroll this machine as a device.
    Enroll,
    /// List known devices.
    List,
    /// Show a device.
    Show {
        /// Device id.
        id: String,
    },
    /// Rename a device.
    Rename {
        /// Device id.
        id: String,
        /// New display name.
        name: String,
    },
    /// Manage device labels.
    Labels {
        /// Device id.
        id: String,
        /// Labels to set.
        labels: Vec<String>,
    },
    /// Rotate the local device key.
    RotateKey,
    /// Revoke a device.
    Revoke {
        /// Device id.
        id: String,
    },
}

/// `ownmesh workspace` subcommands.
#[derive(Debug, Subcommand)]
pub enum WorkspaceCmd {
    /// Add a workspace root.
    Add {
        /// Filesystem path (absolute).
        path: String,
        /// Optional workspace id (ws_...); derived from path when omitted.
        #[arg(long)]
        id: Option<String>,
        /// Optional human label.
        #[arg(long)]
        label: Option<String>,
    },
    /// List workspaces.
    List,
    /// Show a workspace.
    Show {
        /// Workspace id.
        id: String,
    },
    /// Update workspace metadata.
    Update {
        /// Workspace id.
        id: String,
        /// Optional new absolute root path.
        #[arg(long)]
        path: Option<String>,
        /// Optional human label (empty clears).
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a workspace.
    Remove {
        /// Workspace id.
        id: String,
    },
}

/// `ownmesh logs` subcommands.
///
/// Reads stay on the device: the daemon queries the platform provider locally
/// over authenticated local IPC and returns a bounded, cursor-paged page.
#[derive(Debug, Clone, Subcommand)]
pub enum LogsCmd {
    /// List log providers available on this device.
    Providers,
    /// Read one bounded page from a log provider.
    Query {
        /// Provider id. All platforms register `audit`, `journald`, `docker`,
        /// and `process`; Windows also registers `windows_event`.
        #[arg(long, default_value = "audit")]
        provider: String,
        /// Resume from a prior page's `next_cursor`.
        #[arg(long)]
        cursor: Option<u64>,
        /// Maximum entries in this page.
        #[arg(long)]
        limit: Option<usize>,
        /// journald unit filter (`--unit`).
        #[arg(long)]
        unit: Option<String>,
        /// Windows Event Log channel (default Application).
        #[arg(long)]
        channel: Option<String>,
        /// Docker/Podman container name or id.
        #[arg(long)]
        container: Option<String>,
    },
}

/// `ownmesh exec` arguments.
#[derive(Debug, Clone, Parser)]
pub struct ExecArgs {
    /// Target device id (optional; default local).
    #[arg(long)]
    pub device: Option<String>,
    /// Working directory.
    #[arg(long)]
    pub cwd: Option<String>,
    /// Idempotency key to suppress duplicate execution.
    #[arg(long)]
    pub idempotency_key: Option<String>,
    /// Invoke via platform shell (`cmd.exe /C` or `sh -c`).
    #[arg(long)]
    pub raw_shell: bool,
    /// Timeout in milliseconds.
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    /// Request the installed privileged broker (Linux only; fail closed elsewhere).
    #[arg(long)]
    pub elevated: bool,
    /// Command and arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// `ownmesh process` subcommands.
#[derive(Debug, Subcommand)]
pub enum ProcessCmd {
    /// Start a long-running process.
    Start {
        /// Command argv.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show process status.
    Status {
        /// Process / operation id.
        id: String,
    },
    /// Fetch process logs.
    Logs {
        /// Process / operation id.
        id: String,
    },
    /// Stop a process.
    Stop {
        /// Process / operation id.
        id: String,
    },
}

/// `ownmesh session` subcommands.
#[derive(Debug, Subcommand)]
pub enum SessionCmd {
    /// Open a new session.
    Open {
        /// Target device.
        device: Option<String>,
        /// Required exact-once key when opening on a remote device.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Remaining argv after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// List sessions.
    List,
    /// Show session details.
    Show {
        /// Session id.
        id: String,
    },
    /// Attach to a session.
    Attach {
        /// Session id.
        id: String,
        /// Observer (read-only) mode.
        #[arg(long)]
        read_only: bool,
    },
    /// Claim controller lease.
    Claim {
        /// Session id.
        id: String,
    },
    /// Release controller lease.
    Release {
        /// Session id.
        id: String,
    },
    /// Give controller to another principal.
    Give {
        /// Session id.
        id: String,
        /// Target principal.
        #[arg(long = "to")]
        to: String,
    },
    /// Close a session gracefully.
    Close {
        /// Session id.
        id: String,
    },
    /// Terminate sessions.
    Terminate {
        /// Session id (omit with --all).
        id: Option<String>,
        /// Terminate all sessions.
        #[arg(long)]
        all: bool,
    },
}

/// `ownmesh profile` subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileCmd {
    /// Scan for installed coding CLIs.
    Scan,
    /// List known profiles.
    List,
    /// Show a profile.
    Show {
        /// Profile id.
        id: String,
    },
    /// Trigger profile-specific login helper.
    Login {
        /// Profile id.
        id: String,
    },
    /// Run profile conformance / smoke test.
    Test {
        /// Profile id.
        id: String,
    },
    /// Start a profile session.
    Start {
        /// Profile id.
        id: String,
    },
    /// Resume a native profile session.
    Resume {
        /// Profile id.
        id: String,
        /// Native session id.
        native_id: String,
    },
}

/// `ownmesh approval` subcommands.
#[derive(Debug, Subcommand)]
pub enum ApprovalCmd {
    /// List pending approvals.
    List,
    /// Show an approval.
    Show {
        /// Approval id.
        id: String,
    },
    /// Approve a request.
    Approve {
        /// Approval id.
        id: String,
        /// Also issue a temporary capability grant, so later matching
        /// operations by the same principal skip the approval prompt.
        ///
        /// The grant is limited to this approval's capability, this principal,
        /// and the approved path and its descendants inside the same workspace.
        /// It is never issued for `command.run` — commands always re-ask.
        #[arg(long)]
        grant: bool,
        /// Temporary grant lifetime in seconds (with `--grant`).
        #[arg(long, requires = "grant", value_parser = clap::value_parser!(i64).range(1..=86_400))]
        grant_seconds: Option<i64>,
        /// Optional exact-once key for scripted retries (generated when omitted).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Deny a request.
    Deny {
        /// Approval id.
        id: String,
        /// Optional exact-once key for scripted retries (generated when omitted).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Watch the approval queue.
    Watch,
}

/// `ownmesh policy` subcommands.
#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Show effective policy.
    Show,
    /// Select a built-in preset.
    Preset {
        /// Preset name.
        name: String,
        /// Whether an exact-bound remote MCP invocation may satisfy ordinary policy Ask.
        #[arg(long)]
        delegate_remote_mcp: Option<bool>,
        /// Optional exact-once key for scripted retries (generated when omitted).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Add or remove one bounded structured rule.
    #[command(subcommand)]
    Rule(PolicyRuleCmd),
    /// Validate policy files.
    Validate,
    /// Explain a decision.
    Explain {
        /// Operation description.
        query: String,
        /// Workspace-relative path targeted by the operation.
        #[arg(long)]
        path: Option<String>,
        /// Workspace in which the path is resolved (default workspace when omitted).
        #[arg(long)]
        workspace_id: Option<String>,
    },
}

/// `ownmesh transfer` subcommands.
#[derive(Debug, Subcommand)]
pub enum TransferCmd {
    /// Create an immutable cross-device transfer plan (paths are workspace-relative).
    Plan {
        /// Source workspace-relative path (no absolute paths, traversal, or backslashes).
        source: String,
        /// Destination workspace-relative path (no overwrite/force mode exists).
        dest: String,
        /// Source enrolled device id.
        #[arg(long)]
        source_device: String,
        /// Destination enrolled device id.
        #[arg(long)]
        destination_device: String,
        /// Source workspace id.
        #[arg(long)]
        source_workspace: String,
        /// Destination workspace id.
        #[arg(long)]
        destination_workspace: String,
        /// Caller-chosen key making this plan safe to retry (1–256 bytes).
        #[arg(long)]
        idempotency_key: String,
        /// Immutable plan lifetime in seconds (60–86400; default 3600).
        #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u32).range(60..=86_400))]
        ttl_seconds: u32,
    },
    /// Start or resume a previously planned transfer.
    Send {
        /// Immutable transfer id returned by `transfer plan`.
        id: String,
        /// Caller-chosen key making this start/resume safe to retry (1–256 bytes).
        #[arg(long)]
        idempotency_key: String,
    },
    /// List metadata-only transfers visible to the signed-in principal.
    List {
        /// Opaque cursor returned by a preceding list response.
        #[arg(long)]
        cursor: Option<String>,
        /// Maximum entries to return (1–500; default 50).
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u16).range(1..=500))]
        limit: u16,
    },
    /// Show transfer status.
    Status {
        /// Transfer id.
        id: String,
    },
    /// Cancel a transfer.
    Cancel {
        /// Transfer id.
        id: String,
        /// Caller-chosen key making cancellation safe to retry (1–256 bytes).
        #[arg(long)]
        idempotency_key: String,
    },
}

/// Structured `ownmesh policy rule` mutations.
#[derive(Debug, Subcommand)]
pub enum PolicyRuleCmd {
    /// Add one user-authored policy rule.
    Add {
        /// Stable rule id (`rule_...`).
        id: String,
        /// allow | ask | deny.
        #[arg(long, value_parser = ["allow", "ask", "deny"])]
        decision: String,
        /// Exact capability, `*`, or a trailing wildcard such as `filesystem.*`.
        #[arg(long)]
        capability: String,
        /// Priority within the same decision class.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i32).range(-1_000..=1_000))]
        priority: i32,
        /// Match elevated/non-elevated operations only.
        #[arg(long)]
        when_elevated: Option<bool>,
        /// Match an exact operation kind.
        #[arg(long)]
        when_kind: Option<String>,
        /// Match an exact path prefix.
        #[arg(long)]
        path_prefix: Option<String>,
        /// Match an exact program value.
        #[arg(long)]
        program_equals: Option<String>,
        /// Short human-readable rule description.
        #[arg(long)]
        description: Option<String>,
        /// Optional exact-once key for scripted retries (generated when omitted).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Remove one user-authored policy rule.
    Remove {
        /// Stable rule id (`rule_...`).
        id: String,
        /// Optional exact-once key for scripted retries (generated when omitted).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

/// `ownmesh unlock` arguments.
#[derive(Debug, Clone, Parser)]
pub struct UnlockArgs {
    /// Optional exact-once key for scripted retries (generated when omitted).
    #[arg(long)]
    pub idempotency_key: Option<String>,
}

/// Shared flags for `ownmesh service` mutating subcommands.
#[derive(Debug, Clone, Parser, Default)]
pub struct ServiceActionArgs {
    /// Print the planned action without changing OS service state.
    #[arg(long)]
    pub dry_run: bool,

    /// Override path to the `ownmeshd` executable (must be a canonical regular file).
    #[arg(long, value_name = "PATH")]
    pub executable: Option<String>,
}

/// `ownmesh service` subcommands.
#[derive(Debug, Subcommand)]
pub enum ServiceCmd {
    /// Install ownmeshd as a current-user autostart service (not admin/root).
    Install(ServiceActionArgs),
    /// Start the user-level ownmeshd service.
    Start(ServiceActionArgs),
    /// Stop the user-level ownmeshd service.
    Stop(ServiceActionArgs),
    /// Restart the user-level ownmeshd service.
    Restart(ServiceActionArgs),
    /// Show user-level service status (read-only).
    Status,
    /// Uninstall the user-level ownmeshd service.
    Uninstall(ServiceActionArgs),
}

/// `ownmesh privileged` subcommands.
#[derive(Debug, Subcommand)]
pub enum PrivilegedCmd {
    /// Install the privileged broker.
    Install,
    /// Show broker status.
    Status,
    /// Uninstall the broker.
    Uninstall,
}

/// `ownmesh update` subcommands.
#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Optional update operation. Omit to download, verify, and install the latest release.
    #[command(subcommand)]
    pub command: Option<UpdateCmd>,
}

/// Arguments passed only to the detached self-update worker.
#[derive(Debug, Clone, Args)]
pub struct UpdateWorkerArgs {
    /// Transaction identifier created by the parent CLI.
    #[arg(long, hide = true)]
    pub transaction_id: String,
}

/// `ownmesh update` subcommands.
#[derive(Debug, Subcommand)]
pub enum UpdateCmd {
    /// Check for updates.
    Check,
    /// Download an update.
    Download,
    /// Download, verify, and apply the latest release (same as `ownmesh update`).
    Apply,
    /// Show the most recent update transaction.
    Status,
    /// Show or set the update channel.
    Channel {
        /// Optional new channel.
        name: Option<String>,
    },
}

/// `ownmesh mcp` subcommands.
#[derive(Debug, Subcommand)]
pub enum McpCmd {
    /// Serve MCP over stdio (local helper).
    Serve {
        /// Use stdio transport.
        #[arg(long)]
        stdio: bool,
    },
}

/// `ownmesh tokens` subcommands.
#[derive(Debug, Subcommand)]
pub enum TokensCmd {
    /// Revoke a server-assigned canonical IPC principal.
    Revoke {
        /// Canonical principal returned by IPC HELLO (not a self-reported client label).
        #[arg(long, value_name = "CANONICAL_PRINCIPAL")]
        principal: String,
        /// Optional exact-once key for scripted retries (generated when omitted).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

/// Shell completion generation.
#[derive(Debug, Clone, Parser)]
pub struct CompletionArgs {
    /// Target shell.
    pub shell: CompletionShell,
}

/// Supported completion shells.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    /// Bash.
    Bash,
    /// Zsh.
    Zsh,
    /// Fish.
    Fish,
    /// `PowerShell`.
    Powershell,
    /// Elvish.
    Elvish,
}
