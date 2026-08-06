//! Clap command tree for `ownmesh` (specification §16.2).
//!
//! This module is the **final owner** of the CLI registration table. Later tickets
//! implement command bodies without reshaping the tree.

use clap::{Parser, Subcommand, ValueEnum};

/// `OwnMesh` command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh",
    version,
    about = "OwnMesh — capability runtime for user-owned PCs",
    long_about = "OwnMesh CLI. The rich TUI is the separate `ownmesh-tui` binary; running without a subcommand is unsupported."
)]
pub struct Cli {
    /// Emit machine-readable JSON on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// UI / message language tag (e.g. en-US, ja-JP).
    #[arg(long, global = true, env = "OWNMESH_LANG")]
    pub lang: Option<String>,

    /// Subcommand. When omitted, ownmesh exits with an error; launch `ownmesh-tui` separately for the TUI.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Top-level commands (specification §16.2).
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Interactive first-run setup wizard (stub).
    Setup,
    /// Authenticate the human user (browser or device code).
    Login(LoginArgs),
    /// Clear local human credentials.
    Logout,
    /// Show daemon / device status via local IPC.
    Status,
    /// Run local diagnostics.
    Doctor,
    /// Emergency lockdown of the local agent.
    Lockdown,
    /// Lift emergency lockdown (local recovery).
    Unlock,
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
    /// Update checks and application.
    #[command(subcommand)]
    Update(UpdateCmd),
    /// MCP helpers.
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Shell completion scripts.
    Completion(CompletionArgs),
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
        /// Filesystem path.
        path: String,
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
    },
    /// Remove a workspace.
    Remove {
        /// Workspace id.
        id: String,
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
        /// Also issue a temporary capability grant.
        #[arg(long)]
        grant: bool,
        /// Temporary grant lifetime in seconds (with `--grant`).
        #[arg(long, default_value_t = 3600)]
        grant_seconds: i64,
    },
    /// Deny a request.
    Deny {
        /// Approval id.
        id: String,
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
    },
    /// Mutate a rule (stub).
    Rule {
        /// Rule expression / id.
        spec: String,
    },
    /// Validate policy files.
    Validate,
    /// Explain a decision.
    Explain {
        /// Operation description.
        query: String,
    },
}

/// `ownmesh transfer` subcommands.
#[derive(Debug, Subcommand)]
pub enum TransferCmd {
    /// Plan a transfer.
    Plan {
        /// Source path.
        source: String,
        /// Destination spec.
        dest: String,
    },
    /// Send a transfer.
    Send {
        /// Source path.
        source: String,
        /// Destination spec.
        dest: String,
    },
    /// List transfers.
    List,
    /// Show transfer status.
    Status {
        /// Transfer id.
        id: String,
    },
    /// Cancel a transfer.
    Cancel {
        /// Transfer id.
        id: String,
    },
}

/// `ownmesh service` subcommands.
#[derive(Debug, Subcommand)]
pub enum ServiceCmd {
    /// Install ownmeshd as a user service.
    Install,
    /// Start the service.
    Start,
    /// Stop the service.
    Stop,
    /// Restart the service.
    Restart,
    /// Show service status.
    Status,
    /// Uninstall the service.
    Uninstall,
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
#[derive(Debug, Subcommand)]
pub enum UpdateCmd {
    /// Check for updates.
    Check,
    /// Download an update.
    Download,
    /// Apply a downloaded update.
    Apply,
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
    /// Revoke tokens for a client label (e.g. chatgpt).
    Revoke {
        /// Client label to revoke.
        #[arg(long)]
        client: String,
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
