/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Entry point -- CLI argument parsing and subcommand dispatch.
 * Created: 2026-04-07
 * Last Modified: 2026-04-19
 */

#![deny(clippy::correctness)]
#![warn(clippy::suspicious, clippy::style, clippy::perf, clippy::complexity)]

mod audit;
mod bundle;
mod cli;
mod cloud;
mod core;
mod env_sideload;
mod mcp;
mod migrate;
mod partition;
mod policy;
mod proxy;
mod random;
mod secure_files;
mod sharing;

use std::io::Read;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "wispkey")]
#[command(about = "Credential firewall for AI agents with wisp token proxy")]
#[command(version)]
struct Cli {
    /// Output format for machine consumers such as WispKey Desktop
    #[arg(long = "format", global = true, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault with a master password
    Init,

    /// Unlock the vault for the current session
    Unlock {
        /// Session timeout in minutes (default: 30, 0 = no expiry)
        #[arg(long)]
        timeout: Option<i64>,
    },

    /// Add a credential to the vault
    Add {
        /// Human-readable credential name
        name: String,

        /// Credential type (bearer_token, api_key, basic_auth, custom_header, query_param)
        #[arg(long, default_value = "bearer_token")]
        r#type: String,

        /// Short human-readable description of what this credential is for
        #[arg(long)]
        description: Option<String>,

        /// The secret value to store; exposed in shell history and process listings
        #[arg(long, allow_hyphen_values = true)]
        value: Option<String>,

        /// Read the secret value from a file, or '-' for stdin
        #[arg(long)]
        value_file: Option<String>,

        /// Allowed target hosts (comma-separated, glob patterns)
        #[arg(long)]
        hosts: Option<String>,

        /// Tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,

        /// Custom header name (required for custom_header type)
        #[arg(long)]
        header_name: Option<String>,

        /// Query parameter name (required for query_param type)
        #[arg(long)]
        param_name: Option<String>,

        /// Partition to add to (default: personal)
        #[arg(long)]
        partition: Option<String>,

        /// Project override (default: active project)
        #[arg(long)]
        project: Option<String>,
    },

    /// List all credentials (names only, never values)
    List {
        /// Filter by partition
        #[arg(long)]
        partition: Option<String>,

        /// Filter by project (default: active project)
        #[arg(long)]
        project: Option<String>,

        /// Show credentials across all projects
        #[arg(long)]
        all_projects: bool,
    },

    /// Get details for a credential
    Get {
        /// Credential name
        name: String,

        /// Show the wisp token for this credential
        #[arg(long)]
        show_token: bool,
    },

    /// Remove a credential
    Remove {
        /// Credential name
        name: String,
    },

    /// Regenerate the wisp token for a credential
    Rotate {
        /// Credential name
        name: String,
    },

    /// Run a child process with a credential injected through controlled channels
    Exec {
        /// Credential name
        #[arg(long)]
        credential: String,

        /// Project override (default: active project)
        #[arg(long)]
        project: Option<String>,

        /// Write the secret plus a newline to the child's stdin, then close stdin
        #[arg(long = "stdin")]
        stdin_channel: bool,

        /// Set a child-only environment variable to the secret value
        #[arg(long = "env")]
        env_vars: Vec<String>,

        /// Configure SUDO_ASKPASS, SSH_ASKPASS, and GIT_ASKPASS for the child
        #[arg(long)]
        askpass: bool,

        /// Child command and arguments after --
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Run a child process with manifest-defined child-only environment variables
    Run {
        /// Manifest path (default: wispkey.toml in the current directory)
        #[arg(long)]
        manifest: Option<String>,

        /// Project override (default: active project)
        #[arg(long)]
        project: Option<String>,

        /// Child command and arguments after --
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Render a template with credential references
    Inject {
        /// Template input file, or '-' for stdin
        #[arg(short = 'i', long)]
        input: String,

        /// Rendered output file, written owner-only
        #[arg(short = 'o', long)]
        output: Option<String>,

        /// Project override (default: active project)
        #[arg(long)]
        project: Option<String>,

        /// Write rendered plaintext to stdout instead of an owner-only file
        #[arg(long)]
        stdout: bool,
    },

    /// Internal askpass helper
    #[command(hide = true)]
    Askpass,

    /// Start the wisp token proxy
    Serve {
        /// Port to listen on (ignored when --random-port is set)
        #[arg(long, default_value = "7700")]
        port: u16,

        /// Let the OS pick a random available port (written to proxy.json for discovery)
        #[arg(long)]
        random_port: bool,

        /// Run as a background daemon
        #[arg(long)]
        daemon: bool,

        /// Allow credentials from all projects (default: active project only)
        #[arg(long)]
        all_projects: bool,

        /// Add a listener: tcp://127.0.0.1:7700, unix:/absolute/path.sock, or vsock://<cid>:<port>
        #[arg(long = "listen")]
        listen: Vec<String>,

        /// Require per-request instance identity on all listeners
        #[arg(long, conflicts_with = "no_require_identity")]
        require_identity: bool,

        /// Do not require per-request instance identity on any listener
        #[arg(long, conflicts_with = "require_identity")]
        no_require_identity: bool,
    },

    /// Import credentials from a .env file
    Import {
        /// Path to the .env file
        path: String,

        /// Prefix for imported credential names
        #[arg(long)]
        prefix: Option<String>,

        /// Partition to import into (default: personal)
        #[arg(long)]
        partition: Option<String>,

        /// Project to import into (default: active project)
        #[arg(long)]
        project: Option<String>,
    },

    /// Show vault and proxy status
    Status,

    /// Manage the local WispKey proxy control plane
    Proxy {
        #[command(subcommand)]
        command: ProxyCommands,
    },

    /// Query the audit log
    Log {
        /// Number of recent entries to show
        #[arg(long, default_value = "50")]
        last: usize,

        /// Filter by credential name
        #[arg(long)]
        credential: Option<String>,

        /// Filter entries since this date (YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,
    },

    /// Export or stream audit events for SIEM egress
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },

    /// Manage key partitions
    Partition {
        #[command(subcommand)]
        command: PartitionCommands,
    },

    /// Manage projects (credential isolation by team/project)
    Project {
        #[command(subcommand)]
        command: ProjectCommands,
    },

    /// Share or import a single credential bundle
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },

    /// Manage access policies
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Manage enrolled instance identities and access requests
    Instance {
        #[command(subcommand)]
        command: InstanceCommands,
    },

    /// Cloud sync (WispKey Cloud)
    Cloud {
        #[command(subcommand)]
        command: CloudCommands,
    },

    /// Run as an MCP server
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuditOutputFormat {
    Jsonl,
    Json,
}

impl From<AuditOutputFormat> for cli::AuditExportFormat {
    fn from(value: AuditOutputFormat) -> Self {
        match value {
            AuditOutputFormat::Jsonl => Self::Jsonl,
            AuditOutputFormat::Json => Self::Json,
        }
    }
}

fn read_bootstrap_token_source(
    bootstrap_token: Option<String>,
    token_file: Option<String>,
) -> String {
    match (bootstrap_token, token_file) {
        (Some(_), Some(_)) => {
            eprintln!("Error: cannot use both <bootstrap-token> and --token-file");
            std::process::exit(1);
        }
        (Some(token), None) => {
            eprintln!(
                "Warning: positional bootstrap tokens can expose secrets in shell history and process listings; use --token-file instead."
            );
            token
        }
        (None, Some(path)) => {
            let content = if path == "-" {
                let mut content = String::new();
                match std::io::stdin().read_to_string(&mut content) {
                    Ok(_) => Ok(content),
                    Err(e) => Err(e),
                }
            } else {
                std::fs::read_to_string(&path)
            };
            match content {
                Ok(content) => content.trim().to_string(),
                Err(e) => {
                    eprintln!("Error reading {}: {}", path, e);
                    std::process::exit(1);
                }
            }
        }
        (None, None) => {
            eprintln!("Error: provide <bootstrap-token> or --token-file");
            std::process::exit(1);
        }
    }
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Export all matching audit events
    Export {
        /// Include events at or after this timestamp or date
        #[arg(long)]
        since: Option<String>,
        /// Include events at or before this timestamp or date
        #[arg(long)]
        until: Option<String>,
        /// Filter by credential name
        #[arg(long)]
        credential: Option<String>,
        /// Export encoding
        #[arg(long = "encoding", value_enum, default_value_t = AuditOutputFormat::Jsonl)]
        format: AuditOutputFormat,
        /// Write to a file instead of stdout
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Print newest audit events as JSONL, optionally following for new rows
    Tail {
        /// Continue polling for new events
        #[arg(long)]
        follow: bool,
        /// Filter by credential name
        #[arg(long)]
        credential: Option<String>,
    },
}

#[derive(Subcommand)]
enum PartitionCommands {
    /// Create a new partition
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        /// Project to create partition in (default: active project)
        #[arg(long)]
        project: Option<String>,
    },
    /// List all partitions
    List {
        /// Show partitions across all projects
        #[arg(long)]
        all_projects: bool,
    },
    /// Delete a partition (moves credentials to 'personal')
    Delete { name: String },
    /// Assign a credential to a partition
    Assign {
        /// Credential name
        credential: String,
        /// Target partition name
        #[arg(long)]
        to: String,
    },
    /// Export a partition as an encrypted .wkbundle file
    Export {
        /// Partition name
        name: String,
        /// Output file path
        #[arg(long, short)]
        output: String,
        /// Read the bundle passphrase from a protected file
        #[arg(long)]
        bundle_passphrase_file: Option<String>,
    },
    /// Import credentials from an encrypted .wkbundle file
    Import {
        /// Path to .wkbundle file
        path: String,
        /// Read the bundle passphrase from a protected file
        #[arg(long)]
        bundle_passphrase_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProjectCommands {
    /// Create a new project
    Create {
        name: String,
        /// Project description
        #[arg(long, default_value = "")]
        description: String,
    },
    /// List all projects
    List,
    /// Delete a project (moves partitions to 'default')
    Delete { name: String },
    /// Set the active project for this machine
    Use { name: String },
    /// Show the currently active project
    Current,
    /// Export a whole project as an encrypted .wkbundle file
    Export {
        /// Project name
        name: String,
        /// Output file path
        #[arg(long, short)]
        output: String,
        /// Read the bundle passphrase from a protected file
        #[arg(long)]
        bundle_passphrase_file: Option<String>,
    },
    /// Import a whole project from an encrypted .wkbundle file
    Import {
        /// Path to .wkbundle file
        path: String,
        /// Read the bundle passphrase from a protected file
        #[arg(long)]
        bundle_passphrase_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum CredentialCommands {
    /// Export one credential as an encrypted .wkcred file
    Export {
        /// Credential name
        name: String,
        /// Output file path
        #[arg(long, short)]
        output: String,
        /// Read the bundle passphrase from a protected file
        #[arg(long)]
        bundle_passphrase_file: Option<String>,
    },
    /// Import one credential from an encrypted .wkcred file
    Import {
        /// Path to .wkcred file
        path: String,
        /// Read the bundle passphrase from a protected file
        #[arg(long)]
        bundle_passphrase_file: Option<String>,
        /// Destination project override
        #[arg(long)]
        project: Option<String>,
        /// Destination partition override
        #[arg(long)]
        partition: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// List all policies
    List,
    /// Show the policies file path (create if missing)
    Init,
    /// Validate the policies file
    Check,
}

#[derive(Subcommand)]
enum InstanceCommands {
    /// Enroll a new instance and print its one-time secret
    Enroll {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        partition: Vec<String>,
        #[arg(long)]
        project: Vec<String>,
        #[arg(long)]
        credential: Vec<String>,
        #[arg(long)]
        tag: Vec<String>,
    },
    /// List enrolled instances
    List,
    /// Show full instance details
    Show { name: String },
    /// Add or remove instance scopes
    Scope {
        #[command(subcommand)]
        command: InstanceScopeCommands,
    },
    /// Manage scoped bootstrap tokens for fleet self-enrollment
    Bootstrap {
        #[command(subcommand)]
        command: InstanceBootstrapCommands,
    },
    /// Redeem a bootstrap token and create a new instance identity
    Join {
        /// Plaintext bootstrap token (prefer --token-file)
        bootstrap_token: Option<String>,
        /// Read the bootstrap token from a file, or '-' for stdin
        #[arg(long)]
        token_file: Option<String>,
        /// Instance name to create
        #[arg(long)]
        name: String,
    },
    /// Revoke an instance without deleting audit history
    Revoke { name: String },
    /// List access requests
    Requests {
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        pending: bool,
    },
    /// Approve an access request
    Approve { request_id: String },
    /// Deny an access request
    Deny { request_id: String },
}

#[derive(Subcommand)]
enum InstanceBootstrapCommands {
    /// Create a reusable or TTL-limited bootstrap token
    Create {
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        partition: Vec<String>,
        #[arg(long)]
        project: Vec<String>,
        #[arg(long)]
        credential: Vec<String>,
        #[arg(long)]
        tag: Vec<String>,
        /// Token time to live, for example 30m, 1h, or 7d
        #[arg(long)]
        ttl: Option<String>,
        /// Maximum number of successful joins
        #[arg(long)]
        uses: Option<i64>,
    },
    /// List bootstrap token metadata
    List,
    /// Revoke a bootstrap token
    Revoke { id: String },
}

#[derive(Subcommand)]
enum InstanceScopeCommands {
    /// Add one or more scope selectors
    Add {
        name: String,
        #[arg(long, num_args = 1..)]
        partition: Vec<String>,
        #[arg(long, num_args = 1..)]
        project: Vec<String>,
        #[arg(long, num_args = 1..)]
        credential: Vec<String>,
        #[arg(long, num_args = 1..)]
        tag: Vec<String>,
    },
    /// Remove one or more scope selectors
    Remove {
        name: String,
        #[arg(long, num_args = 1..)]
        partition: Vec<String>,
        #[arg(long, num_args = 1..)]
        project: Vec<String>,
        #[arg(long, num_args = 1..)]
        credential: Vec<String>,
        #[arg(long, num_args = 1..)]
        tag: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CloudCommands {
    /// Show cloud sync status
    Status,
    /// Log in to WispKey Cloud
    Login,
    /// Log out of WispKey Cloud
    Logout,
    /// Push a partition to the cloud
    Push { partition: String },
    /// Pull a partition from the cloud
    Pull { partition: String },
    /// Sync all cloud-enabled partitions
    Sync,
}

#[derive(Subcommand)]
enum ProxyCommands {
    /// Show local proxy lifecycle status
    Status,
    /// Stop the owned local proxy
    Stop,
    /// Remove stale proxy discovery files
    Cleanup,
}

#[derive(Subcommand)]
enum McpCommands {
    /// Start MCP server (stdio transport)
    Serve,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls ring CryptoProvider");

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wispkey=info".parse().expect("static directive must parse")),
        )
        .init();

    if cli::askpass_mode_enabled() {
        cli::handle_askpass().await;
        return;
    }

    let parsed = Cli::parse();
    cli::set_json_output(matches!(parsed.output_format, OutputFormat::Json));

    match parsed.command {
        Commands::Init => {
            cli::handle_init().await;
        }
        Commands::Unlock { timeout } => {
            cli::handle_unlock(timeout).await;
        }
        Commands::Add {
            name,
            r#type,
            description,
            value,
            value_file,
            hosts,
            tags,
            header_name,
            param_name,
            partition,
            project,
        } => {
            let resolved_value = match (&value, &value_file) {
                (Some(_), Some(_)) => {
                    eprintln!("Error: cannot use both --value and --value-file");
                    std::process::exit(1);
                }
                (_, Some(path)) => {
                    let content = if path == "-" {
                        let mut content = String::new();
                        match std::io::stdin().read_to_string(&mut content) {
                            Ok(_) => Ok(content),
                            Err(e) => Err(e),
                        }
                    } else {
                        std::fs::read_to_string(path)
                    };
                    match content {
                        Ok(content) => Some(content),
                        Err(e) => {
                            eprintln!("Error reading {}: {}", path, e);
                            std::process::exit(1);
                        }
                    }
                }
                (Some(v), None) => {
                    eprintln!(
                        "Warning: --value can expose secrets in shell history and process listings; use the hidden prompt or --value-file instead."
                    );
                    Some(v.clone())
                }
                (None, None) => None,
            };
            cli::handle_add(cli::AddCredentialArgs {
                name: &name,
                type_str: &r#type,
                description: description.as_deref(),
                value: resolved_value.as_deref(),
                hosts: hosts.as_deref(),
                tags: tags.as_deref(),
                header_name: header_name.as_deref(),
                param_name: param_name.as_deref(),
                partition: partition.as_deref(),
                project: project.as_deref(),
            })
            .await;
        }
        Commands::List {
            partition,
            project,
            all_projects,
        } => {
            cli::handle_list(partition.as_deref(), project.as_deref(), all_projects).await;
        }
        Commands::Get { name, show_token } => {
            cli::handle_get(&name, show_token).await;
        }
        Commands::Remove { name } => {
            cli::handle_remove(&name).await;
        }
        Commands::Rotate { name } => {
            cli::handle_rotate(&name).await;
        }
        Commands::Exec {
            credential,
            project,
            stdin_channel,
            env_vars,
            askpass,
            command,
        } => {
            cli::handle_exec(cli::ExecArgs {
                credential: &credential,
                project: project.as_deref(),
                stdin: stdin_channel,
                env: &env_vars,
                askpass,
                command: &command,
            })
            .await;
        }
        Commands::Run {
            manifest,
            project,
            command,
        } => {
            cli::handle_run(cli::RunArgs {
                manifest: manifest.as_deref(),
                project: project.as_deref(),
                command: &command,
            })
            .await;
        }
        Commands::Inject {
            input,
            output,
            project,
            stdout,
        } => {
            cli::handle_inject(cli::InjectArgs {
                input: &input,
                output: output.as_deref(),
                project: project.as_deref(),
                stdout,
            })
            .await;
        }
        Commands::Askpass => {
            cli::handle_askpass().await;
        }
        Commands::Serve {
            port,
            random_port,
            daemon,
            all_projects,
            listen,
            require_identity,
            no_require_identity,
        } => {
            let effective_port = if random_port { 0 } else { port };
            cli::handle_serve(
                effective_port,
                daemon,
                all_projects,
                listen,
                require_identity,
                no_require_identity,
            )
            .await;
        }
        Commands::Import {
            path,
            prefix,
            partition,
            project,
        } => {
            cli::handle_import(
                &path,
                prefix.as_deref(),
                partition.as_deref(),
                project.as_deref(),
            )
            .await;
        }
        Commands::Status => {
            cli::handle_status().await;
        }
        Commands::Proxy { command } => match command {
            ProxyCommands::Status => cli::handle_proxy_status().await,
            ProxyCommands::Stop => cli::handle_proxy_stop().await,
            ProxyCommands::Cleanup => cli::handle_proxy_cleanup().await,
        },
        Commands::Log {
            last,
            credential,
            since,
        } => {
            cli::handle_log(last, credential.as_deref(), since.as_deref()).await;
        }
        Commands::Audit { command } => match command {
            AuditCommands::Export {
                since,
                until,
                credential,
                format,
                output,
            } => {
                cli::handle_audit_export(
                    since.as_deref(),
                    until.as_deref(),
                    credential.as_deref(),
                    format.into(),
                    output.as_deref(),
                )
                .await
            }
            AuditCommands::Tail { follow, credential } => {
                cli::handle_audit_tail(follow, credential.as_deref()).await
            }
        },
        Commands::Partition { command } => match command {
            PartitionCommands::Create {
                name,
                description,
                project,
            } => cli::handle_partition_create(&name, &description, project.as_deref()).await,
            PartitionCommands::List { all_projects } => {
                cli::handle_partition_list(all_projects).await
            }
            PartitionCommands::Delete { name } => cli::handle_partition_delete(&name).await,
            PartitionCommands::Assign { credential, to } => {
                cli::handle_partition_assign(&credential, &to).await
            }
            PartitionCommands::Export {
                name,
                output,
                bundle_passphrase_file,
            } => {
                cli::handle_partition_export(&name, &output, bundle_passphrase_file.as_deref())
                    .await
            }
            PartitionCommands::Import {
                path,
                bundle_passphrase_file,
            } => cli::handle_partition_import(&path, bundle_passphrase_file.as_deref()).await,
        },
        Commands::Project { command } => match command {
            ProjectCommands::Create { name, description } => {
                cli::handle_project_create(&name, &description).await
            }
            ProjectCommands::List => cli::handle_project_list().await,
            ProjectCommands::Delete { name } => cli::handle_project_delete(&name).await,
            ProjectCommands::Use { name } => cli::handle_project_use(&name).await,
            ProjectCommands::Current => cli::handle_project_current().await,
            ProjectCommands::Export {
                name,
                output,
                bundle_passphrase_file,
            } => {
                cli::handle_project_export(&name, &output, bundle_passphrase_file.as_deref()).await
            }
            ProjectCommands::Import {
                path,
                bundle_passphrase_file,
            } => cli::handle_project_import(&path, bundle_passphrase_file.as_deref()).await,
        },
        Commands::Credential { command } => match command {
            CredentialCommands::Export {
                name,
                output,
                bundle_passphrase_file,
            } => {
                cli::handle_credential_export(&name, &output, bundle_passphrase_file.as_deref())
                    .await
            }
            CredentialCommands::Import {
                path,
                bundle_passphrase_file,
                project,
                partition,
            } => {
                cli::handle_credential_import(
                    &path,
                    project.as_deref(),
                    partition.as_deref(),
                    bundle_passphrase_file.as_deref(),
                )
                .await
            }
        },
        Commands::Policy { command } => match command {
            PolicyCommands::List => cli::handle_policy_list().await,
            PolicyCommands::Init => cli::handle_policy_init().await,
            PolicyCommands::Check => cli::handle_policy_check().await,
        },
        Commands::Instance { command } => match command {
            InstanceCommands::Enroll {
                name,
                description,
                partition,
                project,
                credential,
                tag,
            } => {
                cli::handle_instance_enroll(
                    &name,
                    &description,
                    &partition,
                    &project,
                    &credential,
                    &tag,
                )
                .await
            }
            InstanceCommands::List => cli::handle_instance_list().await,
            InstanceCommands::Show { name } => cli::handle_instance_show(&name).await,
            InstanceCommands::Scope { command } => match command {
                InstanceScopeCommands::Add {
                    name,
                    partition,
                    project,
                    credential,
                    tag,
                } => {
                    cli::handle_instance_scope_add(&name, &partition, &project, &credential, &tag)
                        .await
                }
                InstanceScopeCommands::Remove {
                    name,
                    partition,
                    project,
                    credential,
                    tag,
                } => {
                    cli::handle_instance_scope_remove(
                        &name,
                        &partition,
                        &project,
                        &credential,
                        &tag,
                    )
                    .await
                }
            },
            InstanceCommands::Bootstrap { command } => match command {
                InstanceBootstrapCommands::Create {
                    description,
                    partition,
                    project,
                    credential,
                    tag,
                    ttl,
                    uses,
                } => {
                    cli::handle_instance_bootstrap_create(
                        &description,
                        &partition,
                        &project,
                        &credential,
                        &tag,
                        ttl.as_deref(),
                        uses,
                    )
                    .await
                }
                InstanceBootstrapCommands::List => cli::handle_instance_bootstrap_list().await,
                InstanceBootstrapCommands::Revoke { id } => {
                    cli::handle_instance_bootstrap_revoke(&id).await
                }
            },
            InstanceCommands::Join {
                bootstrap_token,
                token_file,
                name,
            } => {
                let bootstrap_token = read_bootstrap_token_source(bootstrap_token, token_file);
                cli::handle_instance_join(&bootstrap_token, &name).await
            }
            InstanceCommands::Revoke { name } => cli::handle_instance_revoke(&name).await,
            InstanceCommands::Requests { instance, pending } => {
                cli::handle_instance_requests(instance.as_deref(), pending).await
            }
            InstanceCommands::Approve { request_id } => {
                cli::handle_instance_approve(&request_id).await
            }
            InstanceCommands::Deny { request_id } => cli::handle_instance_deny(&request_id).await,
        },
        Commands::Cloud { command } => match command {
            CloudCommands::Status => cli::handle_cloud_status().await,
            CloudCommands::Login => cli::handle_cloud_login().await,
            CloudCommands::Logout => cli::handle_cloud_logout().await,
            CloudCommands::Push { partition } => cli::handle_cloud_push(&partition).await,
            CloudCommands::Pull { partition } => cli::handle_cloud_pull(&partition).await,
            CloudCommands::Sync => cli::handle_cloud_sync().await,
        },
        Commands::Mcp { command } => match command {
            McpCommands::Serve => {
                cli::handle_mcp_serve().await;
            }
        },
    }
}
