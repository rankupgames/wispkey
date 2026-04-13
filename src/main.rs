/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Entry point -- CLI argument parsing and subcommand dispatch.
 * Created: 2026-04-07
 * Last Modified: 2026-04-08
 */

mod audit;
mod cli;
mod cloud;
mod core;
mod mcp;
mod migrate;
mod partition;
mod proxy;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "wispkey")]
#[command(about = "AI credential vault with wisp token proxy")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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

        /// The secret value to store (omit to enter securely via hidden prompt)
        #[arg(long, allow_hyphen_values = true)]
        value: Option<String>,

        /// Read the secret value from a file (useful for SSH keys and multiline secrets)
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
    },

    /// List all credentials (names only, never values)
    List {
        /// Filter by partition
        #[arg(long)]
        partition: Option<String>,
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

    /// Start the wisp token proxy
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "7700")]
        port: u16,

        /// Run as a background daemon
        #[arg(long)]
        daemon: bool,
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
    },

    /// Show vault and proxy status
    Status,

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

    /// Manage key partitions
    Partition {
        #[command(subcommand)]
        command: PartitionCommands,
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

#[derive(Subcommand)]
enum PartitionCommands {
    /// Create a new partition
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// List all partitions
    List,
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
    },
    /// Import credentials from an encrypted .wkbundle file
    Import {
        /// Path to .wkbundle file
        path: String,
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
enum McpCommands {
    /// Start MCP server (stdio transport)
    Serve,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wispkey=info".parse().unwrap()),
        )
        .init();

    let parsed = Cli::parse();

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
            value,
            value_file,
            hosts,
            tags,
            header_name,
            param_name,
            partition,
        } => {
            let resolved_value = match (&value, &value_file) {
                (Some(_), Some(_)) => {
                    eprintln!("Error: cannot use both --value and --value-file");
                    std::process::exit(1);
                }
                (_, Some(path)) => match std::fs::read_to_string(path) {
                    Ok(content) => Some(content),
                    Err(e) => {
                        eprintln!("Error reading {}: {}", path, e);
                        std::process::exit(1);
                    }
                },
                (v, None) => v.clone(),
            };
            cli::handle_add(
                &name,
                &r#type,
                resolved_value.as_deref(),
                hosts.as_deref(),
                tags.as_deref(),
                header_name.as_deref(),
                param_name.as_deref(),
                partition.as_deref(),
            )
            .await;
        }
        Commands::List { partition } => {
            cli::handle_list(partition.as_deref()).await;
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
        Commands::Serve { port, daemon } => {
            cli::handle_serve(port, daemon).await;
        }
        Commands::Import {
            path,
            prefix,
            partition,
        } => {
            cli::handle_import(&path, prefix.as_deref(), partition.as_deref()).await;
        }
        Commands::Status => {
            cli::handle_status().await;
        }
        Commands::Log {
            last,
            credential,
            since,
        } => {
            cli::handle_log(last, credential.as_deref(), since.as_deref()).await;
        }
        Commands::Partition { command } => match command {
            PartitionCommands::Create { name, description } => {
                cli::handle_partition_create(&name, &description).await
            }
            PartitionCommands::List => cli::handle_partition_list().await,
            PartitionCommands::Delete { name } => cli::handle_partition_delete(&name).await,
            PartitionCommands::Assign { credential, to } => {
                cli::handle_partition_assign(&credential, &to).await
            }
            PartitionCommands::Export { name, output } => {
                cli::handle_partition_export(&name, &output).await
            }
            PartitionCommands::Import { path } => cli::handle_partition_import(&path).await,
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
