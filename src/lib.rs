/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Library surface for vault operations and owner IPC.
 * Created: 2026-08-25
 * Last Modified: 2026-08-26
 */

#![deny(clippy::correctness)]
#![warn(clippy::suspicious, clippy::style, clippy::perf, clippy::complexity)]

pub mod audit;
pub mod backup;
pub mod browser_host;
pub mod bundle;
pub mod cli;
pub mod cloud;
pub mod core;
pub mod doctor;
pub mod env_sideload;
pub mod integrate;
pub mod mcp;
pub mod migrate;
pub(crate) mod operations;
pub use operations::helper::run as run_operation_helper;
pub mod owner_ipc;
pub mod partition;
pub mod pki;
pub mod policy;
pub mod proxy;
pub mod random;
pub mod secure_files;
pub mod sharing;
