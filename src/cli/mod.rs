/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: CLI command handlers -- grouped by command family.
 * Created: 2026-04-07
 * Last Modified: 2026-04-12
 */

mod cloud;
mod credential_sharing;
mod credentials;
mod log;
mod mcp;
mod partitions;
mod policy;
mod projects;
mod proxy;
mod shared;
mod status;
mod vault;

pub use cloud::{
    handle_cloud_login, handle_cloud_logout, handle_cloud_pull, handle_cloud_push,
    handle_cloud_status, handle_cloud_sync,
};
pub use credential_sharing::{handle_credential_export, handle_credential_import};
pub use credentials::{
    AddCredentialArgs, handle_add, handle_get, handle_import, handle_list, handle_remove,
    handle_rotate,
};
pub use log::handle_log;
pub use mcp::handle_mcp_serve;
pub use partitions::{
    handle_partition_assign, handle_partition_create, handle_partition_delete,
    handle_partition_export, handle_partition_import, handle_partition_list,
};
pub use policy::{handle_policy_check, handle_policy_init, handle_policy_list};
pub use projects::{
    handle_project_create, handle_project_current, handle_project_delete, handle_project_export,
    handle_project_import, handle_project_list, handle_project_use,
};
pub use proxy::{handle_proxy_cleanup, handle_proxy_status, handle_proxy_stop, handle_serve};
pub use shared::set_json_output;
pub use status::handle_status;
pub use vault::{handle_init, handle_unlock};
