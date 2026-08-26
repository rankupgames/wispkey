/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: CLI handlers for encrypted vault backup, inspect, verify, and restore.
 * Created: 2026-08-26
 * Last Modified: 2026-08-26
 */

use std::path::PathBuf;

use crate::audit;
use crate::backup::{self, BackupScope, ConflictPolicy, RestoreOptions};
use crate::core::Vault;

use super::shared::{
    json_output, print_json, prompt_export_bundle_passphrase, prompt_import_bundle_passphrase,
};

pub fn parse_exclude_list(raw: Option<&str>) -> BackupScope {
    let mut scope = BackupScope::all_included();
    if let Some(raw) = raw {
        let names: Vec<String> = raw
            .split(',')
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect();
        if let Err(error) = scope.exclude_names(&names) {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
    scope
}

pub async fn handle_backup_create(
    output: &str,
    exclude: Option<&str>,
    passphrase_file: Option<&str>,
) {
    let vault = match Vault::open_with_session() {
        Ok(vault) => vault,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };
    let passphrase = prompt_export_bundle_passphrase(passphrase_file);
    let scope = parse_exclude_list(exclude);
    match backup::create_backup(&vault, &Vault::vault_dir(), &passphrase, output, &scope) {
        Ok(summary) => {
            audit::log_event(
                vault.db(),
                "VaultBackupCreated",
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "output": summary.output,
                    "format_version": summary.format_version,
                    "source_schema_version": summary.source_schema_version,
                    "scope": summary.scope,
                    "counts": summary.counts,
                    "warnings": summary.warnings,
                }));
                return;
            }
            println!("Wrote encrypted vault backup to {output}");
            println!(
                "Included {} credential(s), {} project(s), {} audit event(s), {} instance(s).",
                summary.counts.credentials,
                summary.counts.projects,
                summary.counts.audits,
                summary.counts.instances
            );
            for warning in summary.warnings {
                println!("Note: {warning}");
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}

pub async fn handle_backup_inspect(path: &str, passphrase_file: Option<&str>) {
    let passphrase = prompt_import_bundle_passphrase(passphrase_file);
    match backup::inspect_backup(path, &passphrase) {
        Ok(inspect) => {
            if json_output() {
                print_json(serde_json::to_value(&inspect).expect("inspect serializes"));
                return;
            }
            println!("Vault backup {}", path);
            println!("Format version: {}", inspect.format_version);
            println!("Source schema: {}", inspect.source_schema_version);
            println!("Exported at: {}", inspect.exported_at);
            println!(
                "Compatible with this WispKey: {}",
                if inspect.compatible { "yes" } else { "no" }
            );
            println!(
                "Counts: {} project(s), {} partition(s), {} credential(s), {} audit(s), {} instance(s), {} bootstrap token(s)",
                inspect.counts.projects,
                inspect.counts.partitions,
                inspect.counts.credentials,
                inspect.counts.audits,
                inspect.counts.instances,
                inspect.counts.bootstrap
            );
            if !inspect.projects.is_empty() {
                println!("Projects: {}", inspect.projects.join(", "));
            }
            if inspect.sidecars.policies {
                println!("Sidecar: policies.toml");
            }
            if inspect.sidecars.cloud {
                println!(
                    "Sidecar: cloud.json (session token present: {})",
                    inspect.sidecars.cloud_session_token_present
                );
            }
            if let Some(active) = inspect.sidecars.active_project {
                println!("Active project: {active}");
            }
            for warning in inspect.warnings {
                println!("Note: {warning}");
            }
            println!("Recovery limits:");
            for limit in inspect.recovery_limits {
                println!("- {limit}");
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}

pub async fn handle_backup_verify(path: &str, passphrase_file: Option<&str>) {
    let passphrase = prompt_import_bundle_passphrase(passphrase_file);
    match backup::verify_backup(path, &passphrase) {
        Ok(verify) => {
            if json_output() {
                print_json(serde_json::json!({
                    "ok": verify.ok,
                    "format_version": verify.format_version,
                    "source_schema_version": verify.source_schema_version,
                    "integrity_ok": verify.integrity_ok,
                    "compatible": verify.compatible,
                    "counts": verify.counts,
                    "warnings": verify.warnings,
                    "errors": verify.errors,
                }));
                if !verify.ok {
                    std::process::exit(1);
                }
                return;
            }
            if verify.ok {
                println!("Backup verified.");
                println!(
                    "Schema {} format {} integrity ok.",
                    verify.source_schema_version, verify.format_version
                );
            } else {
                eprintln!("Backup verification failed.");
                for error in verify.errors {
                    eprintln!("- {error}");
                }
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}

pub async fn handle_backup_restore(
    path: &str,
    dry_run: bool,
    target: Option<&str>,
    replace: bool,
    on_conflict: &str,
    passphrase_file: Option<&str>,
) {
    let passphrase = prompt_import_bundle_passphrase(passphrase_file);
    let policy = match on_conflict {
        "fail" => ConflictPolicy::Fail,
        "skip" => ConflictPolicy::Skip,
        other => {
            eprintln!("Error: unknown --on-conflict value '{other}' (use fail or skip)");
            std::process::exit(1);
        }
    };
    let target_dir = target.map(PathBuf::from).unwrap_or_else(Vault::vault_dir);
    match backup::restore_backup(
        path,
        &passphrase,
        RestoreOptions {
            target_dir: &target_dir,
            dry_run,
            replace,
            on_conflict: policy,
        },
    ) {
        Ok(report) => {
            if !dry_run {
                log_restore_event(&target_dir);
            }
            if json_output() {
                print_json(serde_json::to_value(&report).expect("restore report serializes"));
                return;
            }
            let action = if report.dry_run {
                "Dry run"
            } else {
                "Restored"
            };
            println!("{action} ({}) into {}", report.mode, report.target);
            println!(
                "Imported {} credential(s), {} project(s), {} audit event(s), {} instance(s).",
                report.imported.credentials,
                report.imported.projects,
                report.imported.audits,
                report.imported.instances
            );
            if report.skipped.credentials + report.skipped.projects > 0 {
                println!(
                    "Skipped {} credential(s) and {} project(s) that already matched or conflicted.",
                    report.skipped.credentials, report.skipped.projects
                );
            }
            if !report.conflicts.is_empty() {
                println!("{} conflict(s):", report.conflicts.len());
                for conflict in &report.conflicts {
                    println!(
                        "- {} {}: {}",
                        conflict.entity, conflict.identity, conflict.reason
                    );
                }
            }
            if !report.instances_needing_reenrollment.is_empty() {
                println!(
                    "Instances marked for re-enrollment: {}",
                    report.instances_needing_reenrollment.join(", ")
                );
                println!("Mint a new secret with: wispkey instance rotate-secret <name>");
            }
            if report.bootstrap_tokens_revoked > 0 {
                println!(
                    "{} bootstrap token(s) revoked; mint new tokens before fleet joins.",
                    report.bootstrap_tokens_revoked
                );
            }
            for warning in report.warnings {
                println!("Note: {warning}");
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}

fn log_restore_event(target_dir: &std::path::Path) {
    if let Ok(db) = rusqlite::Connection::open(target_dir.join("vault.db")) {
        audit::log_event(
            &db,
            "VaultBackupRestored",
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
        );
    }
}
