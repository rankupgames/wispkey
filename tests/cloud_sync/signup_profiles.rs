//! Uses the existing synthetic authenticated HTTP transport fixture. No live relay.
use super::*;
const EMAIL: &str = "synthetic-sync-profile@example.test";
fn create_profile(path: &Path) -> Value {
    let input = path.join("synthetic-identity.json");
    std::fs::write(
        &input,
        json!({"email":EMAIL,"username":"synthetic-handle"}).to_string(),
    )
    .unwrap();
    run_wispkey_json(
        path,
        &[
            "--format",
            "json",
            "signup-profile",
            "create",
            "work",
            "--project",
            "default",
            "--partition",
            "personal",
            "--identity-file",
            input.to_str().unwrap(),
        ],
    )["profile"]
        .clone()
}
fn inventory(path: &Path) -> Value {
    run_wispkey_json(
        path,
        &[
            "--format",
            "json",
            "signup-profile",
            "list",
            "--project",
            "default",
            "--partition",
            "personal",
        ],
    )
}
#[test]
fn signup_profile_only_sync_preserves_edits_deletion_conflicts_and_account_isolation() {
    let server = Server::new();
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let conflict = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    for dir in [&source, &destination, &conflict, &other] {
        init_vault(dir.path());
        server.configure(dir.path());
    }
    server.configure_account(other.path(), "second-account", SECOND_SESSION);
    let profile = create_profile(source.path());
    let local = create_profile(conflict.path());
    let other_profile = create_profile(other.path());
    assert_eq!(
        transfer(source.path(), "push")["partitions"][0]["outcome"],
        "uploaded"
    );
    assert_eq!(
        transfer(destination.path(), "pull")["partitions"][0]["outcome"],
        "downloaded"
    );
    assert_eq!(inventory(source.path()), inventory(destination.path()));
    // The first pull must not silently erase a profile-only local partition.
    let refused = run_wispkey_bundle(conflict.path(), &["--format", "json", "cloud", "pull"]);
    assert!(!refused.status.success());
    assert_eq!(inventory(conflict.path())["profiles"][0], local);
    assert_eq!(
        transfer(other.path(), "push")["partitions"][0]["outcome"],
        "uploaded"
    );
    assert_eq!(server.state.lock().unwrap().records.len(), 2);
    assert_eq!(inventory(other.path())["profiles"][0], other_profile);
    let input = source.path().join("edited.json");
    std::fs::write(
        &input,
        json!({"email":"edited-sync@example.test","username":null}).to_string(),
    )
    .unwrap();
    let edited = run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "signup-profile",
            "update",
            profile["id"].as_str().unwrap(),
            "--revision",
            profile["revision"].as_str().unwrap(),
            "--project",
            "default",
            "--partition",
            "personal",
            "--identity-file",
            input.to_str().unwrap(),
        ],
    )["profile"]
        .clone();
    transfer(source.path(), "push");
    transfer(destination.path(), "pull");
    assert_eq!(inventory(destination.path())["profiles"][0], edited);
    run_wispkey_json(
        source.path(),
        &[
            "--format",
            "json",
            "signup-profile",
            "remove",
            edited["id"].as_str().unwrap(),
            "--revision",
            edited["revision"].as_str().unwrap(),
            "--project",
            "default",
            "--partition",
            "personal",
        ],
    );
    transfer(source.path(), "push");
    transfer(destination.path(), "pull");
    assert!(
        inventory(destination.path())["profiles"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(inventory(other.path())["profiles"][0], other_profile);
    for record in server.state.lock().unwrap().records.values() {
        for canary in [EMAIL, "synthetic-handle", "edited-sync@example.test"] {
            assert!(
                !record
                    .bytes
                    .windows(canary.len())
                    .any(|part| part == canary.as_bytes())
            );
            assert!(!record.metadata.to_string().contains(canary));
        }
    }
}
