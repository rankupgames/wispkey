use super::tokens::{
    candidate_prefix_lengths_with_sideload_tokens, check_host_restriction, inject_credential,
};
use super::*;
use crate::core::CredentialType;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

#[test]
fn listen_spec_parses_supported_transports() {
    let tcp = transport::ListenSpec::parse("tcp://127.0.0.1:7700").unwrap();
    assert!(matches!(tcp, transport::ListenSpec::Tcp(_)));

    #[cfg(unix)]
    {
        let unix = transport::ListenSpec::parse("unix:/tmp/wispkey.sock").unwrap();
        assert!(matches!(unix, transport::ListenSpec::Unix(_)));
    }

    let vsock = transport::ListenSpec::parse("vsock://3:7700").unwrap();
    assert!(matches!(
        vsock,
        transport::ListenSpec::Vsock { cid: 3, port: 7700 }
    ));

    #[cfg(unix)]
    {
        let firecracker =
            transport::ListenSpec::parse("firecracker-vsock:/run/firecracker/worker.vsock:7700")
                .unwrap();
        assert!(matches!(
            firecracker,
            transport::ListenSpec::FirecrackerVsock { port: 7700, .. }
        ));
    }
}

#[test]
fn listener_identity_defaults_are_transport_specific() {
    let tcp = transport::ListenConfig::new(
        transport::ListenSpec::parse("tcp://127.0.0.1:7700").unwrap(),
        transport::IdentityRequirement::Default,
    );
    assert!(!tcp.require_identity);

    #[cfg(unix)]
    {
        let unix = transport::ListenConfig::new(
            transport::ListenSpec::parse("unix:/tmp/wispkey.sock").unwrap(),
            transport::IdentityRequirement::Default,
        );
        assert!(unix.require_identity);
    }
}

#[test]
fn non_loopback_tcp_requires_identity_by_default() {
    let tcp = transport::ListenConfig::new(
        transport::ListenSpec::parse("tcp://0.0.0.0:7700").unwrap(),
        transport::IdentityRequirement::Default,
    );

    assert!(tcp.require_identity);
    assert!(tcp.spec.is_non_loopback_tcp());
}

#[test]
#[cfg(unix)]
fn firecracker_vsock_uses_the_guest_destination_port_suffix() {
    assert_eq!(
        transport::firecracker_guest_socket_path(
            std::path::Path::new("/run/firecracker/worker.vsock"),
            7700,
        ),
        std::path::PathBuf::from("/run/firecracker/worker.vsock_7700")
    );
}

#[test]
fn inject_bearer_replaces_token() {
    let result = inject_credential(
        &CredentialType::BearerToken,
        "real-secret",
        "Bearer wk_test_abc123",
        "wk_test_abc123",
    );
    assert_eq!(result, "Bearer real-secret");
}

#[test]
fn inject_api_key_replaces_token() {
    let result = inject_credential(
        &CredentialType::ApiKey,
        "real-key",
        "wk_api_xyz",
        "wk_api_xyz",
    );
    assert_eq!(result, "real-key");
}

#[test]
fn inject_basic_auth_base64_encodes() {
    let result = inject_credential(
        &CredentialType::BasicAuth,
        "user:pass",
        "wk_basic_abc",
        "wk_basic_abc",
    );
    let expected = format!("Basic {}", BASE64.encode("user:pass".as_bytes()));
    assert_eq!(result, expected);
}

#[test]
fn inject_custom_header_replaces() {
    let cred_type = CredentialType::CustomHeader {
        header_name: "X-Custom".to_string(),
    };
    let result = inject_credential(&cred_type, "secret", "wk_custom_abc", "wk_custom_abc");
    assert_eq!(result, "secret");
}

#[test]
fn token_prefix_candidates_prefer_longest_vault_token_shape() {
    assert_eq!(
        candidate_prefix_lengths_with_sideload_tokens(
            "wk_outer_12345678wk_inner_abcdefghsuffix",
            std::iter::empty::<&str>(),
        ),
        vec![
            "wk_outer_12345678wk_inner_abcdefgh".len(),
            "wk_outer_12345678".len(),
        ],
    );
}

#[test]
fn token_prefix_candidates_include_available_sideload_token() {
    assert_eq!(
        candidate_prefix_lengths_with_sideload_tokens("wk_env_openai_suffix", ["wk_env_openai"]),
        vec!["wk_env_openai".len()],
    );
}

#[test]
fn set_content_length_strips_conflicting_transfer_encoding() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        hyper::header::TRANSFER_ENCODING,
        hyper::header::HeaderValue::from_static("chunked"),
    );
    headers.insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from_static("999"),
    );

    set_content_length(&mut headers, 12);

    assert!(!headers.contains_key(hyper::header::TRANSFER_ENCODING));
    assert_eq!(headers[hyper::header::CONTENT_LENGTH], "12");
}

#[test]
fn host_restriction_empty_allows_all() {
    assert!(check_host_restriction(&[], "anything.com"));
}

#[test]
fn host_restriction_exact_match() {
    let hosts = vec!["api.example.com".to_string()];
    assert!(check_host_restriction(&hosts, "api.example.com"));
    assert!(check_host_restriction(&hosts, "API.EXAMPLE.COM"));
    assert!(!check_host_restriction(&hosts, "evil.com"));
}

#[test]
fn host_restriction_glob_match() {
    let hosts = vec!["*.example.com".to_string()];
    assert!(check_host_restriction(&hosts, "api.example.com"));
    assert!(!check_host_restriction(&hosts, "example.com"));
}

#[test]
fn build_target_uri_with_scheme() {
    let headers = hyper::HeaderMap::new();
    let uri: Uri = "http://example.com/path".parse().unwrap();
    assert_eq!(build_target_uri(&uri, &headers), "http://example.com/path");
}

#[test]
fn build_target_uri_without_scheme() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "host",
        hyper::header::HeaderValue::from_static("example.com"),
    );
    let uri: Uri = "/path".parse().unwrap();
    assert_eq!(build_target_uri(&uri, &headers), "http://example.com/path");
}

#[test]
fn build_target_uri_without_scheme_no_host() {
    let headers = hyper::HeaderMap::new();
    let uri: Uri = "/path".parse().unwrap();
    assert_eq!(build_target_uri(&uri, &headers), "http://localhost/path");
}

#[test]
fn error_response_has_json_body() {
    let resp = error_response(StatusCode::FORBIDDEN, "denied");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(content_type, "application/json");
}

#[test]
fn self_target_detects_loopback_forward_urls() {
    assert!(target::target_points_to_proxy(
        "http://localhost:7700/v1",
        7700
    ));
    assert!(target::target_points_to_proxy(
        "http://127.0.0.1:7700/v1",
        7700
    ));
    assert!(target::target_points_to_proxy("http://[::1]:7700/v1", 7700));
    assert!(!target::target_points_to_proxy(
        "http://localhost:7701/v1",
        7700
    ));
    assert!(!target::target_points_to_proxy(
        "https://api.example.com/v1",
        7700
    ));
}

#[test]
fn self_target_detects_connect_authorities() {
    assert!(target::authority_points_to_proxy(
        "localhost:7700",
        Some(443),
        7700
    ));
    assert!(target::authority_points_to_proxy(
        "127.0.0.1:7700",
        Some(443),
        7700
    ));
    assert!(target::authority_points_to_proxy(
        "[::1]:7700",
        Some(443),
        7700
    ));
    assert!(!target::authority_points_to_proxy(
        "localhost:443",
        Some(443),
        7700
    ));
    assert!(!target::authority_points_to_proxy(
        "api.example.com:443",
        Some(443),
        7700
    ));
}
