use hyper::Uri;

pub(super) fn uri_points_to_proxy(uri: &Uri, proxy_port: u16) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    let port = uri
        .port_u16()
        .or_else(|| default_port_for_scheme(uri.scheme_str()));
    host_port_points_to_proxy(host, port, proxy_port)
}

pub(super) fn target_points_to_proxy(target: &str, proxy_port: u16) -> bool {
    if let Ok(uri) = target.parse::<Uri>()
        && uri_points_to_proxy(&uri, proxy_port)
    {
        return true;
    }
    authority_points_to_proxy(target, None, proxy_port)
}

pub(super) fn authority_points_to_proxy(
    authority: &str,
    default_port: Option<u16>,
    proxy_port: u16,
) -> bool {
    let Some((host, port)) = split_authority(authority, default_port) else {
        return false;
    };
    host_port_points_to_proxy(&host, port, proxy_port)
}

fn host_port_points_to_proxy(host: &str, port: Option<u16>, proxy_port: u16) -> bool {
    is_loopback_host(host) && port == Some(proxy_port)
}

fn default_port_for_scheme(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    }
}

fn split_authority(authority: &str, default_port: Option<u16>) -> Option<(String, Option<u16>)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .or(default_port);
        return Some((host, port));
    }

    if authority.matches(':').count() == 1 {
        let (host, port) = authority.rsplit_once(':')?;
        return Some((host.to_string(), port.parse().ok().or(default_port)));
    }

    Some((authority.to_string(), default_port))
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
}
