//! Opt-in timing only: no request IDs, parameters, paths, responses or errors.
use serde_json::Value;
use std::io::Write;
use std::time::Instant;

#[derive(Clone, Copy)]
pub(super) enum Method {
    Pending,
    Unknown,
    Known(&'static str),
}

impl Method {
    pub(super) fn from_request(request: &Value) -> Self {
        match request.get("method").and_then(Value::as_str) {
            Some("status") => Self::Known("status"),
            Some("unlock") => Self::Known("unlock"),
            Some("lock") => Self::Known("lock"),
            Some("list_credentials") => Self::Known("list_credentials"),
            Some("list_projects") => Self::Known("list_projects"),
            Some("list_partitions") => Self::Known("list_partitions"),
            Some("add_credential") => Self::Known("add_credential"),
            Some("add_template") => Self::Known("add_template"),
            Some("generate_login") => Self::Known("generate_login"),
            Some("get_settings") => Self::Known("get_settings"),
            Some("set_settings") => Self::Known("set_settings"),
            Some("shutdown") => Self::Known("shutdown"),
            _ => Self::Unknown,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Unknown => "unknown",
            Self::Known(label) => label,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Phase {
    ConnectWait,
    Connected,
    ReadWait,
    ReadComplete,
    ReadEmpty,
    InvalidRequest,
    HandlerStart,
    HandlerComplete,
    WriteStart,
    WriteAccepted,
    InstanceReady,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::ConnectWait => "connect_wait",
            Self::Connected => "connected",
            Self::ReadWait => "read_wait",
            Self::ReadComplete => "read_complete",
            Self::ReadEmpty => "read_empty",
            Self::InvalidRequest => "invalid_request",
            Self::HandlerStart => "handler_start",
            Self::HandlerComplete => "handler_complete",
            Self::WriteStart => "write_start",
            // Tokio/Mio can accept an overlapped write before peer receipt.
            Self::WriteAccepted => "write_accepted",
            Self::InstanceReady => "instance_ready",
        }
    }
}

pub(super) struct Phases {
    enabled: bool,
    started: Instant,
    sequence: u64,
}

impl Phases {
    pub(super) fn new() -> Self {
        Self {
            enabled: std::env::var("WISPKEY_OWNER_IPC_DIAGNOSTICS").as_deref() == Ok("1"),
            started: Instant::now(),
            sequence: 0,
        }
    }

    pub(super) fn next_connection(&mut self) {
        self.sequence = self.sequence.saturating_add(1);
    }

    pub(super) fn record(&self, method: Method, phase: Phase) {
        if self.enabled {
            let _ = writeln!(
                std::io::stderr().lock(),
                "WKIPC_PHASE v1 pid={} seq={} method={} phase={} elapsed_ms={}",
                std::process::id(),
                self.sequence,
                method.label(),
                phase.label(),
                self.started.elapsed().as_millis().min(u64::MAX.into()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Method;
    use serde_json::json;

    #[test]
    fn diagnostic_method_never_echoes_private_input() {
        for method in [
            json!("secret\nmethod"),
            json!(null),
            json!({"private": "value"}),
        ] {
            let request = json!({"method":method,"id":"private-id","params":{"password":"secret"}});
            assert_eq!(Method::from_request(&request).label(), "unknown");
        }
        let request =
            json!({"method":"generate_login","id":"private-id","params":{"password":"secret"}});
        assert_eq!(Method::from_request(&request).label(), "generate_login");
    }
}
