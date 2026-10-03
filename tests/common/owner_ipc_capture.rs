//! Failure reports accept a tiny timing grammar, never arbitrary child stderr.
use std::collections::VecDeque;

pub const MAX_RECORDS: usize = 128;
pub const MAX_LINE_BYTES: usize = 256;

pub struct PhaseCapture {
    pid: u32,
    pending: Vec<u8>,
    oversized: bool,
    accepted: u64,
    records: VecDeque<(u64, String)>,
}

impl PhaseCapture {
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            pending: Vec::new(),
            oversized: false,
            accepted: 0,
            records: VecDeque::new(),
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.oversized
                    && let Some(record) = safe_record(&self.pending, self.pid)
                {
                    self.accepted = self.accepted.saturating_add(1);
                    if self.records.len() == MAX_RECORDS {
                        self.records.pop_front();
                    }
                    self.records.push_back((self.accepted, record));
                }
                self.pending.clear();
                self.oversized = false;
            } else if !self.oversized {
                if self.pending.len() == MAX_LINE_BYTES {
                    self.pending.clear();
                    self.oversized = true;
                } else {
                    self.pending.push(byte);
                }
            }
        }
    }

    pub fn snapshot_since(&self, after: u64) -> (u64, String) {
        let mut report = String::new();
        for (index, record) in &self.records {
            if *index > after {
                report.push_str(record);
                report.push('\n');
            }
        }
        (self.accepted, report)
    }
}

fn safe_record(bytes: &[u8], expected_pid: u32) -> Option<String> {
    let line = std::str::from_utf8(bytes).ok()?.trim_end_matches('\r');
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 7 || fields[0] != "WKIPC_PHASE" || fields[1] != "v1" {
        return None;
    }
    let pid: u32 = fields[2].strip_prefix("pid=")?.parse().ok()?;
    let sequence: u64 = fields[3].strip_prefix("seq=")?.parse().ok()?;
    let method = fields[4].strip_prefix("method=")?;
    let phase = fields[5].strip_prefix("phase=")?;
    let elapsed: u64 = fields[6].strip_prefix("elapsed_ms=")?.parse().ok()?;
    if pid != expected_pid
        || !matches!(
            method,
            "pending"
                | "unknown"
                | "status"
                | "unlock"
                | "lock"
                | "list_credentials"
                | "list_projects"
                | "list_partitions"
                | "add_credential"
                | "add_template"
                | "generate_login"
                | "get_settings"
                | "set_settings"
                | "shutdown"
        )
        || !matches!(
            phase,
            "connect_wait"
                | "connected"
                | "read_wait"
                | "read_complete"
                | "read_empty"
                | "invalid_request"
                | "handler_start"
                | "handler_complete"
                | "write_start"
                | "write_accepted"
                | "instance_ready"
        )
    {
        return None;
    }
    Some(format!(
        "WKIPC_PHASE v1 pid={pid} seq={sequence} method={method} phase={phase} elapsed_ms={elapsed}"
    ))
}
