use chrono::Utc;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{FillRequest, Result, Vault};
use crate::core::{CredentialType, browser, session_store};

const MAX_BINDINGS: i64 = 64;
const MAX_JOBS: i64 = 1024;
const MAX_OUTBOX: i64 = 4096;
const MAX_MESSAGE: usize = 8192;
const TTL: i64 = 300;
fn db<T>(value: rusqlite::Result<T>) -> Result<T> {
    value.map_err(|_| "receiver store unavailable")
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 96 && value.bytes().all(|b| b.is_ascii_graphic())
}

/// Authenticated transport identity, not caller-supplied display labels. A future
/// adapter must derive these fields from verified claims and device registration.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub issuer: String,
    pub owner: String,
    pub tenant: String,
    pub client: String,
    pub device: String,
}

/// Local owner selection only. Never deserialize this from a remote request.
pub struct Selection<'a> {
    pub project: &'a str,
    pub partition: &'a str,
    pub name: &'a str,
    pub origin: &'a str,
    pub account: &'a str,
    /// Owner-declared custodian label; not a browser-profile attestation.
    pub profile: &'a str,
}

/// Local handle, with no Deserialize implementation and no secret fields.
#[derive(Clone)]
pub struct Binding {
    id: String,
    revision: String,
    expires_at: i64,
}
impl Binding {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn revision(&self) -> &str {
        &self.revision
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBinding {
    principal: Principal,
    project: String,
    partition_id: String,
    name: String,
    credential_id: String,
    origin: String,
    account: String,
    profile: String,
    revision: String,
    generation: i64,
    session_revision: String,
    expires_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Request {
        job_id: String,
        revision: String,
        origin: String,
        account: String,
        profile: String,
        expires_at: i64,
    },
    Status {
        job_id: String,
    },
    Cancel {
        job_id: String,
    },
    Acknowledge {
        sequence: i64,
    },
}

/// Constructed by a trusted transport implementation after authentication, not
/// by parsing an `authenticated` boolean. There is no shipping implementation.
pub struct VerifiedDelivery {
    pub principal: Principal,
    pub binding_id: String,
    pub command: Command,
}

/// Trusted embedding boundary. Verification must authenticate issuer, subject,
/// tenant, client, device and message integrity/replay constraints, and bound its
/// own processing. Never implement this by merely deserializing untrusted input.
/// This crate supplies no production or runtime-selectable synthetic verifier.
pub trait AuthenticatedTransport {
    fn verify(&self, message: &[u8]) -> Result<VerifiedDelivery>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Queued,
    ReleaseCommitted,
    Filled,
    Denied,
    Cancelled,
    Expired,
    OutcomeUnknown,
}
impl State {
    fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ReleaseCommitted => "release-committed",
            Self::Filled => "filled",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::OutcomeUnknown => "outcome-unknown",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "release-committed" => Ok(Self::ReleaseCommitted),
            "filled" => Ok(Self::Filled),
            "denied" => Ok(Self::Denied),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            "outcome-unknown" => Ok(Self::OutcomeUnknown),
            _ => Err("receiver state unavailable"),
        }
    }
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Status {
    pub job_id: String,
    pub state: State,
}
#[derive(Debug, Serialize)]
pub struct Event {
    pub sequence: i64,
    pub status: Status,
}
#[derive(Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Receipt {
    Status(Status),
    Acknowledged,
}

fn generation(vault: &Vault) -> Result<i64> {
    db(vault.db().query_row(
        "SELECT revision FROM browser_receiver_generation WHERE id=1",
        [],
        |r| r.get(0),
    ))
}
fn stored(vault: &Vault, id: &str) -> Result<StoredBinding> {
    let (metadata, revoked): (String, bool) = db(vault.db().query_row(
        "SELECT metadata,revoked FROM browser_receiver_bindings WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    if revoked {
        return Err("receiver binding revoked");
    }
    serde_json::from_str(&metadata).map_err(|_| "receiver binding unavailable")
}
fn valid_principal(p: &Principal) -> bool {
    p.issuer.len() <= 300
        && crate::core::parse_https_origin(&p.issuer).ok().as_deref() == Some(&p.issuer)
        && [&p.owner, &p.tenant, &p.client, &p.device]
            .into_iter()
            .all(|s| text(s))
}
fn check_live(vault: &Vault, binding: &StoredBinding) -> Result<()> {
    let store = session_store::session_store();
    let session = vault
        .operation_session_binding_from_record(
            store
                .load_locked()
                .map_err(|_| "receiver owner session unavailable")?,
        )
        .map_err(|_| "receiver owner session unavailable")?;
    if session.revision != binding.session_revision
        || Utc::now().timestamp() >= binding.expires_at
        || generation(vault)? != binding.generation
    {
        return Err("receiver selection expired or changed");
    }
    let credential = vault
        .get_credential_in_project(&binding.project, &binding.name)
        .map_err(|_| "receiver target unavailable")?;
    if credential.id != binding.credential_id
        || credential.partition_id.as_deref() != Some(&binding.partition_id)
        || credential.origin != binding.origin
        || credential.credential_type != CredentialType::WebsiteLogin
        || credential.lifecycle_state == crate::core::LIFECYCLE_ARCHIVED
    {
        return Err("receiver target changed");
    }
    vault
        .ensure_auth_usable(&credential.id, true, Some(&binding.origin))
        .map_err(|_| "receiver authorization unavailable")
}

/// Prepare a short-lived local owner selection. This is not device enrollment or
/// proof of provider identity. Only a trusted owner frontend may call this API.
pub fn prepare(vault: &Vault, principal: Principal, selection: Selection<'_>) -> Result<Binding> {
    if !valid_principal(&principal)
        || ![
            selection.project,
            selection.partition,
            selection.name,
            selection.account,
            selection.profile,
        ]
        .into_iter()
        .all(text)
        || selection.origin.len() > 300
        || crate::core::parse_https_origin(selection.origin)
            .ok()
            .as_deref()
            != Some(selection.origin)
    {
        return Err("invalid receiver selection");
    }
    let tx = db(Transaction::new_unchecked(
        vault.db(),
        TransactionBehavior::Immediate,
    ))?;
    let store = session_store::session_store();
    let _guard = store.lock().map_err(|_| "receiver session unavailable")?;
    let session = vault
        .operation_session_binding_from_record(
            store
                .load_locked()
                .map_err(|_| "receiver session unavailable")?,
        )
        .map_err(|_| "receiver session unavailable")?;
    let count: i64 =
        db(vault
            .db()
            .query_row("SELECT COUNT(*) FROM browser_receiver_bindings", [], |r| {
                r.get(0)
            }))?;
    if count >= MAX_BINDINGS {
        return Err("receiver binding limit reached");
    }
    let partition_id = vault
        .resolve_partition_id_for_insert(Some(selection.partition), Some(selection.project))
        .map_err(|_| "receiver scope unavailable")?;
    let credential = vault
        .get_credential_in_project(selection.project, selection.name)
        .map_err(|_| "receiver target unavailable")?;
    let expires_at = (Utc::now().timestamp() + TTL).min(session.expires_at.timestamp());
    let binding = Binding {
        id: Uuid::new_v4().to_string(),
        revision: Uuid::new_v4().to_string(),
        expires_at,
    };
    let selected = StoredBinding {
        principal,
        project: selection.project.into(),
        partition_id,
        name: selection.name.into(),
        credential_id: credential.id,
        origin: selection.origin.into(),
        account: selection.account.into(),
        profile: selection.profile.into(),
        revision: binding.revision.clone(),
        generation: generation(vault)?,
        session_revision: session.revision,
        expires_at,
    };
    check_live(vault, &selected)?;
    let metadata = serde_json::to_string(&selected).map_err(|_| "invalid receiver selection")?;
    db(vault.db().execute(
        "INSERT INTO browser_receiver_bindings(id,metadata) VALUES(?1,?2)",
        params![binding.id, metadata],
    ))?;
    db(tx.commit())?;
    Ok(binding)
}

/// Restore a local checkpoint handle without granting authority or renewing it.
/// The ID must come from the receiver's protected local configuration, not a
/// remote request selecting an arbitrary local binding.
pub fn restore_local_binding(vault: &Vault, id: &str) -> Result<Binding> {
    if Uuid::parse_str(id).is_err() {
        return Err("invalid receiver binding");
    }
    let metadata: String = db(vault.db().query_row(
        "SELECT metadata FROM browser_receiver_bindings WHERE id=?1",
        [id],
        |r| r.get(0),
    ))?;
    let selected: StoredBinding =
        serde_json::from_str(&metadata).map_err(|_| "receiver binding unavailable")?;
    Ok(Binding {
        id: id.into(),
        revision: selected.revision,
        expires_at: selected.expires_at,
    })
}

fn outbox_event(vault: &Vault, binding: &str, job: &str, state: State) -> Result<()> {
    let count: i64 =
        db(vault
            .db()
            .query_row("SELECT COUNT(*) FROM browser_receiver_outbox", [], |r| {
                r.get(0)
            }))?;
    if count >= MAX_OUTBOX {
        return Err("receiver outbox full");
    }
    db(vault.db().execute(
        "INSERT INTO browser_receiver_outbox(binding_id,job_id,state) VALUES(?1,?2,?3)",
        params![binding, job, state.label()],
    ))?;
    Ok(())
}
fn job(vault: &Vault, binding: &str, job_id: &str) -> Result<(String, State)> {
    let (request, state): (String, String) = db(vault.db().query_row(
        "SELECT request_id,state FROM browser_receiver_jobs WHERE binding_id=?1 AND job_id=?2",
        params![binding, job_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    Ok((request, State::parse(&state)?))
}
fn set_state(vault: &Vault, request: &str, expected: State, next: State) -> Result<()> {
    let (binding, job_id): (String, String) = db(vault.db().query_row(
        "SELECT binding_id,job_id FROM browser_receiver_jobs WHERE request_id=?1",
        [request],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    if db(vault.db().execute(
        "UPDATE browser_receiver_jobs SET state=?1 WHERE request_id=?2 AND state=?3",
        params![next.label(), request, expected.label()],
    ))? != 1
    {
        return Err("receiver job already decided");
    }
    outbox_event(vault, &binding, &job_id, next)
}
fn cancel_job(vault: &Vault, request: &str, state: State, queued: State) -> Result<()> {
    let next = match state {
        State::Queued => queued,
        State::ReleaseCommitted => State::OutcomeUnknown,
        _ => return Ok(()),
    };
    set_state(vault, request, state, next)?;
    db(vault.db().execute("UPDATE browser_fill_requests SET status='failed' WHERE request_id=?1 AND status IN ('pending','approved')", [request]))?;
    crate::audit::try_log_event(
        vault.db(),
        "BrowserReceiverStopped",
        None,
        None,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
    )
    .map_err(|_| "receiver audit unavailable")
}

/// Bounded ingress into the real local browser request store. Authentication is
/// injected; no URL, password, approval result or selected vault can enter here.
pub fn receive(
    vault: &Vault,
    handle: &Binding,
    transport: &impl AuthenticatedTransport,
    bytes: &[u8],
) -> Result<Receipt> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
        return Err("invalid receiver message");
    }
    let delivery = transport
        .verify(bytes)
        .map_err(|_| "receiver authentication failed")?;
    if delivery.binding_id != handle.id || !valid_principal(&delivery.principal) {
        return Err("receiver identity mismatch");
    }
    let tx = db(Transaction::new_unchecked(
        vault.db(),
        TransactionBehavior::Immediate,
    ))?;
    let selected = stored(vault, &handle.id)?;
    if delivery.principal != selected.principal {
        return Err("receiver identity mismatch");
    }
    reconcile_binding(vault, &handle.id, false, false)?;
    let response = match &delivery.command {
        Command::Request {
            job_id,
            revision,
            origin,
            account,
            profile,
            expires_at,
        } => {
            if Uuid::parse_str(job_id).is_err()
                || revision != &selected.revision
                || origin != &selected.origin
                || account != &selected.account
                || profile != &selected.profile
                || *expires_at > selected.expires_at
            {
                return Err("receiver intent mismatch");
            }
            let envelope =
                serde_json::to_string(&delivery.command).map_err(|_| "invalid receiver intent")?;
            let prior: Option<(String,String)> = db(vault.db().query_row(
                "SELECT envelope,state FROM browser_receiver_jobs WHERE binding_id=?1 AND job_id=?2", params![handle.id,job_id], |r| Ok((r.get(0)?,r.get(1)?))).optional())?;
            if let Some((previous, state)) = prior {
                if previous != envelope {
                    return Err("receiver job replay mismatch");
                }
                Receipt::Status(Status {
                    job_id: job_id.clone(),
                    state: State::parse(&state)?,
                })
            } else {
                if *expires_at <= Utc::now().timestamp() {
                    return Err("receiver intent expired");
                }
                let store = session_store::session_store();
                let _guard = store.lock().map_err(|_| "receiver session unavailable")?;
                check_live(vault, &selected)?;
                let count: i64 = db(vault.db().query_row(
                    "SELECT COUNT(*) FROM browser_receiver_jobs",
                    [],
                    |r| r.get(0),
                ))?;
                let pending: i64 = db(vault.db().query_row("SELECT COUNT(*) FROM browser_fill_requests WHERE status IN ('pending','approved')", [], |r| r.get(0)))?;
                if count >= MAX_JOBS || pending >= 32 {
                    return Err("receiver queue full");
                }
                let request = FillRequest {
                    request_id: Uuid::new_v4().to_string(),
                    name: selected.name.clone(),
                    project: selected.project.clone(),
                    origin: selected.origin.clone(),
                    requester: "Authenticated receiver transport".into(),
                    reason: "Review and fill only; submit yourself".into(),
                    status: "pending".into(),
                    expires_at: *expires_at,
                    credential_id: selected.credential_id.clone(),
                    revision: browser::revision(vault, &selected.credential_id)?,
                    receiver_binding: Some(handle.id.clone()),
                };
                db(vault.db().execute(
                    "INSERT INTO browser_receiver_jobs VALUES(?1,?2,?3,?4,'queued',?5)",
                    params![request.request_id, handle.id, job_id, envelope, expires_at],
                ))?;
                browser::insert_request(vault, &request)?;
                outbox_event(vault, &handle.id, job_id, State::Queued)?;
                check_live(vault, &selected)?;
                Receipt::Status(Status {
                    job_id: job_id.clone(),
                    state: State::Queued,
                })
            }
        }
        Command::Status { job_id } | Command::Cancel { job_id } => {
            if Uuid::parse_str(job_id).is_err() {
                return Err("invalid receiver job");
            }
            let (request, state) = job(vault, &handle.id, job_id)?;
            if matches!(&delivery.command, Command::Cancel { .. }) {
                cancel_job(vault, &request, state, State::Cancelled)?;
            }
            Receipt::Status(Status {
                job_id: job_id.clone(),
                state: job(vault, &handle.id, job_id)?.1,
            })
        }
        Command::Acknowledge { sequence } => {
            if *sequence <= 0 {
                return Err("invalid receiver acknowledgement");
            }
            let previous: i64 = db(vault.db().query_row(
                "SELECT acknowledged FROM browser_receiver_bindings WHERE id=?1",
                [&handle.id],
                |r| r.get(0),
            ))?;
            if *sequence > previous {
                let exists: bool = db(vault.db().query_row("SELECT EXISTS(SELECT 1 FROM browser_receiver_outbox WHERE binding_id=?1 AND sequence=?2)", params![handle.id,sequence], |r| r.get(0)))?;
                if !exists {
                    return Err("receiver acknowledgement unavailable");
                }
                db(vault.db().execute(
                    "DELETE FROM browser_receiver_outbox WHERE binding_id=?1 AND sequence<=?2",
                    params![handle.id, sequence],
                ))?;
                db(vault.db().execute(
                    "UPDATE browser_receiver_bindings SET acknowledged=?1 WHERE id=?2",
                    params![sequence, handle.id],
                ))?;
            }
            Receipt::Acknowledged
        }
    };
    db(tx.commit())?;
    Ok(response)
}

/// Local metadata outbox. Delivery/acknowledgement must use an authenticated
/// channel; an uncertain send retains the event and never repeats secret release.
pub fn outbox(vault: &Vault, binding: &Binding) -> Result<Vec<Event>> {
    let mut query = db(vault.db().prepare("SELECT sequence,job_id,state FROM browser_receiver_outbox WHERE binding_id=?1 ORDER BY sequence LIMIT 64"))?;
    let rows = db(query.query_map([&binding.id], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    }))?;
    rows.map(|r| {
        let (sequence, job_id, state) = db(r)?;
        Ok(Event {
            sequence,
            status: Status {
                job_id,
                state: State::parse(&state)?,
            },
        })
    })
    .collect()
}

/// Local owner revocation; no remote device is enrolled or signed out by this.
pub fn revoke(vault: &Vault, binding: &Binding) -> Result<()> {
    let tx = db(Transaction::new_unchecked(
        vault.db(),
        TransactionBehavior::Immediate,
    ))?;
    db(vault.db().execute(
        "UPDATE browser_receiver_bindings SET revoked=1 WHERE id=?1",
        [&binding.id],
    ))?;
    reconcile_binding(vault, &binding.id, true, false)?;
    db(tx.commit())
}
fn reconcile_binding(vault: &Vault, binding_id: &str, revoke: bool, restart: bool) -> Result<()> {
    let mut stmt = db(vault.db().prepare("SELECT request_id,state,expires_at FROM browser_receiver_jobs WHERE binding_id=?1 AND state IN ('queued','release-committed')"))?;
    let rows = db(stmt.query_map([binding_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    }))?;
    let rows = db(rows.collect::<rusqlite::Result<Vec<_>>>())?;
    for (request, state, expiry) in rows {
        let state = State::parse(&state)?;
        if revoke
            || expiry <= Utc::now().timestamp()
            || (restart && state == State::ReleaseCommitted)
        {
            cancel_job(
                vault,
                &request,
                state,
                if revoke {
                    State::Cancelled
                } else {
                    State::Expired
                },
            )?;
        }
    }
    Ok(())
}
/// Call once after receiver restart, not during an active fill. A committed
/// release without a durable fill result is terminal/unknown, never replayable.
pub fn reconcile_after_restart(vault: &Vault, binding: &Binding) -> Result<()> {
    let tx = db(Transaction::new_unchecked(
        vault.db(),
        TransactionBehavior::Immediate,
    ))?;
    let store = session_store::session_store();
    let _guard = store.lock().map_err(|_| "receiver session unavailable")?;
    let stale = stored(vault, &binding.id)
        .and_then(|b| check_live(vault, &b))
        .is_err();
    reconcile_binding(vault, &binding.id, stale, true)?;
    db(tx.commit())
}

fn bound_request(vault: &Vault, request: &FillRequest) -> Result<(StoredBinding, State)> {
    let binding_id = request
        .receiver_binding
        .as_deref()
        .ok_or("receiver binding unavailable")?;
    let binding = stored(vault, binding_id)?;
    let (id, state, expires_at): (String, String, i64) = db(vault.db().query_row(
        "SELECT binding_id,state,expires_at FROM browser_receiver_jobs WHERE request_id=?1",
        [&request.request_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ))?;
    if id != binding_id
        || request.credential_id != binding.credential_id
        || request.name != binding.name
        || request.project != binding.project
        || request.origin != binding.origin
        || request.expires_at != expires_at
        || expires_at > binding.expires_at
        || expires_at <= Utc::now().timestamp()
    {
        return Err("receiver request changed or expired");
    }
    Ok((binding, State::parse(&state)?))
}
pub(super) fn release_guard(
    vault: &Vault,
    request: &FillRequest,
) -> Result<session_store::SessionGuard> {
    let store = session_store::session_store();
    let guard = store.lock().map_err(|_| "receiver session unavailable")?;
    let (binding, state) = bound_request(vault, request)?;
    if state != State::Queued {
        return Err("receiver release already decided");
    }
    check_live(vault, &binding)?;
    Ok(guard)
}
pub(super) fn released(vault: &Vault, request: &FillRequest) -> Result<()> {
    let (binding, state) = bound_request(vault, request)?;
    if state != State::Queued {
        return Err("receiver release already decided");
    }
    check_live(vault, &binding)?; // Session lock is held by browser::release.
    set_state(
        vault,
        &request.request_id,
        State::Queued,
        State::ReleaseCommitted,
    )?;
    let (binding, state) = bound_request(vault, request)?;
    if state != State::ReleaseCommitted {
        return Err("receiver release changed");
    }
    check_live(vault, &binding)
}
pub(super) fn finished(vault: &Vault, request: &FillRequest, completed: bool) -> Result<()> {
    let (_, state) = bound_request(vault, request)?;
    let next = match (state, completed) {
        (State::Queued, false) => State::Denied,
        (State::ReleaseCommitted, true) => State::Filled,
        (State::ReleaseCommitted, false) => State::OutcomeUnknown,
        _ => return Err("receiver result already decided"),
    };
    // Recheck local authority/revision/session before claiming successful fill.
    let store = session_store::session_store();
    let _guard = store.lock().map_err(|_| "receiver session unavailable")?;
    if completed {
        check_live(
            vault,
            &stored(vault, request.receiver_binding.as_deref().unwrap())?,
        )?;
    }
    set_state(vault, &request.request_id, state, next)?;
    if completed {
        check_live(
            vault,
            &stored(vault, request.receiver_binding.as_deref().unwrap())?,
        )?;
    }
    Ok(())
}
pub(super) fn expired(vault: &Vault, request: &FillRequest) -> Result<()> {
    let state: String = db(vault.db().query_row(
        "SELECT state FROM browser_receiver_jobs WHERE request_id=?1",
        [&request.request_id],
        |r| r.get(0),
    ))?;
    cancel_job(
        vault,
        &request.request_id,
        State::parse(&state)?,
        State::Expired,
    )
}
pub(super) fn approval_details(vault: &Vault, request: &FillRequest) -> Result<String> {
    let store = session_store::session_store();
    let _guard = store.lock().map_err(|_| "receiver session unavailable")?;
    let (b, state) = bound_request(vault, request)?;
    if state != State::Queued {
        return Err("receiver request already decided");
    }
    check_live(vault, &b)?;
    Ok(format!(
        "Receiver transport binding:\nIssuer: {}\nOwner/tenant: {} / {}\nClient/device: {} / {}\nOwner-declared account/profile: {} / {}\nThese labels do not attest provider identity or OS/profile isolation.\n\n",
        b.principal.issuer,
        b.principal.owner,
        b.principal.tenant,
        b.principal.client,
        b.principal.device,
        b.account,
        b.profile
    ))
}
