//! Serial desktop-to-owner IPC. Queue expiry never retries an uncertain operation.

use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tao::event_loop::EventLoopProxy;
use tao::window::WindowId;
use zeroize::Zeroize;

use crate::UserEvent;

// Reject unstarted work before the renderer's 30-second response deadline.
const OWNER_QUEUE_TTL: Duration = Duration::from_secs(29);

pub(super) struct OwnerClient {
    jobs: SyncSender<OwnerJob>,
}

struct OwnerJob {
    window_id: WindowId,
    request: Value,
    copy_token: bool,
    activity: u64,
    deadline: Instant,
    destination: ResponseDestination,
}

enum ResponseDestination {
    Renderer,
    MenuLock,
}

impl OwnerClient {
    pub(super) fn start(proxy: EventLoopProxy<UserEvent>) -> Self {
        let (jobs, receiver) = mpsc::sync_channel::<OwnerJob>(16);
        std::thread::spawn(move || {
            for job in receiver {
                let id = job.request.get("id").cloned().unwrap_or(Value::Null);
                let response = dispatch_owner(job.request, job.deadline);
                let event = match job.destination {
                    ResponseDestination::MenuLock => UserEvent::MenuLock(response),
                    ResponseDestination::Renderer => UserEvent::Response {
                        window_id: job.window_id,
                        id,
                        response,
                        copy_token: job.copy_token,
                        activity: job.activity,
                    },
                };
                if proxy.send_event(event).is_err() {
                    break;
                }
            }
        });
        Self { jobs }
    }

    pub(super) fn queue(
        &self,
        window_id: WindowId,
        request: Value,
        copy_token: bool,
        activity: u64,
    ) -> bool {
        self.enqueue(OwnerJob {
            window_id,
            request,
            copy_token,
            activity,
            deadline: Instant::now() + OWNER_QUEUE_TTL,
            destination: ResponseDestination::Renderer,
        })
    }

    pub(super) fn lock(&self, window_id: WindowId) -> bool {
        self.enqueue(OwnerJob {
            window_id,
            request: json!({"method":"lock"}),
            copy_token: false,
            activity: 0,
            deadline: Instant::now() + OWNER_QUEUE_TTL,
            destination: ResponseDestination::MenuLock,
        })
    }

    fn enqueue(&self, job: OwnerJob) -> bool {
        match self.jobs.try_send(job) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(mut job) | mpsc::TrySendError::Disconnected(mut job)) => {
                clear_json(&mut job.request);
                false
            }
        }
    }
}

fn dispatch_owner(mut request: Value, deadline: Instant) -> Value {
    if Instant::now() >= deadline {
        clear_json(&mut request);
        return failure(
            "timeout",
            "operation expired before starting; no request was sent",
        );
    }
    call_owner(request)
}

fn call_owner(request: Value) -> Value {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("owner runtime")
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(30),
                wispkey::owner_ipc::call(&wispkey::owner_ipc::socket_path(), request),
            )
            .await
        })
        .ok()
        .and_then(Result::ok)
        .unwrap_or_else(|| {
            failure(
                "unavailable",
                "owner IPC is unavailable; check the operation before retrying",
            )
        })
}

pub(super) fn wait_for_owner_endpoint() -> bool {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("owner runtime");
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if wispkey::owner_ipc::is_live().await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
}

pub(super) fn failure(code: &str, message: &str) -> Value {
    json!({"ok":false,"error":{"code":code,"message":message}})
}

pub(super) fn clear_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(clear_json),
        Value::Object(fields) => fields.values_mut().for_each(clear_json),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_queued_request_is_rejected_before_owner_dispatch() {
        let response = dispatch_owner(
            json!({"method":"synthetic_expired", "params":{"value":"synthetic-secret"}}),
            Instant::now(),
        );
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "timeout");
        assert!(!response.to_string().contains("synthetic-secret"));
    }
}
