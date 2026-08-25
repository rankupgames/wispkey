/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Optional tray UI host for owner credential entry.
 * Created: 2026-08-25
 * Last Modified: 2026-08-25
 */

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use serde_json::{Value, json};
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy, EventLoopWindowTarget};
use tao::window::{Window, WindowBuilder, WindowId};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use wry::WebViewBuilder;

const UI_HTML: &str = include_str!("../ui-dist/index.html");
const INIT_SCRIPT: &str = r#"
window.__wispkeyPending = window.__wispkeyPending || {};
window.__wispkeyResolve = function (id, payload) {
  const pending = window.__wispkeyPending[id];
  if (pending) {
    delete window.__wispkeyPending[id];
    pending(payload);
  }
};
"#;

struct Dialog {
    _window: Window,
    webview: wry::WebView,
}

enum UserEvent {
    Menu(MenuId),
    IpcRequest { window_id: WindowId, body: String },
    IpcResponse { window_id: WindowId, script: String },
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls ring CryptoProvider");
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wispkey=info".parse().expect("static directive must parse")),
        )
        .init();

    if !wispkey::owner_ipc::metadata_path().exists() {
        std::thread::spawn(|| {
            let runtime = tokio::runtime::Runtime::new().expect("owner ipc runtime");
            if let Err(error) = runtime.block_on(wispkey::owner_ipc::serve()) {
                tracing::error!(error = %error, "owner ipc server stopped");
            }
        });
        wait_for_owner_endpoint();
    }

    let menu = Menu::new();
    let add_item = MenuItem::new("Add credential", true, None);
    let list_item = MenuItem::new("List credentials", true, None);
    let unlock_item = MenuItem::new("Unlock vault", true, None);
    let lock_item = MenuItem::new("Lock vault", true, None);
    let settings_item = MenuItem::new("Open settings", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    menu.append(&add_item).expect("add menu item");
    menu.append(&list_item).expect("list menu item");
    menu.append(&unlock_item).expect("unlock menu item");
    menu.append(&lock_item).expect("lock menu item");
    menu.append(&settings_item).expect("settings menu item");
    menu.append(&quit_item).expect("quit menu item");

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let menu_proxy = proxy.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = menu_proxy.send_event(UserEvent::Menu(event.id));
    }));

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(&vault_tooltip())
        .with_icon(tray_icon_image())
        .build()
        .expect("tray icon");

    let add_id = add_item.id().clone();
    let list_id = list_item.id().clone();
    let unlock_id = unlock_item.id().clone();
    let lock_id = lock_item.id().clone();
    let settings_id = settings_item.id().clone();
    let quit_id = quit_item.id().clone();
    let dialogs: Rc<RefCell<HashMap<WindowId, Dialog>>> = Rc::new(RefCell::new(HashMap::new()));
    let keepalive: Rc<RefCell<Option<Window>>> = Rc::new(RefCell::new(None));
    let tray = Rc::new(RefCell::new(tray));

    event_loop.run(move |event, event_loop, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                let window = WindowBuilder::new()
                    .with_visible(false)
                    .with_title("WispKey")
                    .build(event_loop)
                    .expect("keepalive window");
                *keepalive.borrow_mut() = Some(window);
                tracing::info!("WispKey tray started");
            }
            Event::UserEvent(UserEvent::Menu(menu_id)) => {
                if menu_id == add_id {
                    open_dialog(&dialogs, event_loop, &proxy, "add");
                } else if menu_id == list_id {
                    open_dialog(&dialogs, event_loop, &proxy, "list");
                } else if menu_id == unlock_id {
                    open_dialog(&dialogs, event_loop, &proxy, "unlock");
                } else if menu_id == settings_id {
                    open_dialog(&dialogs, event_loop, &proxy, "settings");
                } else if menu_id == lock_id {
                    let _ = call_owner(json!({ "id": "lock", "method": "lock" }));
                    dialogs.borrow_mut().clear();
                    refresh_tooltip(&tray);
                } else if menu_id == quit_id {
                    let _ = call_owner(json!({ "id": "shutdown", "method": "shutdown" }));
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::UserEvent(UserEvent::IpcRequest { window_id, body }) => {
                let proxy = proxy.clone();
                std::thread::spawn(move || {
                    let request: Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));
                    let response = call_owner(request.clone());
                    let script = ipc_resolve_script(&request, &response);
                    let _ = proxy.send_event(UserEvent::IpcResponse { window_id, script });
                });
            }
            Event::UserEvent(UserEvent::IpcResponse { window_id, script }) => {
                if let Some(dialog) = dialogs.borrow().get(&window_id)
                    && let Err(error) = dialog.webview.evaluate_script(&script)
                {
                    tracing::error!(error = %error, "failed to deliver owner IPC response");
                }
                refresh_tooltip(&tray);
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                window_id,
                ..
            } => {
                if keepalive
                    .borrow()
                    .as_ref()
                    .is_some_and(|window| window.id() == window_id)
                {
                    return;
                }
                dialogs.borrow_mut().remove(&window_id);
            }
            _ => {}
        }
    });
}

fn wait_for_owner_endpoint() {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !wispkey::owner_ipc::metadata_path().exists() {
        if std::time::Instant::now() > deadline {
            eprintln!("Error: owner IPC did not start");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn open_dialog(
    dialogs: &Rc<RefCell<HashMap<WindowId, Dialog>>>,
    event_loop: &EventLoopWindowTarget<UserEvent>,
    proxy: &EventLoopProxy<UserEvent>,
    view: &str,
) {
    let view = sanitize_view(view);
    let window = WindowBuilder::new()
        .with_title("WispKey")
        .with_inner_size(tao::dpi::LogicalSize::new(520.0, 640.0))
        .build(event_loop)
        .expect("dialog window");
    let window_id = window.id();
    let html = UI_HTML.replace("\"WISPKEY_INITIAL_VIEW\"", &format!("\"{view}\""));
    let proxy = proxy.clone();
    match WebViewBuilder::new()
        .with_html(&html)
        .with_initialization_script(INIT_SCRIPT)
        .with_ipc_handler(move |message| {
            let _ = proxy.send_event(UserEvent::IpcRequest {
                window_id,
                body: message.body().clone(),
            });
        })
        .build(&window)
    {
        Ok(webview) => {
            dialogs.borrow_mut().insert(
                window_id,
                Dialog {
                    _window: window,
                    webview,
                },
            );
        }
        Err(error) => tracing::error!(error = %error, "failed to open tray dialog"),
    }
}

fn sanitize_view(view: &str) -> &'static str {
    match view {
        "list" => "list",
        "settings" => "settings",
        "unlock" => "unlock",
        _ => "add",
    }
}

fn ipc_resolve_script(request: &Value, response: &Value) -> String {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    format!(
        "window.__wispkeyResolve && window.__wispkeyResolve({}, {});",
        serde_json::to_string(&id).unwrap_or_else(|_| "null".to_string()),
        serde_json::to_string(response).unwrap_or_else(|_| "{\"ok\":false}".to_string())
    )
}

fn call_owner(request: Value) -> Value {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("ipc runtime")
        .block_on(wispkey::owner_ipc::call(
            &wispkey::owner_ipc::socket_path(),
            request,
        ))
        .unwrap_or_else(|error| {
            json!({
                "ok": false,
                "error": { "code": "unavailable", "message": error.to_string() }
            })
        })
}

fn vault_tooltip() -> String {
    let response = call_owner(json!({ "id": "status", "method": "status" }));
    if response["result"]["session_active"] == true {
        "WispKey — unlocked".to_string()
    } else {
        "WispKey — locked".to_string()
    }
}

fn refresh_tooltip(tray: &Rc<RefCell<TrayIcon>>) {
    if let Err(error) = tray.borrow().set_tooltip(Some(&vault_tooltip())) {
        tracing::error!(error = %error, "failed to update tray tooltip");
    }
}

fn tray_icon_image() -> Icon {
    let mut rgba = vec![0u8; 32 * 32 * 4];
    for pixel in rgba.chunks_exact_mut(4) {
        pixel[0] = 0x1a;
        pixel[1] = 0x73;
        pixel[2] = 0xe8;
        pixel[3] = 0xff;
    }
    Icon::from_rgba(rgba, 32, 32).expect("tray icon")
}
