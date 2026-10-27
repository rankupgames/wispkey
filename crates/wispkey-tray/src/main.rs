/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Optional local desktop popout; the CLI owns vault operations.
 * Created: 2026-08-25
 * Last Modified: 2026-10-26
 */

use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender};
use std::time::Duration;

use serde_json::{Value, json};
use tao::dpi::{LogicalSize, PhysicalPosition};
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy, EventLoopWindowTarget};
use tao::window::{Window, WindowBuilder, WindowId};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use wry::{DragDropEvent, WebViewBuilder};
use zeroize::{Zeroize, Zeroizing};

const UI_HTML: &str = include_str!("../ui-dist/index.html");
const WIDTH: f64 = 460.0;
const MIN_HEIGHT: f64 = 300.0;
const MAX_HEIGHT: f64 = 820.0;
const MAX_RENDERER_BYTES: usize = 1024 * 1024;

struct Popout {
    // Drop the webview before its native parent.
    webview: wry::WebView,
    window: Window,
    returning_from_picker: bool,
}

enum UserEvent {
    Menu(MenuId),
    Tray(TrayIconEvent),
    Request {
        window_id: WindowId,
        body: String,
    },
    Response {
        window_id: WindowId,
        id: Value,
        response: Value,
        copy_token: bool,
    },
    Files {
        window_id: WindowId,
        paths: Vec<PathBuf>,
    },
    Drag {
        window_id: WindowId,
        active: bool,
    },
}

struct OwnerJob {
    window_id: WindowId,
    request: Value,
    copy_token: bool,
}

#[derive(Clone, Copy)]
struct Anchor {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring provider");
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wispkey=info".parse().expect("static directive")),
        )
        .init();
    if !wait_for_owner_endpoint() {
        eprintln!("Error: owner IPC is unavailable; start it with `wispkey tray`");
        std::process::exit(1);
    }
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    #[cfg(target_os = "macos")]
    let event_loop = {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        let mut event_loop = event_loop;
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
        event_loop.set_dock_visibility(false);
        event_loop
    };
    #[cfg(target_os = "macos")]
    let application_menu = macos_application_menu();
    let proxy = event_loop.create_proxy();
    let jobs = owner_worker(proxy.clone());
    let menu = Menu::new();
    let open = MenuItem::new("Open WispKey", true, None);
    let lock = MenuItem::new("Lock vault", true, None);
    let quit = MenuItem::new("Quit", true, None);
    for item in [&open, &lock, &quit] {
        menu.append(item).expect("tray menu item");
    }
    let open_id = open.id().clone();
    let lock_id = lock.id().clone();
    let quit_id = quit.id().clone();
    let menu_proxy = proxy.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = menu_proxy.send_event(UserEvent::Menu(event.id));
    }));
    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = tray_proxy.send_event(UserEvent::Tray(event));
    }));
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip("WispKey")
        .with_icon(tray_icon_image())
        .build()
        .expect("tray icon");
    let mut popout: Option<Popout> = None;
    let mut keepalive: Option<Window> = None;
    let mut clipboard: Option<arboard::Clipboard> = None;
    let mut anchor = None;
    event_loop.run(move |event, target, control| {
        #[cfg(target_os = "macos")]
        let _application_menu = &application_menu;
        *control = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                keepalive = Some(WindowBuilder::new().with_visible(false)
                    .with_title("WispKey").build(target).expect("keepalive window"));
            }
            Event::UserEvent(UserEvent::Tray(TrayIconEvent::Click {
                rect, button: MouseButton::Left, button_state: MouseButtonState::Up, ..
            })) => {
                anchor = Some(Anchor { x: rect.position.x, y: rect.position.y,
                    width: f64::from(rect.size.width), height: f64::from(rect.size.height) });
                if popout.is_some() { dismiss(&mut popout, &jobs); }
                else { popout = open_popout(target, &proxy, anchor); }
            }
            Event::UserEvent(UserEvent::Menu(id)) if id == open_id => {
                if popout.is_none() { popout = open_popout(target, &proxy, anchor); }
                if let Some(dialog) = &popout { dialog.window.set_focus(); }
            }
            Event::UserEvent(UserEvent::Menu(id)) if id == lock_id => {
                dismiss(&mut popout, &jobs);
                if let Some(window) = &keepalive {
                    queue(&jobs, window.id(), json!({"id":"menu-lock", "method":"lock"}), false);
                }
            }
            Event::UserEvent(UserEvent::Menu(id)) if id == quit_id => {
                dismiss(&mut popout, &jobs);
                clipboard.take();
                // Closing this GUI does not terminate a shared CLI-owned server.
                *control = ControlFlow::Exit;
            }
            Event::UserEvent(UserEvent::Request { window_id, body }) => {
                let body = Zeroizing::new(body);
                let Some(dialog) = popout.as_mut().filter(|dialog| dialog.window.id() == window_id) else { return; };
                if body.len() > MAX_RENDERER_BYTES { return; }
                let Ok(mut request) = serde_json::from_str::<Value>(&body) else { return; };
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                let method = request.get("method").and_then(Value::as_str).unwrap_or("").to_owned();
                let empty = json!({});
                let params = request.get("params").unwrap_or(&empty);
                match method.as_str() {
                    "close_window" => dismiss(&mut popout, &jobs),
                    "resize_window" => {
                        let height = params.get("height").and_then(Value::as_f64);
                        match height.filter(|height| height.is_finite() && *height > 0.0) {
                            Some(height) => {
                                let height = height.clamp(MIN_HEIGHT, MAX_HEIGHT);
                                let height = monitor_height(&dialog.window).map_or(height, |limit| height.min(limit));
                                dialog.window.set_inner_size(LogicalSize::new(WIDTH, height));
                                position_popout(&dialog.window, anchor);
                                deliver(dialog, &id, &json!({"ok":true,"result":{"resized":true}}));
                            }
                            None => deliver(dialog, &id, &failure("invalid_input", "window height is invalid")),
                        }
                    }
                    "choose_import_files" | "choose_import_directory" => {
                        dialog.returning_from_picker = true;
                        let picker = rfd::FileDialog::new().set_parent(&dialog.window).set_title("Import into WispKey");
                        let paths = if method == "choose_import_directory" { picker.pick_folder().map(|path| vec![path]) }
                            else { picker.pick_files() };
                        deliver(dialog, &id, &json!({"ok":true,"result":{"cancelled":paths.is_none(),"paths":paths.unwrap_or_default()}}));
                        dialog.window.set_focus();
                    }
                    "clipboard_import" => {
                        let result = clipboard_mut(&mut clipboard).and_then(|clipboard| clipboard.get_text()
                            .map(Zeroizing::new).map_err(|_| failure("clipboard_unavailable", "clipboard text is unavailable")));
                        match result {
                            Ok(content) => match clipboard_preview(&content, params) {
                                Ok(preview) => {
                                    clear_json(&mut request);
                                    request = json!({"id": id, "method":"import_preview", "params":preview});
                                    if !queue(&jobs, window_id, request, false) { deliver(dialog, &id, &failure("busy", "desktop is busy; try again")); }
                                }
                                Err(error) => deliver(dialog, &id, &error),
                            },
                            Err(error) => deliver(dialog, &id, &error),
                        }
                    }
                    "copy_token" => {
                        request["method"] = json!("get_token");
                        if !queue(&jobs, window_id, request, true) { deliver(dialog, &id, &failure("busy", "desktop is busy; try again")); }
                    }
                    method if owner_method_allowed(method) => {
                        if !queue(&jobs, window_id, request, false) { deliver(dialog, &id, &failure("busy", "desktop is busy; try again")); }
                    }
                    _ => deliver(dialog, &id, &failure("invalid_input", "desktop action is unavailable")),
                }
            }
            Event::UserEvent(UserEvent::Response { window_id, id, mut response, copy_token }) => {
                if response["result"]["session_active"].is_boolean() {
                    let text = if response["result"]["session_active"] == true { "WispKey — unlocked" } else { "WispKey — locked" };
                    let _ = tray.set_tooltip(Some(text));
                }
                if let Some(dialog) = popout.as_ref().filter(|dialog| dialog.window.id() == window_id) {
                    if copy_token && response["ok"] == true {
                        let copied = response["result"]["token"].as_str()
                            .filter(|token| token.starts_with("wk_"))
                            .ok_or_else(|| failure("invalid_response", "credential token is unavailable"))
                            .and_then(|token| clipboard_mut(&mut clipboard)?.set_text(token.to_owned())
                                .map_err(|_| failure("clipboard_unavailable", "could not copy the token")));
                        clear_json(&mut response);
                        response = copied.map_or_else(|error| error, |_| json!({"ok":true,"result":{"copied":true}}));
                    }
                    deliver(dialog, &id, &response);
                }
                clear_json(&mut response);
            }
            Event::UserEvent(UserEvent::Files { window_id, paths }) => {
                if let Some(dialog) = popout.as_ref().filter(|dialog| dialog.window.id() == window_id)
                    && let Ok(paths) = serde_json::to_string(&paths) {
                    let _ = dialog.webview.evaluate_script(&format!("window.__wispkeyFiles?.({paths});"));
                }
            }
            Event::UserEvent(UserEvent::Drag { window_id, active }) => {
                if let Some(dialog) = popout.as_ref().filter(|dialog| dialog.window.id() == window_id) {
                    let _ = dialog.webview.evaluate_script(&format!("window.__wispkeyDrag?.({active});"));
                }
            }
            Event::WindowEvent { window_id, event, .. } => {
                if let Some(dialog) = popout.as_mut().filter(|dialog| dialog.window.id() == window_id) {
                    match event {
                        WindowEvent::CloseRequested => dismiss(&mut popout, &jobs),
                        WindowEvent::Focused(true) => dialog.returning_from_picker = false,
                        WindowEvent::Focused(false) if !dialog.returning_from_picker => {
                            let _ = dialog.webview.evaluate_script("window.__wispkeyBlur?.();");
                            queue(&jobs, window_id, json!({"id":"blur", "method":"import_cancel"}), false);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    });
}

#[cfg(target_os = "macos")]
fn macos_application_menu() -> Menu {
    use tray_icon::menu::{PredefinedMenuItem, Submenu};
    let edit = Submenu::with_items(
        "Edit",
        true,
        &[
            &PredefinedMenuItem::cut(None),
            &PredefinedMenuItem::copy(None),
            &PredefinedMenuItem::paste(None),
            &PredefinedMenuItem::select_all(None),
        ],
    )
    .expect("native Edit menu");
    let menu = Menu::with_items(&[&edit]).expect("application menu");
    menu.init_for_nsapp();
    menu
}

fn open_popout(
    target: &EventLoopWindowTarget<UserEvent>,
    proxy: &EventLoopProxy<UserEvent>,
    anchor: Option<Anchor>,
) -> Option<Popout> {
    let window = WindowBuilder::new()
        .with_title("WispKey")
        .with_decorations(false)
        .with_transparent(true)
        .with_always_on_top(true)
        .with_resizable(false)
        .with_visible(false)
        .with_inner_size(LogicalSize::new(WIDTH, MIN_HEIGHT))
        .build(target)
        .ok()?;
    #[cfg(target_os = "windows")]
    {
        use tao::platform::windows::WindowExtWindows;
        let _ = window.set_skip_taskbar(true);
    }
    #[cfg(target_os = "linux")]
    {
        use tao::platform::unix::WindowExtUnix;
        let _ = window.set_skip_taskbar(true);
    }
    let window_id = window.id();
    let ipc_proxy = proxy.clone();
    let drop_proxy = proxy.clone();
    let html = UI_HTML.replace("\"WISPKEY_INITIAL_VIEW\"", "\"intake\"");
    let webview = WebViewBuilder::new()
        .with_html(&html)
        .with_devtools(false)
        .with_transparent(true)
        .with_background_color((0, 0, 0, 0))
        .with_incognito(true)
        .with_navigation_handler(|url| url == "about:blank")
        .with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
        .with_download_started_handler(|_, _| false)
        .with_ipc_handler(move |message| {
            let _ = ipc_proxy.send_event(UserEvent::Request {
                window_id,
                body: message.into_body(),
            });
        })
        .with_drag_drop_handler(move |event| {
            match event {
                DragDropEvent::Drop { paths, .. } => {
                    let _ = drop_proxy.send_event(UserEvent::Drag {
                        window_id,
                        active: false,
                    });
                    let _ = drop_proxy.send_event(UserEvent::Files { window_id, paths });
                }
                DragDropEvent::Enter { .. } | DragDropEvent::Over { .. } => {
                    let _ = drop_proxy.send_event(UserEvent::Drag {
                        window_id,
                        active: true,
                    });
                }
                DragDropEvent::Leave => {
                    let _ = drop_proxy.send_event(UserEvent::Drag {
                        window_id,
                        active: false,
                    });
                }
                _ => {}
            }
            true
        })
        .build(&window)
        .ok()?;
    position_popout(&window, anchor);
    window.set_visible(true);
    window.set_focus();
    Some(Popout {
        webview,
        window,
        returning_from_picker: false,
    })
}

fn monitor_height(window: &Window) -> Option<f64> {
    window.current_monitor().map(|monitor| {
        (f64::from(monitor.size().height) / window.scale_factor() - 64.0).max(MIN_HEIGHT)
    })
}

fn position_popout(window: &Window, anchor: Option<Anchor>) {
    let monitor = anchor
        .and_then(|anchor| {
            window.available_monitors().find(|monitor| {
                let position = monitor.position();
                let size = monitor.size();
                anchor.x >= f64::from(position.x)
                    && anchor.x < f64::from(position.x) + f64::from(size.width)
                    && anchor.y >= f64::from(position.y)
                    && anchor.y < f64::from(position.y) + f64::from(size.height)
            })
        })
        .or_else(|| window.current_monitor());
    let Some(monitor) = monitor else {
        return;
    };
    let origin = monitor.position();
    let size = monitor.size();
    let scale = monitor.scale_factor();
    let window_size = window.outer_size();
    let anchor = anchor.unwrap_or(Anchor {
        x: f64::from(origin.x) + f64::from(size.width) - WIDTH * scale,
        y: f64::from(origin.y) + 32.0 * scale,
        width: WIDTH * scale,
        height: 0.0,
    });
    let (x, y) = popout_position(
        anchor,
        (
            f64::from(origin.x),
            f64::from(origin.y),
            f64::from(size.width),
            f64::from(size.height),
        ),
        (f64::from(window_size.width), f64::from(window_size.height)),
        8.0 * scale,
    );
    window.set_outer_position(PhysicalPosition::new(x, y));
}

fn popout_position(
    anchor: Anchor,
    monitor: (f64, f64, f64, f64),
    size: (f64, f64),
    gap: f64,
) -> (f64, f64) {
    let (left, top, width, height) = monitor;
    let x = (anchor.x + anchor.width - size.0)
        .clamp(left + gap, (left + width - size.0 - gap).max(left + gap));
    let y = if anchor.y < top + height / 2.0 {
        anchor.y + anchor.height + gap
    } else {
        anchor.y - size.1 - gap
    };
    (
        x,
        y.clamp(top + gap, (top + height - size.1 - gap).max(top + gap)),
    )
}

fn dismiss(popout: &mut Option<Popout>, jobs: &SyncSender<OwnerJob>) {
    if let Some(dialog) = popout.take() {
        queue(
            jobs,
            dialog.window.id(),
            json!({"id":"dismiss", "method":"import_cancel"}),
            false,
        );
    }
}

fn owner_worker(proxy: EventLoopProxy<UserEvent>) -> SyncSender<OwnerJob> {
    let (sender, receiver) = mpsc::sync_channel::<OwnerJob>(16);
    std::thread::spawn(move || {
        for job in receiver {
            let id = job.request.get("id").cloned().unwrap_or(Value::Null);
            let response = call_owner(job.request);
            if proxy
                .send_event(UserEvent::Response {
                    window_id: job.window_id,
                    id,
                    response,
                    copy_token: job.copy_token,
                })
                .is_err()
            {
                break;
            }
        }
    });
    sender
}

fn queue(
    jobs: &SyncSender<OwnerJob>,
    window_id: WindowId,
    request: Value,
    copy_token: bool,
) -> bool {
    match jobs.try_send(OwnerJob {
        window_id,
        request,
        copy_token,
    }) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(mut job) | mpsc::TrySendError::Disconnected(mut job)) => {
            clear_json(&mut job.request);
            false
        }
    }
}

fn clipboard_mut(
    clipboard: &mut Option<arboard::Clipboard>,
) -> Result<&mut arboard::Clipboard, Value> {
    if clipboard.is_none() {
        *clipboard = Some(
            arboard::Clipboard::new()
                .map_err(|_| failure("clipboard_unavailable", "clipboard is unavailable"))?,
        );
    }
    clipboard
        .as_mut()
        .ok_or_else(|| failure("clipboard_unavailable", "clipboard is unavailable"))
}

fn clipboard_preview(content: &str, params: &Value) -> Result<Value, Value> {
    if content.trim().is_empty() {
        return Err(failure("invalid_input", "clipboard is empty"));
    }
    if content.len() > 1024 * 1024 {
        return Err(failure(
            "limit_exceeded",
            "clipboard exceeds the import limit",
        ));
    }
    let format = if content.trim_start().starts_with('{') {
        "json"
    } else if content.lines().any(|line| {
        line.trim_start()
            .split_once('=')
            .is_some_and(|(key, value)| {
                let key = key
                    .trim()
                    .strip_prefix("export ")
                    .unwrap_or(key.trim())
                    .trim();
                !key.is_empty()
                    && !value.is_empty()
                    && !value.starts_with('=')
                    && key.bytes().enumerate().all(|(index, ch)| {
                        ch == b'_' || ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit())
                    })
            })
    }) {
        "env"
    } else {
        "secret"
    };
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty());
    if format == "secret" && name.is_none() {
        return Err(failure("clipboard_name_required", "Name this credential"));
    }
    Ok(
        json!({"source":{"kind":"clipboard", "content":content, "format":format, "name":name}, "project":params.get("project"), "environment":params.get("environment")}),
    )
}

fn owner_method_allowed(method: &str) -> bool {
    matches!(
        method,
        "status"
            | "initialize"
            | "unlock"
            | "lock"
            | "list_credentials"
            | "list_projects"
            | "list_partitions"
            | "create_project"
            | "create_partition"
            | "add_credential"
            | "add_template"
            | "generate_login"
            | "rotate_credential"
            | "remove_credential"
            | "import_preview"
            | "import_review"
            | "import_commit"
            | "import_cancel"
            | "get_settings"
            | "set_settings"
    )
}

fn deliver(dialog: &Popout, id: &Value, response: &Value) {
    let script = format!("window.__wispkeyResolve?.({id},{response});");
    if dialog.webview.evaluate_script(&script).is_err() {
        tracing::error!("could not deliver owner response");
    }
}

fn failure(code: &str, message: &str) -> Value {
    json!({"ok":false,"error":{"code":code,"message":message}})
}

fn clear_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(clear_json),
        Value::Object(fields) => fields.values_mut().for_each(clear_json),
        _ => {}
    }
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

fn wait_for_owner_endpoint() -> bool {
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

fn tray_icon_image() -> Icon {
    let mut rgba = vec![0u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let ring = (x as i32 - 11).pow(2) + (y as i32 - 11).pow(2);
            if (30..=75).contains(&ring)
                || ((12..26).contains(&x) && (12..16).contains(&y))
                || ((20..24).contains(&x) && (15..21).contains(&y))
            {
                rgba[(y * 32 + x) * 4..(y * 32 + x) * 4 + 4].copy_from_slice(&[243, 243, 246, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, 32, 32).expect("tray icon")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_placement_keeps_top_and_bottom_popouts_on_the_selected_monitor() {
        let monitor = (-1920.0, 0.0, 1920.0, 1080.0);
        let top = popout_position(
            Anchor {
                x: -40.0,
                y: 0.0,
                width: 24.0,
                height: 24.0,
            },
            monitor,
            (460.0, 600.0),
            8.0,
        );
        assert_eq!(top, (-468.0, 32.0));
        let bottom = popout_position(
            Anchor {
                x: -1900.0,
                y: 1050.0,
                width: 24.0,
                height: 24.0,
            },
            monitor,
            (460.0, 600.0),
            8.0,
        );
        assert_eq!(bottom, (-1912.0, 442.0));
    }

    #[test]
    fn clipboard_preview_requires_a_name_for_one_value_and_never_guesses_a_secret_as_env() {
        let value = "fixture-value==";
        assert_eq!(
            clipboard_preview(value, &json!({"project":"default"})).unwrap_err()["error"]["code"],
            "clipboard_name_required"
        );
        let preview = clipboard_preview(
            value,
            &json!({"project":"default","name":"clipboard-fixture"}),
        )
        .unwrap();
        assert_eq!(preview["source"]["format"], "secret");
        assert_eq!(preview["source"]["name"], "clipboard-fixture");
        assert_eq!(
            clipboard_preview("QUJDRA==", &json!({"project":"default"})).unwrap_err()["error"]["code"],
            "clipboard_name_required"
        );
        assert_eq!(
            clipboard_preview("FIXTURE_KEY=value", &json!({"project":"default"})).unwrap()["source"]
                ["format"],
            "env"
        );
        assert_eq!(
            clipboard_preview("{\"FIXTURE_KEY\":\"value\"}", &json!({"project":"default"}))
                .unwrap()["source"]["format"],
            "json"
        );
    }

    #[test]
    fn renderer_cannot_call_raw_token_or_server_shutdown_methods() {
        assert!(!owner_method_allowed("get_token"));
        assert!(!owner_method_allowed("shutdown"));
        assert!(!owner_method_allowed("cloud_login"));
        assert!(owner_method_allowed("import_commit"));
    }
}
