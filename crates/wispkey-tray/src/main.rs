/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: Optional local desktop popout; the CLI owns vault operations.
 * Created: 2026-08-25
 * Last Modified: 2026-11-05
 */

mod bridge;
mod owner_client;
mod popout;

use std::path::PathBuf;

use serde_json::Value;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::{Window, WindowBuilder, WindowId};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use zeroize::Zeroizing;

use bridge::RendererBridge;
use owner_client::{OwnerClient, wait_for_owner_endpoint};
#[cfg(target_os = "macos")]
use popout::macos_application_menu;
use popout::{Anchor, Popout, dismiss, open_popout, tray_icon_image};

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
        activity: u64,
    },
    MenuLock(Value),
    Files {
        window_id: WindowId,
        paths: Vec<PathBuf>,
    },
    Drag {
        window_id: WindowId,
        active: bool,
    },
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
    let owner = OwnerClient::start(proxy.clone());
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
    let mut bridge = RendererBridge::default();
    let mut anchor = None;
    event_loop.run(move |event, target, control| {
        #[cfg(target_os = "macos")]
        let _application_menu = &application_menu;
        *control = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                keepalive = Some(
                    WindowBuilder::new()
                        .with_visible(false)
                        .with_title("WispKey")
                        .build(target)
                        .expect("keepalive window"),
                );
            }
            Event::UserEvent(UserEvent::Tray(TrayIconEvent::Click {
                rect,
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            })) => {
                anchor = Some(Anchor {
                    x: rect.position.x,
                    y: rect.position.y,
                    width: f64::from(rect.size.width),
                    height: f64::from(rect.size.height),
                });
                if popout.is_some() {
                    dismiss(&mut popout, &owner);
                } else {
                    popout = open_popout(target, &proxy, anchor);
                }
            }
            Event::UserEvent(UserEvent::Menu(id)) if id == open_id => {
                if popout.is_none() {
                    popout = open_popout(target, &proxy, anchor);
                }
                if let Some(dialog) = &popout {
                    dialog.focus();
                }
            }
            Event::UserEvent(UserEvent::Menu(id)) if id == lock_id => {
                dismiss(&mut popout, &owner);
                if let Some(window) = &keepalive
                    && !owner.lock(window.id())
                {
                    lock.set_text("Lock failed: desktop busy; retry");
                    let _ = tray.set_tooltip(Some("WispKey: lock failed; desktop busy"));
                }
            }
            Event::UserEvent(UserEvent::Menu(id)) if id == quit_id => {
                dismiss(&mut popout, &owner);
                bridge.release_clipboard();
                // Closing this GUI does not terminate a shared CLI-owned server.
                *control = ControlFlow::Exit;
            }
            Event::UserEvent(UserEvent::Request { window_id, body }) => {
                let body = Zeroizing::new(body);
                let Some(dialog) = popout.as_mut().filter(|dialog| dialog.id() == window_id) else {
                    return;
                };
                if bridge.handle_request(dialog, &owner, &body, anchor) {
                    dismiss(&mut popout, &owner);
                }
            }
            Event::UserEvent(UserEvent::MenuLock(response)) => {
                let succeeded =
                    response["ok"] == true && response["result"]["session_active"] == false;
                lock.set_text(if succeeded {
                    "Lock vault"
                } else {
                    "Lock failed; retry"
                });
                let _ = tray.set_tooltip(Some(if succeeded {
                    "WispKey: locked"
                } else {
                    "WispKey: lock failed; check the vault and retry"
                }));
            }
            Event::UserEvent(UserEvent::Response {
                window_id,
                id,
                response,
                copy_token,
                activity,
            }) => {
                if response["result"]["session_active"].is_boolean() {
                    let text = if response["result"]["session_active"] == true {
                        "WispKey — unlocked"
                    } else {
                        "WispKey — locked"
                    };
                    let _ = tray.set_tooltip(Some(text));
                }
                bridge.respond(
                    popout.as_ref().filter(|dialog| dialog.id() == window_id),
                    &id,
                    response,
                    copy_token,
                    activity,
                );
            }
            Event::UserEvent(UserEvent::Files { window_id, paths }) => {
                if let Some(dialog) = popout.as_ref().filter(|dialog| dialog.id() == window_id)
                    && let Ok(paths) = serde_json::to_string(&paths)
                {
                    dialog.evaluate_script(&format!("window.__wispkeyFiles?.({paths});"));
                }
            }
            Event::UserEvent(UserEvent::Drag { window_id, active }) => {
                if let Some(dialog) = popout.as_ref().filter(|dialog| dialog.id() == window_id) {
                    dialog.evaluate_script(&format!("window.__wispkeyDrag?.({active});"));
                }
            }
            Event::WindowEvent {
                window_id, event, ..
            } => {
                if let Some(dialog) = popout.as_mut().filter(|dialog| dialog.id() == window_id) {
                    match event {
                        WindowEvent::CloseRequested => dismiss(&mut popout, &owner),
                        WindowEvent::Focused(focused) => dialog.focus_changed(focused, &owner),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    });
}
