//! Native popout lifetime, geometry, file pickers and platform presentation.

use std::path::PathBuf;

use serde_json::json;
use tao::dpi::{LogicalSize, PhysicalPosition};
use tao::event_loop::{EventLoopProxy, EventLoopWindowTarget};
use tao::window::{Window, WindowBuilder, WindowId};
use tray_icon::Icon;
#[cfg(target_os = "macos")]
use tray_icon::menu::Menu;
use wry::{DragDropEvent, WebViewBuilder};

use crate::UserEvent;
use crate::owner_client::OwnerClient;

const UI_HTML: &str = include_str!("../ui-dist/index.html");
const WIDTH: f64 = 460.0;
const MIN_HEIGHT: f64 = 300.0;
const MAX_HEIGHT: f64 = 820.0;

pub(super) struct Popout {
    // Drop the webview before its native parent.
    webview: wry::WebView,
    window: Window,
    returning_from_picker: bool,
    activity: u64,
}

#[derive(Clone, Copy)]
pub(super) struct Anchor {
    pub(super) x: f64,
    pub(super) y: f64,
    pub(super) width: f64,
    pub(super) height: f64,
}

impl Popout {
    pub(super) fn id(&self) -> WindowId {
        self.window.id()
    }

    pub(super) fn activity(&self) -> u64 {
        self.activity
    }

    pub(super) fn focus(&self) {
        self.window.set_focus();
    }

    pub(super) fn resize(&self, height: f64, anchor: Option<Anchor>) {
        let height = height.clamp(MIN_HEIGHT, MAX_HEIGHT);
        let height = monitor_height(&self.window).map_or(height, |limit| height.min(limit));
        self.window.set_inner_size(LogicalSize::new(WIDTH, height));
        position_popout(&self.window, anchor);
    }

    pub(super) fn choose_import_paths(&mut self, directory: bool) -> Option<Vec<PathBuf>> {
        self.returning_from_picker = true;
        let picker = rfd::FileDialog::new()
            .set_parent(&self.window)
            .set_title("Import into WispKey");
        if directory {
            picker.pick_folder().map(|path| vec![path])
        } else {
            picker.pick_files()
        }
    }

    pub(super) fn focus_changed(&mut self, focused: bool, owner: &OwnerClient) {
        if focused {
            self.returning_from_picker = false;
        } else if !self.returning_from_picker {
            self.activity = self.activity.wrapping_add(1);
            self.evaluate_script("window.__wispkeyBlur?.();");
            owner.queue(
                self.id(),
                json!({"id":"blur", "method":"import_cancel"}),
                false,
                self.activity,
            );
        }
    }

    pub(super) fn evaluate_script(&self, script: &str) {
        if self.webview.evaluate_script(script).is_err() {
            tracing::error!("could not deliver desktop event");
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn macos_application_menu() -> Menu {
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

pub(super) fn open_popout(
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
        activity: 0,
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

pub(super) fn dismiss(popout: &mut Option<Popout>, owner: &OwnerClient) {
    if let Some(dialog) = popout.take() {
        owner.queue(
            dialog.id(),
            json!({"id":"dismiss", "method":"import_cancel"}),
            false,
            dialog.activity,
        );
    }
}

pub(super) fn tray_icon_image() -> Icon {
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
        assert_eq!(top, (-476.0, 32.0));
        let right_edge = popout_position(
            Anchor {
                x: -24.0,
                y: 0.0,
                width: 24.0,
                height: 24.0,
            },
            monitor,
            (460.0, 600.0),
            8.0,
        );
        assert_eq!(right_edge, (-468.0, 32.0));
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
}
