#![windows_subsystem = "windows"]

//! AIVPN Windows GUI Application
//!
//! Native Windows app using egui/eframe with system tray support.
//! Manages aivpn-client.exe as a subprocess — no console window visible.

mod vpn_manager;
mod key_storage;
mod localization;
mod tray;
mod ui;

use eframe::egui;
use key_storage::KeyStorage;
use localization::Lang;
use vpn_manager::VpnManager;
use std::fs;
use std::path::PathBuf;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const WINDOW_WIDTH: f32 = 360.0;
const WINDOW_HEIGHT: f32 = 480.0;

fn main() -> eframe::Result<()> {
    let log_path = startup_log_path();
    write_startup_log(&log_path, "startup: entered main");
    write_startup_log(&log_path, "startup: using wgpu renderer path");

    // Embed app icon directly into the binary — no external file needed
    let icon = {
        let png_bytes = include_bytes!("../assets/aivpn_preview.png");
        match image::load_from_memory_with_format(png_bytes, image::ImageFormat::Png) {
            Ok(img) => {
                let rgba = img.to_rgba8();
                let (w, h) = rgba.dimensions();
                Some(Box::new(egui::IconData {
                    rgba: rgba.into_raw(),
                    width: w,
                    height: h,
                }))
            }
            Err(e) => {
                eprintln!("Icon decode error: {}", e);
                None
            }
        }
    };

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([WINDOW_WIDTH, WINDOW_HEIGHT])
        .with_min_inner_size([WINDOW_WIDTH, WINDOW_HEIGHT])
        .with_max_inner_size([WINDOW_WIDTH, WINDOW_HEIGHT])
        .with_resizable(false)
        .with_decorations(true)
        .with_transparent(false)
        .with_title("AIVPN");
    
    if let Some(icon_data) = icon {
        viewport = viewport.with_icon(icon_data);
    }

    let options = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: egui_wgpu::WgpuConfiguration {
            wgpu_setup: egui_wgpu::WgpuSetup::CreateNew(egui_wgpu::WgpuSetupCreateNew {
                instance_descriptor: wgpu::InstanceDescriptor {
                    backends: wgpu::Backends::DX12 | wgpu::Backends::VULKAN | wgpu::Backends::GL,
                    flags: wgpu::InstanceFlags::from_env_or_default()
                        .union(wgpu::InstanceFlags::ALLOW_UNDERLYING_NONCOMPLIANT_ADAPTER),
                    ..Default::default()
                },
                native_adapter_selector: Some(std::sync::Arc::new(
                    |adapters: &[wgpu::Adapter], _surface| -> Result<wgpu::Adapter, String> {
                        // Prefer hardware, fall back to software (WARP)
                        for adapter in adapters {
                            let info = adapter.get_info();
                            if info.device_type != wgpu::DeviceType::Cpu {
                                return Ok(adapter.clone());
                            }
                        }
                        // Accept any adapter including software
                        adapters.first().cloned().ok_or_else(|| "No adapters found".to_string())
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        },
        ..Default::default()
    };

    let result = eframe::run_native(
        "AIVPN",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(dark_visuals());
            Ok(Box::new(AivpnApp::new()))
        }),
    );

    match &result {
        Ok(()) => write_startup_log(&log_path, "startup: run_native returned ok"),
        Err(err) => write_startup_log(&log_path, &format!("startup error: {err}")),
    }

    result
}

fn startup_log_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("AIVPN")
        .join("startup.log")
}

fn write_startup_log(path: &PathBuf, message: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let line = format!("{}\r\n", message);
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()));
}

fn dark_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();
    visuals.window_corner_radius = egui::CornerRadius::same(8);
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(30, 30, 35);
    visuals.panel_fill = egui::Color32::from_rgb(25, 25, 30);
    visuals
}

/// Main application state
pub struct AivpnApp {
    vpn: VpnManager,
    keys: KeyStorage,
    lang: Lang,
    // UI state
    show_add_key: bool,
    new_key_name: String,
    new_key_value: String,
    new_key_full_tunnel: bool,
    editing_key_idx: Option<usize>,
    error_message: Option<String>,
    error_timer: Option<std::time::Instant>,
    // Recording UI state
    recording_service_name: String,
}

impl AivpnApp {
    fn new() -> Self {
        let keys = KeyStorage::load();
        Self {
            vpn: VpnManager::new(),
            keys,
            lang: Lang::load(),
            show_add_key: false,
            new_key_name: String::new(),
            new_key_value: String::new(),
            new_key_full_tunnel: false,
            editing_key_idx: None,
            error_message: None,
            error_timer: None,
            recording_service_name: String::new(),
        }
    }

    fn set_error(&mut self, msg: String) {
        self.error_message = Some(msg);
        self.error_timer = Some(std::time::Instant::now());
    }

    fn clear_old_error(&mut self) {
        if let Some(timer) = self.error_timer {
            if timer.elapsed() > std::time::Duration::from_secs(8) {
                self.error_message = None;
                self.error_timer = None;
            }
        }
    }
}

impl eframe::App for AivpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.clear_old_error();
        self.vpn.poll_status();

        // Request repaint every second for live stats
        ctx.request_repaint_after(std::time::Duration::from_secs(1));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui::draw_main_ui(ui, self);
        });
    }
}
