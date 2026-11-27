#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod analyzer;
mod app;
mod store;
mod theme;
mod visuals;

use app::BinviewApp;
use eframe::egui;
use std::sync::Arc;

/// Generates a crisp 64x64 monochrome geometric hex/Hilbert binary icon.
fn generate_app_icon() -> egui::IconData {
    let size = 64usize;
    let mut rgba = vec![0u8; size * size * 4];

    // 4x4 geometric binary/Hilbert architectural glyph
    let pattern: [[u8; 4]; 4] = [
        [1, 1, 0, 1],
        [1, 0, 0, 1],
        [0, 1, 1, 0],
        [1, 1, 1, 1],
    ];

    for y in 0..size {
        for x in 0..size {
            let idx = (y * size + x) * 4;
            let in_box = x >= 4 && x < 60 && y >= 4 && y < 60;
            if !in_box {
                continue;
            }
            let is_border = x == 4 || x == 59 || y == 4 || y == 59;
            let mut v = 8u8;
            if is_border {
                v = 242;
            } else if x >= 12 && x < 52 && y >= 12 && y < 52 {
                let gx = (x - 12) / 10;
                let gy = (y - 12) / 10;
                let lx = (x - 12) % 10;
                let ly = (y - 12) % 10;
                if gx < 4 && gy < 4 && lx >= 1 && lx <= 8 && ly >= 1 && ly <= 8 {
                    v = if pattern[gy][gx] == 1 { 248 } else { 26 };
                }
            }
            rgba[idx] = v;
            rgba[idx + 1] = v;
            rgba[idx + 2] = v;
            rgba[idx + 3] = 255;
        }
    }

    egui::IconData {
        rgba,
        width: size as u32,
        height: size as u32,
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("BINVIEW")
            .with_decorations(false)
            .with_inner_size([1360.0, 840.0])
            .with_min_inner_size([1040.0, 680.0])
            .with_icon(Arc::new(generate_app_icon())),
        ..Default::default()
    };

    eframe::run_native(
        "BINVIEW",
        options,
        Box::new(|cc| Ok(Box::new(BinviewApp::new(cc)))),
    )
}
