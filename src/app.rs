use crate::analyzer::{
    analyze_file, compare_binaries, format_bytes, format_bytes_compact, search_binary,
    BinaryAnalysis, BinaryDiff, SearchMode, SearchOutcome,
};
use crate::store::{mask_path_display, PersistedStore, VizMode};
use crate::theme::{
    action_btn, apply_fonts, apply_theme, blend, catalog_row, paint_dot_field, rule, stamp,
    typo_switch, with_alpha, FontPreset, Palette,
};
use crate::visuals::{
    draw_binary_plate, format_safety_blocks, generate_binary_svg, PlateAction,
};
use egui::{
    Align, Align2, FontId, Key, Layout, Pos2, Rect, RichText, Rounding, ScrollArea, Sense, Stroke,
    TextEdit, Vec2, ViewportCommand,
};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectorTab {
    Overview,
    Hex,
    Strings,
    Compare,
}

impl InspectorTab {
    fn label(&self) -> &'static str {
        match self {
            Self::Overview => "OVERVIEW",
            Self::Hex => "HEX",
            Self::Strings => "STRINGS",
            Self::Compare => "COMPARE",
        }
    }

    fn all() -> &'static [InspectorTab] {
        &[Self::Overview, Self::Hex, Self::Strings, Self::Compare]
    }
}

enum LoadTarget {
    Primary,
    Compare,
}

struct LoadResult {
    target: LoadTarget,
    result: Result<BinaryAnalysis, String>,
}

pub struct BinviewApp {
    store: PersistedStore,
    tab: InspectorTab,
    settings_open: bool,

    // Primary & Compare binary analyses
    analysis: Option<BinaryAnalysis>,
    compare_analysis: Option<BinaryAnalysis>,
    diff: Option<BinaryDiff>,
    loading_rx: Option<Receiver<LoadResult>>,
    loading_label: Option<String>,

    // Reveal animation & telemetry
    reveal_start: Instant,
    hover_telemetry: Option<String>,
    toast: Option<(String, Instant)>,

    // HEX view state
    hex_cursor_offset: Option<usize>,
    hex_highlight_len: usize,
    hex_jump_input: String,
    hex_scroll_to_y: Option<f32>,
    hex_search_input: String,
    hex_search_mode: SearchMode,
    hex_search_outcome: Option<SearchOutcome>,
    hex_search_index: usize,
    selected_digraph_cell: Option<(usize, usize)>,

    // STRINGS view state
    strings_filter: String,
}

impl BinviewApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let store = PersistedStore::load();
        apply_fonts(&cc.egui_ctx, store.settings.font_preset());
        apply_theme(&cc.egui_ctx, store.settings.theme_kind());

        let mut app = Self {
            store,
            tab: InspectorTab::Overview,
            settings_open: false,
            analysis: None,
            compare_analysis: None,
            diff: None,
            loading_rx: None,
            loading_label: None,
            reveal_start: Instant::now(),
            hover_telemetry: None,
            toast: None,
            hex_cursor_offset: Some(0),
            hex_highlight_len: 1,
            hex_jump_input: "0x00000000".into(),
            hex_scroll_to_y: None,
            hex_search_input: String::new(),
            hex_search_mode: SearchMode::Auto,
            hex_search_outcome: None,
            hex_search_index: 0,
            selected_digraph_cell: None,
            strings_filter: String::new(),
        };

        // Automatically self-inspect binview.exe on launch!
        if let Ok(exe_path) = std::env::current_exe() {
            app.start_load_file(&cc.egui_ctx, exe_path, LoadTarget::Primary);
        }

        app
    }

    fn trigger_reveal(&mut self) {
        self.reveal_start = Instant::now();
    }

    fn notify(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    fn copy_with_toast(&mut self, ctx: &egui::Context, text: &str, label: &str) {
        ctx.copy_text(text.to_string());
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(text.to_string());
        }
        self.notify(format!("COPIED  ·  {}", label));
    }

    fn start_load_file(&mut self, ctx: &egui::Context, path: PathBuf, target: LoadTarget) {
        let min_len = self.store.settings.sanitized_min_string_len();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "FILE".into());
        let (tx, rx) = mpsc::channel();
        let repaint = ctx.clone();

        self.loading_rx = Some(rx);
        self.loading_label = Some(match target {
            LoadTarget::Primary => format!("ANALYZING {}", name),
            LoadTarget::Compare => format!("DIFFING {}", name),
        });

        thread::spawn(move || {
            let res = analyze_file(&path, min_len);
            let _ = tx.send(LoadResult {
                target,
                result: res,
            });
            repaint.request_repaint();
        });
    }

    fn poll_loader(&mut self) {
        let Some(rx) = &self.loading_rx else {
            return;
        };
        if let Ok(msg) = rx.try_recv() {
            self.loading_rx = None;
            self.loading_label = None;
            match msg.result {
                Ok(a) => match msg.target {
                    LoadTarget::Primary => {
                        let summary = format!(
                            "{}  ·  {}  ·  {}ms",
                            a.format.format_short,
                            format_bytes_compact(a.size),
                            a.analyzed_ms
                        );
                        self.analysis = Some(a);
                        self.hex_cursor_offset = Some(0);
                        self.hex_highlight_len = 1;
                        self.hex_jump_input = "0x00000000".into();
                        self.hex_scroll_to_y = Some(0.0);
                        self.hex_search_outcome = None;
                        self.hex_search_index = 0;
                        self.selected_digraph_cell = None;
                        if let (Some(prim), Some(comp)) = (&self.analysis, &self.compare_analysis) {
                            self.diff = Some(compare_binaries(prim, comp));
                        }
                        self.trigger_reveal();
                        self.notify(summary);
                    }
                    LoadTarget::Compare => {
                        let other_name = a.file_name.clone();
                        self.compare_analysis = Some(a);
                        if let (Some(prim), Some(comp)) = (&self.analysis, &self.compare_analysis) {
                            self.diff = Some(compare_binaries(prim, comp));
                        }
                        self.tab = InspectorTab::Compare;
                        self.notify(format!("COMPARED  ·  {}", other_name));
                    }
                },
                Err(e) => {
                    self.notify(e);
                }
            }
        }
    }

    fn jump_hex_to(&mut self, offset: usize, highlight_len: usize, switch_tab: bool) {
        let Some(a) = &self.analysis else {
            return;
        };
        if a.size == 0 {
            return;
        }
        let clamped = offset.min(a.size - 1);
        let cols = self.store.settings.sanitized_hex_cols();
        let row = clamped / cols;
        let row_h = 20.0_f32;
        self.hex_cursor_offset = Some(clamped);
        self.hex_highlight_len = highlight_len.max(1);
        self.hex_jump_input = format!("0x{:08X}", clamped);
        self.hex_scroll_to_y = Some((row.saturating_sub(3) as f32) * row_h);
        if switch_tab {
            self.tab = InspectorTab::Hex;
        }
    }

    fn run_hex_search(&mut self) {
        let Some(a) = &self.analysis else {
            return;
        };
        match search_binary(&a.bytes, &self.hex_search_input, self.hex_search_mode, 4096) {
            Ok(outcome) => {
                let count = outcome.offsets.len();
                let first = outcome.offsets.first().copied();
                let pat_len = outcome.pattern.len();
                let kind = outcome.interpreted_as;
                self.hex_search_outcome = Some(outcome);
                self.hex_search_index = 0;
                if let Some(off) = first {
                    self.jump_hex_to(off, pat_len, true);
                    self.notify(format!("FOUND {} {} MATCHES", count, kind));
                } else {
                    self.notify(format!("0 {} MATCHES", kind));
                }
            }
            Err(e) => {
                self.hex_search_outcome = None;
                self.notify(e);
            }
        }
    }

    fn save_svg_poster(&mut self) {
        let Some(a) = &self.analysis else {
            return;
        };
        let mode = self.store.settings.viz_mode();
        let default_name = format!(
            "{}-{}.svg",
            a.file_name.replace('.', "_"),
            mode.cutout_tag().to_lowercase()
        );
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(&default_name)
            .add_filter("SVG Vector Poster", &["svg"])
            .save_file()
        else {
            return;
        };
        let svg = generate_binary_svg(
            a,
            mode,
            self.store.settings.show_trail,
            self.store.settings.dark_mode,
            self.store.settings.font_preset().svg_stack(),
        );
        match std::fs::write(&path, svg) {
            Ok(_) => self.notify(format!("SAVED SVG  ·  {}", path.display())),
            Err(e) => self.notify(format!("SVG ERROR  ·  {}", e)),
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<_> = ctx.input(|i| i.raw.dropped_files.clone());
        for file in dropped {
            if let Some(path) = file.path {
                if path.is_file() {
                    let target = if self.tab == InspectorTab::Compare && self.analysis.is_some() {
                        LoadTarget::Compare
                    } else {
                        LoadTarget::Primary
                    };
                    self.start_load_file(ctx, path, target);
                    break;
                }
            }
        }
    }

    fn handle_borderless_resize(ctx: &egui::Context) {
        let screen = ctx.screen_rect();
        let edge = 6.0_f32;
        if let Some(pos) = ctx.input(|i| i.pointer.hover_pos()) {
            let left = pos.x <= screen.min.x + edge;
            let right = pos.x >= screen.max.x - edge;
            let top = pos.y <= screen.min.y + edge;
            let bottom = pos.y >= screen.max.y - edge;

            let dir = match (left, right, top, bottom) {
                (true, _, true, _) => Some(egui::ResizeDirection::NorthWest),
                (_, true, true, _) => Some(egui::ResizeDirection::NorthEast),
                (true, _, _, true) => Some(egui::ResizeDirection::SouthWest),
                (_, true, _, true) => Some(egui::ResizeDirection::SouthEast),
                (true, _, _, _) => Some(egui::ResizeDirection::West),
                (_, true, _, _) => Some(egui::ResizeDirection::East),
                (_, _, true, _) => Some(egui::ResizeDirection::North),
                (_, _, _, true) => Some(egui::ResizeDirection::South),
                _ => None,
            };

            if let Some(d) = dir {
                let cursor = match d {
                    egui::ResizeDirection::North | egui::ResizeDirection::South => {
                        egui::CursorIcon::ResizeVertical
                    }
                    egui::ResizeDirection::East | egui::ResizeDirection::West => {
                        egui::CursorIcon::ResizeHorizontal
                    }
                    egui::ResizeDirection::NorthWest | egui::ResizeDirection::SouthEast => {
                        egui::CursorIcon::ResizeNwSe
                    }
                    egui::ResizeDirection::NorthEast | egui::ResizeDirection::SouthWest => {
                        egui::CursorIcon::ResizeNeSw
                    }
                };
                ctx.set_cursor_icon(cursor);
                if ctx.input(|i| i.pointer.primary_pressed()) {
                    ctx.send_viewport_cmd(ViewportCommand::BeginResize(d));
                }
            }
        }
    }
}

impl eframe::App for BinviewApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        Self::handle_borderless_resize(ctx);
        self.handle_dropped_files(ctx);
        self.poll_loader();

        // Shortcuts: Ctrl+, toggles Settings, Esc closes Settings
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::Comma)) {
            self.settings_open = !self.settings_open;
        }
        if self.settings_open && ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.settings_open = false;
        }

        let reveal = (self.reveal_start.elapsed().as_secs_f32() / 0.46).clamp(0.0, 1.0);
        if reveal < 1.0 || self.loading_rx.is_some() {
            ctx.request_repaint();
        } else {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        if let Some((_, at)) = &self.toast {
            if at.elapsed() > Duration::from_secs(3) {
                self.toast = None;
            }
        }

        let p = self.store.settings.theme_kind().palette();
        self.hover_telemetry = None;

        // 1. Custom 48px Borderless Titlebar
        egui::TopBottomPanel::top("binview_titlebar")
            .exact_height(48.0)
            .frame(
                egui::Frame::none()
                    .fill(p.surface)
                    .stroke(Stroke::new(1.0_f32, p.hairline))
                    .inner_margin(egui::Margin::symmetric(20.0, 0.0)),
            )
            .show(ctx, |ui| {
                self.render_titlebar(ui, ctx, &p);
            });

        // 2. Ultra-Slim 28px Telemetry Footer Rail
        egui::TopBottomPanel::bottom("binview_status_rail")
            .exact_height(28.0)
            .frame(
                egui::Frame::none()
                    .fill(p.surface)
                    .stroke(Stroke::new(1.0_f32, p.hairline))
                    .inner_margin(egui::Margin::symmetric(20.0, 0.0)),
            )
            .show(ctx, |ui| {
                self.render_status_rail(ui, &p);
            });

        // 3. Asymmetric 58.5% / 41.5% Exhibition Split
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(p.canvas))
            .show(ctx, |ui| {
                let full_rect = ui.available_rect_before_wrap();
                let split_x = (full_rect.min.x + full_rect.width() * 0.585).round();

                let stage_rect =
                    Rect::from_min_max(full_rect.min, Pos2::new(split_x, full_rect.max.y));
                let inspector_rect = Rect::from_min_max(
                    Pos2::new(split_x + 1.0, full_rect.min.y),
                    full_rect.max,
                );

                paint_dot_field(ui.painter(), stage_rect, 26.0, &p);
                ui.painter()
                    .rect_filled(inspector_rect, Rounding::ZERO, p.surface);
                ui.painter().line_segment(
                    [
                        Pos2::new(split_x, full_rect.min.y),
                        Pos2::new(split_x, full_rect.max.y),
                    ],
                    Stroke::new(1.0_f32, p.hairline),
                );

                // Left Exhibition Stage
                let mut stage_ui = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(stage_rect.shrink2(Vec2::new(30.0, 20.0)))
                        .layout(Layout::top_down(Align::LEFT)),
                );
                self.render_exhibition_stage(&mut stage_ui, ctx, &p, reveal);

                // Right Editorial Inspector
                let mut insp_ui = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(inspector_rect.shrink2(Vec2::new(22.0, 18.0)))
                        .layout(Layout::top_down(Align::LEFT)),
                );
                self.render_inspector(&mut insp_ui, ctx, &p);

                // 1px outer frame around borderless window
                let screen = ctx.screen_rect();
                ctx.layer_painter(egui::LayerId::new(
                    egui::Order::Foreground,
                    egui::Id::new("window_frame"),
                ))
                .rect_stroke(screen, Rounding::ZERO, Stroke::new(1.0_f32, p.hairline));
            });

        // 4. Settings Modal Overlay
        if self.settings_open {
            self.render_settings_modal(ctx, &p);
        }

        // 5. Minimal Floating Monochrome Toast
        if let Some((msg, _)) = &self.toast {
            let screen = ctx.screen_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("toast_layer"),
            ));
            let font = FontId::monospace(10.5);
            let galley = painter.layout_no_wrap(msg.clone(), font.clone(), p.invert_fg);
            let box_rect = Rect::from_min_size(
                Pos2::new(24.0, screen.max.y - 66.0),
                Vec2::new(galley.size().x + 24.0, 26.0),
            );
            painter.rect_filled(box_rect, Rounding::same(2.0), p.invert_bg);
            painter.text(box_rect.center(), Align2::CENTER_CENTER, msg, font, p.invert_fg);
        }

        // 6. Monochrome Drag & Drop Overlay
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let screen = ctx.screen_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop_overlay"),
            ));
            painter.rect_filled(screen, Rounding::ZERO, with_alpha(p.canvas, 232));
            painter.rect_stroke(
                screen.shrink(28.0),
                Rounding::ZERO,
                Stroke::new(1.2_f32, p.ink),
            );
            let drop_msg = if self.tab == InspectorTab::Compare && self.analysis.is_some() {
                "[ DROP BINARY FILE B TO COMPARE ]"
            } else {
                "[ DROP ANY BINARY FILE TO ANALYZE ]"
            };
            painter.text(
                screen.center(),
                Align2::CENTER_CENTER,
                drop_msg,
                FontId::monospace(14.0),
                p.ink,
            );
        }
    }
}

impl BinviewApp {
    fn render_titlebar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: &Palette) {
        let bar_rect = ui.max_rect();
        let drag_resp = ui.interact(bar_rect, ui.id().with("title_drag"), Sense::click_and_drag());
        if drag_resp.drag_started_by(egui::PointerButton::Primary) {
            ctx.send_viewport_cmd(ViewportCommand::StartDrag);
        }
        if drag_resp.double_clicked() {
            let is_max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
            ctx.send_viewport_cmd(ViewportCommand::Maximized(!is_max));
        }

        ui.horizontal_centered(|ui| {
            // Minimal Geometric Brand Mark
            let (mr, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
            let mp = ui.painter_at(mr);
            mp.rect_stroke(mr, Rounding::ZERO, Stroke::new(1.0_f32, p.rule_strong));
            let bits = [1, 1, 0, 1, 0, 1, 1, 1, 1];
            for i in 0..9 {
                if bits[i] == 1 {
                    let gx = (i % 3) as f32;
                    let gy = (i / 3) as f32;
                    mp.rect_filled(
                        Rect::from_min_size(
                            Pos2::new(mr.min.x + 3.0 + gx * 4.0, mr.min.y + 3.0 + gy * 4.0),
                            Vec2::splat(2.5),
                        ),
                        Rounding::ZERO,
                        p.ink,
                    );
                }
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new("B I N V I E W")
                    .monospace()
                    .size(12.0)
                    .strong()
                    .color(p.ink),
            );

            ui.add_space(24.0);

            // 4 Architectural Inspector Tabs
            for &t in InspectorTab::all() {
                let active = self.tab == t;
                let text = match t {
                    InspectorTab::Strings => {
                        if let Some(a) = &self.analysis {
                            format!("STRINGS {:02}", a.strings.len().min(9999))
                        } else {
                            t.label().to_string()
                        }
                    }
                    InspectorTab::Compare if self.diff.is_some() => "COMPARE ●".to_string(),
                    _ => t.label().to_string(),
                };
                let tab_w = if t == InspectorTab::Strings { 108.0 } else { 94.0 };
                let (rect, resp) = ui.allocate_exact_size(Vec2::new(tab_w, 46.0), Sense::click());
                if resp.hovered() {
                    ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                let tp = ui.painter_at(rect);
                tp.text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    text,
                    FontId::monospace(10.0),
                    if active {
                        p.ink
                    } else if resp.hovered() {
                        p.ink_mid
                    } else {
                        p.ink_dim
                    },
                );
                if active {
                    tp.line_segment(
                        [
                            Pos2::new(rect.min.x + 12.0, rect.max.y - 1.0),
                            Pos2::new(rect.max.x - 12.0, rect.max.y - 1.0),
                        ],
                        Stroke::new(2.0_f32, p.ink),
                    );
                }
                if resp.clicked() {
                    self.tab = t;
                }
            }

            // Right Controls: + OPEN, SELF EXE, SETTINGS, Window Chrome
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if window_ctrl_btn(ui, "×", true, p) {
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
                let is_max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                if window_ctrl_btn(ui, if is_max { "❐" } else { "□" }, false, p) {
                    ctx.send_viewport_cmd(ViewportCommand::Maximized(!is_max));
                }
                if window_ctrl_btn(ui, "—", false, p) {
                    ctx.send_viewport_cmd(ViewportCommand::Minimized(true));
                }

                ui.add_space(10.0);
                let (sep, _) = ui.allocate_exact_size(Vec2::new(1.0, 16.0), Sense::hover());
                ui.painter().line_segment(
                    [sep.center_top(), sep.center_bottom()],
                    Stroke::new(1.0_f32, p.hairline),
                );
                ui.add_space(10.0);

                if typo_switch(ui, "SETTINGS", self.settings_open, p) {
                    self.settings_open = !self.settings_open;
                }
                ui.add_space(10.0);
                if typo_switch(ui, "SELF EXE", false, p) {
                    if let Ok(exe) = std::env::current_exe() {
                        self.start_load_file(ctx, exe, LoadTarget::Primary);
                    }
                }
                ui.add_space(10.0);
                if action_btn(ui, "+ OPEN FILE", false, p) {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.start_load_file(ctx, path, LoadTarget::Primary);
                    }
                }
            });
        });
    }

    fn render_status_rail(&self, ui: &mut egui::Ui, p: &Palette) {
        ui.horizontal_centered(|ui| {
            let left_str = if let Some(lbl) = &self.loading_label {
                format!("{}...", lbl)
            } else if let Some(a) = &self.analysis {
                format!(
                    "{}  ·  {}  ·  H {:.2} b/B  ·  {}",
                    a.format.format_short,
                    format_bytes_compact(a.size),
                    a.entropy,
                    self.store.settings.font_preset().label()
                )
            } else {
                format!("READY  ·  {}", self.store.settings.font_preset().label())
            };

            ui.label(RichText::new(left_str).monospace().size(9.5).color(p.ink_dim));

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(tel) = &self.hover_telemetry {
                    ui.label(RichText::new(tel).monospace().size(9.5).color(p.ink));
                } else {
                    ui.label(
                        RichText::new("DROP ANY BINARY  ·  CLICK PLATE TO INSPECT  ·  CTRL+, SETTINGS")
                            .monospace()
                            .size(9.5)
                            .color(p.ink_dim),
                    );
                }
            });
        });
    }

    fn render_exhibition_stage(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        p: &Palette,
        reveal: f32,
    ) {
        let Some(a) = self.analysis.clone() else {
            ui.vertical_centered(|ui| {
                ui.add_space((ui.available_height() * 0.36).max(60.0));
                let title = self
                    .loading_label
                    .clone()
                    .unwrap_or_else(|| "NO BINARY SPECIMEN LOADED".into());
                ui.label(RichText::new(title).monospace().size(13.0).color(p.ink));
                ui.add_space(12.0);
                if action_btn(ui, "+ OPEN FILE", true, p) {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.start_load_file(ctx, path, LoadTarget::Primary);
                    }
                }
            });
            return;
        };

        // Top Stage Editorial Header
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(
                    RichText::new(format!("SPECIMEN  ·  {}", a.format.format_long.to_uppercase()))
                        .monospace()
                        .size(9.5)
                        .color(p.ink_dim),
                );
                let title_disp: String = if a.file_name.chars().count() > 34 {
                    format!("{}…", a.file_name.chars().take(33).collect::<String>())
                } else {
                    a.file_name.clone()
                };
                ui.label(RichText::new(title_disp).size(22.0).strong().color(p.ink));
            });

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if action_btn(ui, "SAVE SVG", false, p) {
                    self.save_svg_poster();
                }
                ui.add_space(4.0);
                stamp(ui, a.entropy_class.label(), false, p);
                ui.add_space(2.0);
                stamp(ui, &a.format.format_short, true, p);
            });
        });

        ui.add_space(14.0);

        // Center Gallery-Framed Exhibition Plate
        let mode = self.store.settings.viz_mode();
        let avail_w = ui.available_width();
        let avail_h = (ui.available_height() - 122.0).max(260.0);

        let mut plate_interaction = None;
        ui.vertical_centered(|ui| {
            let res = draw_binary_plate(
                ui,
                &a,
                mode,
                self.store.settings.show_trail,
                reveal,
                self.hex_cursor_offset,
                self.selected_digraph_cell,
                Vec2::new(avail_w, avail_h),
                p,
            );
            plate_interaction = Some(res);
        });

        if let Some(inter) = plate_interaction {
            self.hover_telemetry = inter.hover_telemetry;
            if let Some(action) = inter.action {
                match action {
                    PlateAction::JumpOffset { offset, reason } => {
                        self.jump_hex_to(offset, 1, true);
                        self.notify(format!("JUMP  ·  {}", reason));
                    }
                    PlateAction::SearchByte { byte } => {
                        self.hex_search_input = format!("{:02X}", byte);
                        self.hex_search_mode = SearchMode::Hex;
                        self.run_hex_search();
                    }
                    PlateAction::DigraphSelect {
                        bx,
                        by,
                        sample_offset,
                    } => {
                        self.selected_digraph_cell = Some((bx, by));
                        if let Some(off) = sample_offset {
                            self.jump_hex_to(off, 2, true);
                            self.notify(format!(
                                "BIGRAM ({:02X}..{:02X}, {:02X}..{:02X})  ·  0x{:08X}",
                                bx * 4,
                                bx * 4 + 3,
                                by * 4,
                                by * 4 + 3,
                                off
                            ));
                        } else {
                            self.notify("EMPTY BIGRAM CELL");
                        }
                    }
                }
            }
        }

        ui.add_space(10.0);

        // Minimal Typographic Mode Selector + Optional TRAIL toggle for Hilbert
        ui.horizontal(|ui| {
            for &m in VizMode::all() {
                if typo_switch(ui, m.label(), mode == m, p) && mode != m {
                    self.store.settings.set_viz_mode(m);
                    self.store.save();
                    self.trigger_reveal();
                }
                ui.add_space(10.0);
            }
            if mode == VizMode::Hilbert {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let tr = self.store.settings.show_trail;
                    if typo_switch(ui, if tr { "TRAIL ●" } else { "TRAIL ○" }, tr, p) {
                        self.store.settings.show_trail = !tr;
                        self.store.save();
                    }
                });
            }
        });

        ui.add_space(10.0);
        rule(ui, p);
        ui.add_space(10.0);

        // Footer: 4x8x2 Safety-Number SHA-256 Digest (click to copy) + Compact Metrics
        let (line1, line2) = format_safety_blocks(&a.sha256);
        let sha_resp = ui
            .horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(
                        RichText::new(&line1)
                            .monospace()
                            .size(11.5)
                            .color(p.ink),
                    );
                    ui.label(
                        RichText::new(&line2)
                            .monospace()
                            .size(11.5)
                            .color(p.ink_mid),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(
                            RichText::new(format!("H {:.2} / 8.00", a.entropy))
                                .monospace()
                                .size(10.5)
                                .color(p.ink),
                        );
                        ui.label(
                            RichText::new(format!(
                                "NUL {:.1}%  ·  ASC {:.1}%",
                                a.null_pct, a.ascii_pct
                            ))
                            .monospace()
                            .size(9.5)
                            .color(p.ink_dim),
                        );
                    });
                });
            })
            .response
            .interact(Sense::click());

        if sha_resp.hovered() {
            ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
        }
        if sha_resp.clicked() {
            self.copy_with_toast(ctx, &a.sha256, "SHA-256");
        }
    }

    fn render_inspector(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: &Palette) {
        match self.tab {
            InspectorTab::Overview => {
                ScrollArea::vertical()
                    .id_salt("overview_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.render_tab_overview(ui, ctx, p);
                    });
            }
            InspectorTab::Hex => self.render_tab_hex(ui, ctx, p),
            InspectorTab::Strings => self.render_tab_strings(ui, p),
            InspectorTab::Compare => self.render_tab_compare(ui, ctx, p),
        }
    }

    fn render_tab_overview(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: &Palette) {
        let Some(a) = self.analysis.clone() else {
            ui.label(
                RichText::new("LOADING SPECIMEN...")
                    .monospace()
                    .size(11.0)
                    .color(p.ink_dim),
            );
            return;
        };

        // 01 / FILE SPECIFICATION
        ui.label(
            RichText::new("01 / FILE SPECIFICATION")
                .monospace()
                .size(10.0)
                .color(p.ink_dim),
        );
        ui.add_space(6.0);
        rule(ui, p);

        let disp_path = mask_path_display(&a.file_path, self.store.settings.privacy_mask);
        if catalog_row(ui, "FILE", &a.file_name, true, p) {
            self.copy_with_toast(ctx, &a.file_name, "FILENAME");
        }
        if catalog_row(ui, "PATH", &disp_path, true, p) {
            self.copy_with_toast(ctx, &a.file_path, "PATH");
        }
        catalog_row(ui, "SIZE", &format_bytes(a.size), false, p);
        catalog_row(ui, "FORMAT", &a.format.format_long, false, p);
        catalog_row(
            ui,
            "ENTROPY",
            &format!("{:.3} b/B  [{}]", a.entropy, a.entropy_class.label()),
            false,
            p,
        );
        catalog_row(
            ui,
            "COMPOSITION",
            &format!("NULL {:.1}%  ·  ASCII {:.1}%", a.null_pct, a.ascii_pct),
            false,
            p,
        );

        // 02 / FORMAT HEADER
        if !a.format.details.is_empty() {
            ui.add_space(16.0);
            ui.label(
                RichText::new(format!("02 / {} HEADER", a.format.format_short))
                    .monospace()
                    .size(10.0)
                    .color(p.ink_dim),
            );
            ui.add_space(6.0);
            rule(ui, p);

            for (k, v) in &a.format.details {
                if catalog_row(ui, k, v, true, p) {
                    self.copy_with_toast(ctx, v, k);
                }
            }
        }

        // 03 / SECTIONS & ENTROPY (Interactive: click section -> jump to HEX)
        if !a.format.sections.is_empty() {
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "03 / SECTIONS ({:02})",
                        a.format.sections.len()
                    ))
                    .monospace()
                    .size(10.0)
                    .color(p.ink_dim),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("CLICK TO JUMP HEX")
                            .monospace()
                            .size(9.0)
                            .color(p.ink_dim),
                    );
                });
            });
            ui.add_space(6.0);
            rule(ui, p);

            for sec in &a.format.sections {
                let w = ui.available_width();
                let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 36.0), Sense::click());
                if resp.hovered() {
                    ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
                    ui.painter()
                        .rect_filled(rect, Rounding::same(2.0), p.hover);
                }

                let sp = ui.painter_at(rect);
                sp.text(
                    Pos2::new(rect.min.x + 2.0, rect.min.y + 11.0),
                    Align2::LEFT_CENTER,
                    &sec.name,
                    FontId::monospace(11.0),
                    p.ink,
                );
                sp.text(
                    Pos2::new(rect.min.x + 92.0, rect.min.y + 11.0),
                    Align2::LEFT_CENTER,
                    &sec.flags,
                    FontId::monospace(10.0),
                    p.ink_mid,
                );
                sp.text(
                    Pos2::new(rect.min.x + 128.0, rect.min.y + 11.0),
                    Align2::LEFT_CENTER,
                    format!(
                        "0x{:06X} · {}",
                        sec.raw_offset,
                        format_bytes_compact(sec.raw_size as usize),
                    ),
                    FontId::monospace(9.5),
                    p.ink_dim,
                );
                let _ = resp.clone().on_hover_text(format!(
                    "{}  ·  VA 0x{:08X}  ·  VSIZE {}  ·  RAW 0x{:08X}  ·  SIZE {}",
                    sec.name,
                    sec.virtual_addr,
                    format_bytes_compact(sec.virtual_size as usize),
                    sec.raw_offset,
                    format_bytes_compact(sec.raw_size as usize)
                ));
                sp.text(
                    Pos2::new(rect.max.x - 2.0, rect.min.y + 11.0),
                    Align2::RIGHT_CENTER,
                    format!("H {:.2}", sec.entropy),
                    FontId::monospace(10.0),
                    if sec.entropy >= 7.2 { p.ink } else { p.ink_mid },
                );

                // Minimal monochrome entropy bar
                let bar_rect = Rect::from_min_max(
                    Pos2::new(rect.min.x + 2.0, rect.max.y - 8.0),
                    Pos2::new(rect.max.x - 2.0, rect.max.y - 4.0),
                );
                sp.rect_filled(bar_rect, Rounding::ZERO, p.hairline);
                let ratio = (sec.entropy / 8.0).clamp(0.0, 1.0);
                sp.rect_filled(
                    Rect::from_min_size(
                        bar_rect.min,
                        Vec2::new(bar_rect.width() * ratio, bar_rect.height()),
                    ),
                    Rounding::ZERO,
                    if sec.entropy >= 7.2 {
                        p.ink
                    } else {
                        blend(p.ink_mid, p.ink, ratio)
                    },
                );

                rule(ui, p);

                if resp.clicked() {
                    self.jump_hex_to(sec.raw_offset as usize, 16, true);
                    self.notify(format!("SECTION {}  ·  0x{:08X}", sec.name, sec.raw_offset));
                }
            }
        }

        // 04 / CRYPTOGRAPHIC DIGESTS
        ui.add_space(16.0);
        ui.label(
            RichText::new("04 / CRYPTOGRAPHIC DIGESTS")
                .monospace()
                .size(10.0)
                .color(p.ink_dim),
        );
        ui.add_space(6.0);
        rule(ui, p);

        if catalog_row(ui, "SHA-256", &a.sha256, true, p) {
            self.copy_with_toast(ctx, &a.sha256, "SHA-256");
        }
        if catalog_row(ui, "SHA-1", &a.sha1, true, p) {
            self.copy_with_toast(ctx, &a.sha1, "SHA-1");
        }
        if catalog_row(ui, "MD5", &a.md5, true, p) {
            self.copy_with_toast(ctx, &a.md5, "MD5");
        }
    }

    /// Virtualized 60fps `xxd` Hex + ASCII Viewer with offset jump and Hex/ASCII search.
    fn render_tab_hex(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: &Palette) {
        let Some(a) = self.analysis.clone() else {
            ui.label(RichText::new("NO FILE LOADED").monospace().size(11.0).color(p.ink_dim));
            return;
        };

        // Top Control Strip: Offset Jump + Search
        ui.horizontal(|ui| {
            ui.label(RichText::new("01 / HEX INSPECTOR").monospace().size(10.0).color(p.ink_dim));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(off) = self.hex_cursor_offset {
                    let sec = a
                        .section_at_offset(off)
                        .map(|s| format!("  ·  {}", s.name))
                        .unwrap_or_default();
                    ui.label(
                        RichText::new(format!("@ 0x{:08X}{}", off, sec))
                            .monospace()
                            .size(10.0)
                            .color(p.ink),
                    );
                }
            });
        });
        ui.add_space(6.0);

        // Row 1: Jump Offset
        ui.horizontal(|ui| {
            let jump_resp = ui.add(
                TextEdit::singleline(&mut self.hex_jump_input)
                    .font(FontId::monospace(10.5))
                    .desired_width(118.0)
                    .hint_text("0x00000000"),
            );
            let do_jump = action_btn(ui, "JUMP", false, p)
                || (jump_resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)));
            if do_jump {
                if let Some(off) = parse_offset_input(&self.hex_jump_input) {
                    self.jump_hex_to(off, 1, false);
                } else {
                    self.notify("INVALID OFFSET");
                }
            }

            ui.add_space(6.0);

            // Search Mode Cycle
            if action_btn(ui, self.hex_search_mode.label(), false, p) {
                self.hex_search_mode = match self.hex_search_mode {
                    SearchMode::Auto => SearchMode::Hex,
                    SearchMode::Hex => SearchMode::Ascii,
                    SearchMode::Ascii => SearchMode::Auto,
                };
            }

            let search_w = (ui.available_width() - 68.0).max(80.0);
            let search_resp = ui.add(
                TextEdit::singleline(&mut self.hex_search_input)
                    .font(FontId::monospace(10.5))
                    .desired_width(search_w)
                    .hint_text("4D 5A / ASCII"),
            );
            let do_search = action_btn(ui, "FIND", true, p)
                || (search_resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)));
            if do_search {
                self.run_hex_search();
            }
        });

        // Search Results Navigation Strip
        let mut clear_search = false;
        let mut nav_target: Option<(usize, usize)> = None;
        if let Some(outcome) = &self.hex_search_outcome {
            ui.add_space(6.0);
            let total = outcome.offsets.len();
            let pat_len = outcome.pattern.len();

            ui.horizontal(|ui| {
                let status = if total == 0 {
                    format!("0 {} MATCHES", outcome.interpreted_as)
                } else {
                    format!(
                        "{} MATCH {:02}/{:02}{}",
                        outcome.interpreted_as,
                        self.hex_search_index + 1,
                        total,
                        if outcome.truncated { "+" } else { "" }
                    )
                };
                stamp(ui, &status, total > 0, p);

                if total > 1 {
                    if action_btn(ui, "< PREV", false, p) {
                        self.hex_search_index = if self.hex_search_index == 0 {
                            total - 1
                        } else {
                            self.hex_search_index - 1
                        };
                        if let Some(&off) = outcome.offsets.get(self.hex_search_index) {
                            nav_target = Some((off, pat_len));
                        }
                    }
                    if action_btn(ui, "NEXT >", false, p) {
                        self.hex_search_index = (self.hex_search_index + 1) % total;
                        if let Some(&off) = outcome.offsets.get(self.hex_search_index) {
                            nav_target = Some((off, pat_len));
                        }
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if typo_switch(ui, "CLEAR", false, p) {
                        clear_search = true;
                    }
                });
            });
        }
        if clear_search {
            self.hex_search_outcome = None;
        } else if let Some((off, pat_len)) = nav_target {
            self.jump_hex_to(off, pat_len, false);
        }

        ui.add_space(8.0);
        rule(ui, p);

        // Column Header
        let cols = self.store.settings.sanitized_hex_cols();
        let hdr = if cols == 16 {
            "OFFSET    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII"
        } else {
            "OFFSET    00 01 02 03 04 05 06 07  ASCII"
        };
        ui.add_space(4.0);
        ui.label(RichText::new(hdr).monospace().size(9.5).color(p.ink_dim));
        ui.add_space(4.0);
        rule(ui, p);

        // Virtualized Hex Rows via ScrollArea::show_rows (60fps even for 100MB+ files!)
        let total_rows = (a.size + cols - 1) / cols;
        if total_rows == 0 {
            ui.add_space(12.0);
            ui.label(RichText::new("EMPTY BUFFER").monospace().size(11.0).color(p.ink_dim));
            return;
        }

        let row_h = 20.0_f32;
        let mut sa = ScrollArea::vertical()
            .id_salt("hex_virtual_scroll")
            .auto_shrink([false, false]);
        if let Some(y) = self.hex_scroll_to_y.take() {
            sa = sa.vertical_scroll_offset(y);
        }

        let bytes = a.bytes.as_slice();
        let active_off = self.hex_cursor_offset;
        let hl_len = self.hex_highlight_len;
        let mut clicked_row_off: Option<usize> = None;

        sa.show_rows(ui, row_h, total_rows, |ui, row_range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for row in row_range {
                let row_off = row * cols;
                let row_end = (row_off + cols).min(bytes.len());
                let slice = &bytes[row_off..row_end];

                let is_active_row = active_off
                    .map(|ao| ao < row_off + cols && ao + hl_len > row_off)
                    .unwrap_or(false);

                let line = format_xxd_line(row_off, slice, cols);

                let (rect, resp) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), row_h),
                    Sense::click(),
                );
                if resp.hovered() {
                    ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
                }

                let painter = ui.painter_at(rect);
                if is_active_row {
                    painter.rect_filled(rect, Rounding::same(1.0), p.invert_bg);
                } else if resp.hovered() {
                    painter.rect_filled(rect, Rounding::same(1.0), p.hover);
                } else if row % 2 == 1 {
                    painter.rect_filled(rect, Rounding::ZERO, with_alpha(p.ink, 5));
                }

                painter.text(
                    Pos2::new(rect.min.x + 2.0, rect.center().y),
                    Align2::LEFT_CENTER,
                    line,
                    FontId::monospace(10.0),
                    if is_active_row { p.invert_fg } else { p.ink },
                );

                if resp.clicked() {
                    clicked_row_off = Some(row_off);
                }
            }
        });

        if let Some(off) = clicked_row_off {
            self.hex_cursor_offset = Some(off);
            self.hex_highlight_len = 1;
            self.hex_jump_input = format!("0x{:08X}", off);
        }
    }

    /// Filterable Extracted Strings Catalog (click any string -> jump straight to HEX!).
    fn render_tab_strings(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let Some(a) = &self.analysis else {
            ui.label(RichText::new("NO FILE LOADED").monospace().size(11.0).color(p.ink_dim));
            return;
        };

        let cur_min = self.store.settings.sanitized_min_string_len();
        let total_extracted = a.strings.len();
        let truncated = a.strings_truncated;

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "01 / STRINGS ({}{})",
                    total_extracted,
                    if truncated { "+" } else { "" }
                ))
                .monospace()
                .size(10.0)
                .color(p.ink_dim),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let mut new_min: Option<usize> = None;
                for len in [12usize, 8, 6, 4] {
                    if typo_switch(ui, &format!("≥{}", len), cur_min == len, p) && cur_min != len {
                        new_min = Some(len);
                    }
                    ui.add_space(4.0);
                }
                if let Some(m) = new_min {
                    self.store.settings.min_string_len = m;
                    self.store.save();
                    if let Some(am) = &mut self.analysis {
                        am.re_extract_strings(m);
                    }
                }
            });
        });

        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.strings_filter)
                    .font(FontId::monospace(10.5))
                    .desired_width((ui.available_width() - 56.0).max(100.0))
                    .hint_text("Filter ASCII strings..."),
            );
            if typo_switch(ui, "CLEAR", false, p) {
                self.strings_filter.clear();
            }
        });

        ui.add_space(8.0);
        rule(ui, p);

        let q = self.strings_filter.trim().to_lowercase();
        let filtered: Vec<(usize, String)> = self
            .analysis
            .as_ref()
            .map(|a| {
                a.strings
                    .iter()
                    .filter(|s| q.is_empty() || s.value.to_lowercase().contains(&q))
                    .map(|s| (s.offset, s.value.clone()))
                    .collect()
            })
            .unwrap_or_default();

        if filtered.is_empty() {
            ui.add_space(16.0);
            ui.label(
                RichText::new("NO MATCHING STRINGS")
                    .monospace()
                    .size(11.0)
                    .color(p.ink_dim),
            );
            return;
        }

        let row_h = 26.0_f32;
        let mut jump_target: Option<(usize, usize)> = None;

        ScrollArea::vertical()
            .id_salt("strings_virtual_scroll")
            .auto_shrink([false, false])
            .show_rows(ui, row_h, filtered.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for idx in range {
                    let (off, val) = &filtered[idx];
                    let (rect, resp) = ui.allocate_exact_size(
                        Vec2::new(ui.available_width(), row_h),
                        Sense::click(),
                    );
                    if resp.hovered() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        ui.painter()
                            .rect_filled(rect, Rounding::same(1.0), p.hover);
                    }

                    let sp = ui.painter_at(rect);
                    sp.text(
                        Pos2::new(rect.min.x + 2.0, rect.center().y),
                        Align2::LEFT_CENTER,
                        format!("0x{:08X}", off),
                        FontId::monospace(9.5),
                        p.ink_dim,
                    );
                    let display_val: String = if val.chars().count() > 42 {
                        format!("{}…", val.chars().take(41).collect::<String>())
                    } else {
                        val.clone()
                    };
                    sp.text(
                        Pos2::new(rect.min.x + 86.0, rect.center().y),
                        Align2::LEFT_CENTER,
                        display_val,
                        FontId::monospace(10.5),
                        p.ink,
                    );
                    sp.line_segment(
                        [
                            Pos2::new(rect.min.x, rect.max.y),
                            Pos2::new(rect.max.x, rect.max.y),
                        ],
                        Stroke::new(1.0_f32, p.hairline),
                    );

                    if resp.clicked() {
                        jump_target = Some((*off, val.len().min(32)));
                    }
                }
            });

        if let Some((off, len)) = jump_target {
            self.jump_hex_to(off, len, true);
            self.notify(format!("STRING  ·  0x{:08X}", off));
        }
    }

    /// Byte-Level Binary Diff Inspector.
    fn render_tab_compare(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, p: &Palette) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("01 / BINARY DIFF")
                    .monospace()
                    .size(10.0)
                    .color(p.ink_dim),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self.diff.is_some() && typo_switch(ui, "CLEAR", false, p) {
                    self.compare_analysis = None;
                    self.diff = None;
                }
                ui.add_space(6.0);
                if action_btn(ui, "+ LOAD FILE B", true, p) {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.start_load_file(ctx, path, LoadTarget::Compare);
                    }
                }
            });
        });
        ui.add_space(8.0);
        rule(ui, p);

        let Some(diff) = self.diff.clone() else {
            ui.add_space(28.0);
            ui.label(
                RichText::new("NO COMPARISON FILE LOADED")
                    .monospace()
                    .size(11.5)
                    .color(p.ink),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Load a second binary with '+ LOAD FILE B' or drag & drop a file while on this tab to inspect byte-level deltas.")
                    .size(11.5)
                    .color(p.ink_mid),
            );
            return;
        };

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            stamp(
                ui,
                if diff.sha256_match {
                    "SHA-256 IDENTICAL ●"
                } else {
                    "BINARY DIFF DETECTED"
                },
                true,
                p,
            );
            ui.add_space(6.0);
            stamp(ui, &format!("{:.2}% MATCH", diff.identical_pct), false, p);
        });
        ui.add_space(10.0);

        let disp_b = mask_path_display(&diff.other_path, self.store.settings.privacy_mask);
        catalog_row(ui, "FILE B", &diff.other_name, false, p);
        if catalog_row(ui, "PATH B", &disp_b, true, p) {
            self.copy_with_toast(ctx, &diff.other_path, "PATH B");
        }
        let delta_str = if diff.size_delta >= 0 {
            format!("+{} B", diff.size_delta)
        } else {
            format!("{} B", diff.size_delta)
        };
        catalog_row(
            ui,
            "SIZE DELTA",
            &format!(
                "{} vs {} ({})",
                format_bytes_compact(diff.size_a),
                format_bytes_compact(diff.size_b),
                delta_str
            ),
            false,
            p,
        );
        catalog_row(
            ui,
            "BYTE DELTA",
            &format!(
                "{} DIFF  ·  {} IDENTICAL",
                diff.differing_bytes, diff.identical_bytes
            ),
            false,
            p,
        );
        if catalog_row(ui, "SHA-256 B", &diff.other_sha256, true, p) {
            self.copy_with_toast(ctx, &diff.other_sha256, "SHA-256 B");
        }

        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "02 / DIFFERING REGIONS ({}{})",
                    diff.ranges.len(),
                    if diff.total_ranges > diff.ranges.len() {
                        format!(" / {}", diff.total_ranges)
                    } else {
                        String::new()
                    }
                ))
                .monospace()
                .size(10.0)
                .color(p.ink_dim),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new("CLICK TO JUMP HEX")
                        .monospace()
                        .size(9.0)
                        .color(p.ink_dim),
                );
            });
        });
        ui.add_space(6.0);
        rule(ui, p);

        if diff.ranges.is_empty() {
            ui.add_space(12.0);
            ui.label(
                RichText::new("0 DIFFERING BYTES — FILES ARE BIT-IDENTICAL")
                    .monospace()
                    .size(10.5)
                    .color(p.ink),
            );
            return;
        }

        let row_h = 40.0_f32;
        let mut jump_off: Option<(usize, usize)> = None;

        ScrollArea::vertical()
            .id_salt("diff_ranges_scroll")
            .auto_shrink([false, false])
            .show_rows(ui, row_h, diff.ranges.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for idx in range {
                    let dr = &diff.ranges[idx];
                    let (rect, resp) = ui.allocate_exact_size(
                        Vec2::new(ui.available_width(), row_h),
                        Sense::click(),
                    );
                    if resp.hovered() {
                        ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
                        ui.painter()
                            .rect_filled(rect, Rounding::same(1.0), p.hover);
                    }

                    let sp = ui.painter_at(rect);
                    sp.text(
                        Pos2::new(rect.min.x + 2.0, rect.min.y + 12.0),
                        Align2::LEFT_CENTER,
                        format!("0x{:08X}", dr.offset),
                        FontId::monospace(10.5),
                        p.ink,
                    );
                    sp.text(
                        Pos2::new(rect.max.x - 2.0, rect.min.y + 12.0),
                        Align2::RIGHT_CENTER,
                        format!("{} B", dr.len),
                        FontId::monospace(9.5),
                        p.ink_mid,
                    );

                    let hex_a = format_hex_preview(&dr.sample_a, 6);
                    let hex_b = format_hex_preview(&dr.sample_b, 6);
                    sp.text(
                        Pos2::new(rect.min.x + 2.0, rect.max.y - 11.0),
                        Align2::LEFT_CENTER,
                        format!("A [{}]  →  B [{}]", hex_a, hex_b),
                        FontId::monospace(9.5),
                        p.ink_dim,
                    );
                    sp.line_segment(
                        [
                            Pos2::new(rect.min.x, rect.max.y),
                            Pos2::new(rect.max.x, rect.max.y),
                        ],
                        Stroke::new(1.0_f32, p.hairline),
                    );

                    if resp.clicked() {
                        jump_off = Some((dr.offset, dr.len.min(16)));
                    }
                }
            });

        if let Some((off, len)) = jump_off {
            self.jump_hex_to(off, len, true);
            self.notify(format!("DIFF RANGE  ·  0x{:08X}", off));
        }
    }

    /// Sleek Monochrome Architectural Settings Modal (Ctrl+, / ESC / Backdrop click)
    fn render_settings_modal(&mut self, ctx: &egui::Context, p: &Palette) {
        let screen = ctx.screen_rect();

        egui::Area::new(egui::Id::new("settings_backdrop"))
            .order(egui::Order::Middle)
            .fixed_pos(screen.min)
            .show(ctx, |ui| {
                let (rect, resp) = ui.allocate_exact_size(screen.size(), Sense::click());
                ui.painter()
                    .rect_filled(rect, Rounding::ZERO, with_alpha(p.canvas, 200));
                if resp.clicked() {
                    self.settings_open = false;
                }
            });

        let modal_w = 560.0_f32.min(screen.width() - 48.0);
        egui::Area::new(egui::Id::new("settings_modal"))
            .order(egui::Order::Foreground)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(p.surface)
                    .stroke(Stroke::new(1.2_f32, p.rule_strong))
                    .rounding(Rounding::same(3.0))
                    .inner_margin(egui::Margin::same(28.0))
                    .show(ui, |ui| {
                        ui.set_width(modal_w);

                        // Header
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.label(
                                    RichText::new("BINVIEW // PREFERENCES")
                                        .monospace()
                                        .size(9.5)
                                        .color(p.ink_dim),
                                );
                                ui.label(RichText::new("Settings").size(20.0).strong().color(p.ink));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if window_ctrl_btn(ui, "×", true, p) {
                                    self.settings_open = false;
                                }
                            });
                        });

                        ui.add_space(14.0);
                        rule(ui, p);
                        ui.add_space(16.0);

                        // 01 / APPEARANCE
                        ui.label(
                            RichText::new("01 / APPEARANCE")
                                .monospace()
                                .size(10.0)
                                .color(p.ink_dim),
                        );
                        ui.add_space(10.0);

                        setting_row(ui, "THEME", p, |ui| {
                            if action_btn(ui, "NOIR", self.store.settings.dark_mode, p) {
                                self.store.settings.dark_mode = true;
                                apply_theme(ctx, self.store.settings.theme_kind());
                                self.store.save();
                            }
                            if action_btn(ui, "PAPER", !self.store.settings.dark_mode, p) {
                                self.store.settings.dark_mode = false;
                                apply_theme(ctx, self.store.settings.theme_kind());
                                self.store.save();
                            }
                        });

                        setting_row(ui, "TYPOGRAPHY", p, |ui| {
                            let cur_f = self.store.settings.font_preset();
                            for (lbl, fp) in [
                                ("IBM PLEX", FontPreset::IbmPlex),
                                ("SPACE MONO", FontPreset::SpaceMono),
                                ("JETBRAINS", FontPreset::JetBrains),
                            ] {
                                if action_btn(ui, lbl, cur_f == fp, p) {
                                    self.store.settings.set_font_preset(fp);
                                    apply_fonts(ctx, fp);
                                    self.store.save();
                                }
                            }
                        });

                        setting_row(ui, "PLATE MODE", p, |ui| {
                            let cur_m = self.store.settings.viz_mode();
                            for &m in VizMode::all() {
                                if action_btn(ui, m.label(), cur_m == m, p) {
                                    self.store.settings.set_viz_mode(m);
                                    self.store.save();
                                    self.trigger_reveal();
                                }
                            }
                        });

                        ui.add_space(12.0);
                        rule(ui, p);
                        ui.add_space(14.0);

                        // 02 / INSPECTOR & PRIVACY
                        ui.label(
                            RichText::new("02 / INSPECTOR & PRIVACY")
                                .monospace()
                                .size(10.0)
                                .color(p.ink_dim),
                        );
                        ui.add_space(10.0);

                        setting_row(ui, "MIN STRING", p, |ui| {
                            let cur = self.store.settings.sanitized_min_string_len();
                            for len in [4usize, 6, 8, 12] {
                                if action_btn(ui, &format!("{} CHARS", len), cur == len, p) {
                                    self.store.settings.min_string_len = len;
                                    self.store.save();
                                    if let Some(a) = &mut self.analysis {
                                        a.re_extract_strings(len);
                                    }
                                }
                            }
                        });

                        setting_row(ui, "HEX WIDTH", p, |ui| {
                            let cols = self.store.settings.sanitized_hex_cols();
                            for c in [8usize, 16] {
                                if action_btn(ui, &format!("{} BYTES / ROW", c), cols == c, p) {
                                    self.store.settings.hex_bytes_per_row = c;
                                    self.store.save();
                                }
                            }
                        });

                        setting_row(ui, "DISPLAY", p, |ui| {
                            let tr = self.store.settings.show_trail;
                            if action_btn(
                                ui,
                                if tr { "HILBERT TRAIL: ON" } else { "HILBERT TRAIL: OFF" },
                                tr,
                                p,
                            ) {
                                self.store.settings.show_trail = !tr;
                                self.store.save();
                            }
                            let pm = self.store.settings.privacy_mask;
                            if action_btn(
                                ui,
                                if pm { "PRIVACY MASK: ON" } else { "PRIVACY MASK: OFF" },
                                pm,
                                p,
                            ) {
                                self.store.settings.privacy_mask = !pm;
                                self.store.save();
                            }
                        });

                        ui.add_space(16.0);
                        rule(ui, p);
                        ui.add_space(14.0);

                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("STATE SAVED AUTOMATICALLY")
                                    .monospace()
                                    .size(9.5)
                                    .color(p.ink_dim),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if action_btn(ui, "DONE", true, p) {
                                    self.settings_open = false;
                                }
                            });
                        });
                    });
            });
    }
}

fn format_xxd_line(offset: usize, slice: &[u8], cols: usize) -> String {
    let mut s = String::with_capacity(80);
    use std::fmt::Write;
    let _ = write!(s, "{:08X}  ", offset);
    for i in 0..cols {
        if i == 8 && cols == 16 {
            s.push(' ');
        }
        if let Some(&b) = slice.get(i) {
            let _ = write!(s, "{:02X} ", b);
        } else {
            s.push_str("   ");
        }
    }
    s.push(' ');
    for &b in slice {
        if (0x20..=0x7E).contains(&b) {
            s.push(b as char);
        } else {
            s.push('·');
        }
    }
    s
}

fn format_hex_preview(bytes: &[u8], max_bytes: usize) -> String {
    if bytes.is_empty() {
        return "EOF".into();
    }
    let s = bytes
        .iter()
        .take(max_bytes)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > max_bytes {
        format!("{}…", s)
    } else {
        s
    }
}

fn parse_offset_input(raw: &str) -> Option<usize> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex_part) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        usize::from_str_radix(hex_part, 16).ok()
    } else if t.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
        usize::from_str_radix(t, 16).ok()
    } else {
        t.parse::<usize>().ok()
    }
}

fn setting_row(
    ui: &mut egui::Ui,
    label: &str,
    p: &Palette,
    content: impl FnOnce(&mut egui::Ui),
) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [112.0, 26.0],
            egui::Label::new(RichText::new(label).monospace().size(10.0).color(p.ink_mid)),
        );
        ui.horizontal_wrapped(content);
    });
    ui.add_space(6.0);
}

fn window_ctrl_btn(ui: &mut egui::Ui, glyph: &str, is_close: bool, p: &Palette) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(28.0, 26.0), Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let painter = ui.painter_at(rect);
    let (fill, fg) = if resp.hovered() {
        if is_close {
            (p.invert_bg, p.invert_fg)
        } else {
            (p.hover, p.ink)
        }
    } else {
        (egui::Color32::TRANSPARENT, p.ink_mid)
    };
    painter.rect_filled(rect, Rounding::same(2.0), fill);
    painter.text(
        rect.center(),
        Align2::CENTER_CENTER,
        glyph,
        FontId::monospace(12.0),
        fg,
    );
    resp.clicked()
}
