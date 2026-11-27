use egui::{
    Align2, Color32, FontData, FontDefinitions, FontFamily, FontId, Margin, Pos2, Rect, RichText,
    Rounding, Sense, Stroke, Style, Vec2, Visuals,
};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontPreset {
    IbmPlex,
    SpaceMono,
    JetBrains,
}

impl FontPreset {
    pub fn label(&self) -> &'static str {
        match self {
            Self::IbmPlex => "FONT: PLEX",
            Self::SpaceMono => "FONT: SPACE",
            Self::JetBrains => "FONT: JB",
        }
    }

    pub fn svg_stack(&self) -> &'static str {
        match self {
            Self::IbmPlex => "'IBM Plex Mono', 'JetBrains Mono', monospace",
            Self::SpaceMono => "'Space Mono', 'IBM Plex Mono', monospace",
            Self::JetBrains => "'JetBrains Mono', 'IBM Plex Mono', monospace",
        }
    }
}

const FONT_SPACE_GROTESK: &[u8] = include_bytes!("../assets/fonts/SpaceGrotesk-Medium.ttf");
const FONT_IBM_PLEX_MONO: &[u8] = include_bytes!("../assets/fonts/IBMPlexMono-Medium.ttf");
const FONT_SPACE_MONO: &[u8] = include_bytes!("../assets/fonts/SpaceMono-Regular.ttf");
const FONT_JETBRAINS_MONO: &[u8] = include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf");

/// Applies embedded studio typography + modern Japanese fallback (M PLUS 1p -> Noto Sans JP -> BIZ UDGothic).
pub fn apply_fonts(ctx: &egui::Context, preset: FontPreset) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "space_grotesk".to_owned(),
        FontData::from_static(FONT_SPACE_GROTESK),
    );
    fonts.font_data.insert(
        "ibm_plex_mono".to_owned(),
        FontData::from_static(FONT_IBM_PLEX_MONO),
    );
    fonts.font_data.insert(
        "space_mono".to_owned(),
        FontData::from_static(FONT_SPACE_MONO),
    );
    fonts.font_data.insert(
        "jetbrains_mono".to_owned(),
        FontData::from_static(FONT_JETBRAINS_MONO),
    );

    let mono_key = match preset {
        FontPreset::IbmPlex => "ibm_plex_mono",
        FontPreset::SpaceMono => "space_mono",
        FontPreset::JetBrains => "jetbrains_mono",
    };

    let mut jp_candidates: Vec<PathBuf> = Vec::new();
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        let user_fonts = PathBuf::from(local_app).join(r"Microsoft\Windows\Fonts");
        jp_candidates.push(user_fonts.join("MPLUS1p-Medium.ttf"));
        jp_candidates.push(user_fonts.join("MPLUS1p-Regular.ttf"));
    }
    jp_candidates.push(PathBuf::from(r"C:\Windows\Fonts\NotoSansJP-VF.ttf"));
    jp_candidates.push(PathBuf::from(r"C:\Windows\Fonts\BIZ-UDGothicR.ttc"));
    jp_candidates.push(PathBuf::from(r"C:\Windows\Fonts\YuGothM.ttc"));
    jp_candidates.push(PathBuf::from(r"C:\Windows\Fonts\meiryo.ttc"));

    let mut has_jp = false;
    for path in jp_candidates {
        if path.exists() {
            if let Ok(bytes) = std::fs::read(&path) {
                fonts
                    .font_data
                    .insert("jp_modern".to_owned(), FontData::from_owned(bytes));
                has_jp = true;
                break;
            }
        }
    }

    if let Some(prop) = fonts.families.get_mut(&FontFamily::Proportional) {
        prop.insert(0, "space_grotesk".to_owned());
        if has_jp {
            prop.insert(1, "jp_modern".to_owned());
        }
        prop.push(mono_key.to_owned());
    }

    if let Some(mono) = fonts.families.get_mut(&FontFamily::Monospace) {
        mono.insert(0, mono_key.to_owned());
        if mono_key != "jetbrains_mono" {
            mono.insert(1, "jetbrains_mono".to_owned());
        }
        if has_jp {
            mono.push("jp_modern".to_owned());
        }
    }

    ctx.set_fonts(fonts);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeKind {
    Noir,
    Paper,
}

#[allow(dead_code)]
impl ThemeKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Noir => "NOIR",
            Self::Paper => "PAPER",
        }
    }

    pub fn palette(&self) -> Palette {
        match self {
            ThemeKind::Noir => Palette {
                is_dark: true,
                canvas: Color32::from_rgb(6, 6, 7),         // #060607 Jet Obsidian
                surface: Color32::from_rgb(11, 11, 13),     // #0B0B0D
                well: Color32::from_rgb(3, 3, 4),           // #030304 Pure Matte
                hover: Color32::from_rgb(20, 20, 24),       // #141418
                hairline: Color32::from_rgb(30, 30, 35),    // #1E1E23
                rule_strong: Color32::from_rgb(64, 64, 74), // #40404A
                ink: Color32::from_rgb(245, 245, 247),      // #F5F5F7
                ink_mid: Color32::from_rgb(156, 156, 166),  // #9C9CA6
                ink_dim: Color32::from_rgb(86, 86, 96),     // #565660
                dot_grid: Color32::from_rgb(28, 28, 33),
                invert_bg: Color32::from_rgb(245, 245, 247),
                invert_fg: Color32::from_rgb(6, 6, 7),
            },
            ThemeKind::Paper => Palette {
                is_dark: false,
                canvas: Color32::from_rgb(244, 243, 238),    // #F4F3EE Warm Archival Paper
                surface: Color32::from_rgb(250, 249, 246),   // #FAF9F6
                well: Color32::from_rgb(236, 235, 229),      // #ECEBE5
                hover: Color32::from_rgb(230, 229, 222),     // #E6E5DE
                hairline: Color32::from_rgb(214, 212, 204),  // #D6D4CC
                rule_strong: Color32::from_rgb(148, 146, 138),
                ink: Color32::from_rgb(12, 12, 14),          // #0C0C0E Carbon Ink
                ink_mid: Color32::from_rgb(84, 84, 90),
                ink_dim: Color32::from_rgb(144, 142, 136),
                dot_grid: Color32::from_rgb(216, 214, 206),
                invert_bg: Color32::from_rgb(12, 12, 14),
                invert_fg: Color32::from_rgb(248, 247, 243),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub is_dark: bool,
    pub canvas: Color32,
    pub surface: Color32,
    pub well: Color32,
    pub hover: Color32,
    pub hairline: Color32,
    pub rule_strong: Color32,
    pub ink: Color32,
    pub ink_mid: Color32,
    pub ink_dim: Color32,
    pub dot_grid: Color32,
    pub invert_bg: Color32,
    pub invert_fg: Color32,
}

pub fn apply_theme(ctx: &egui::Context, kind: ThemeKind) {
    let p = kind.palette();
    let mut style = Style::default();
    let mut visuals = if p.is_dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };

    visuals.panel_fill = p.canvas;
    visuals.window_fill = p.surface;
    visuals.extreme_bg_color = p.well;
    visuals.faint_bg_color = p.hover;
    visuals.override_text_color = Some(p.ink);

    visuals.widgets.noninteractive.bg_fill = p.surface;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.hairline);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.ink);
    visuals.widgets.noninteractive.rounding = Rounding::same(2.0);

    visuals.widgets.inactive.bg_fill = p.well;
    visuals.widgets.inactive.weak_bg_fill = p.well;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.hairline);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.ink);
    visuals.widgets.inactive.rounding = Rounding::same(2.0);

    visuals.widgets.hovered.bg_fill = p.hover;
    visuals.widgets.hovered.weak_bg_fill = p.hover;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.rule_strong);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, p.ink);
    visuals.widgets.hovered.rounding = Rounding::same(2.0);

    visuals.widgets.active.bg_fill = p.invert_bg;
    visuals.widgets.active.weak_bg_fill = p.invert_bg;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, p.invert_bg);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, p.invert_fg);
    visuals.widgets.active.rounding = Rounding::same(2.0);

    visuals.selection.bg_fill = with_alpha(p.invert_bg, 45);
    visuals.selection.stroke = Stroke::new(1.0_f32, p.invert_bg);

    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.scroll = egui::style::ScrollStyle::thin();
    style.spacing.window_margin = Margin::same(0.0);
    ctx.set_style(style);
}

/// Paints a subtle 26px architectural dot-grid field across a rect.
pub fn paint_dot_field(painter: &egui::Painter, rect: Rect, spacing: f32, p: &Palette) {
    let mut y = rect.min.y + spacing * 0.5;
    while y < rect.max.y {
        let mut x = rect.min.x + spacing * 0.5;
        while x < rect.max.x {
            painter.rect_filled(
                Rect::from_min_size(Pos2::new(x, y), Vec2::splat(1.2)),
                Rounding::ZERO,
                p.dot_grid,
            );
            x += spacing;
        }
        y += spacing;
    }
}

/// Pure typographic underline switch.
pub fn typo_switch(ui: &mut egui::Ui, label: &str, active: bool, p: &Palette) -> bool {
    let font = FontId::monospace(10.5);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font.clone(), p.ink);
    let desired = Vec2::new(galley.size().x + 6.0, 22.0);
    let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let color = if active {
        p.ink
    } else if resp.hovered() {
        p.ink_mid
    } else {
        p.ink_dim
    };
    let painter = ui.painter_at(rect);
    painter.text(rect.center(), Align2::CENTER_CENTER, label, font, color);
    if active {
        painter.line_segment(
            [
                Pos2::new(rect.min.x + 2.0, rect.max.y - 1.0),
                Pos2::new(rect.max.x - 2.0, rect.max.y - 1.0),
            ],
            Stroke::new(1.5_f32, p.ink),
        );
    }
    resp.clicked()
}

/// Crisp 1px hairline action button (sharp 2px corners, monochrome inversion when solid).
pub fn action_btn(ui: &mut egui::Ui, label: &str, solid: bool, p: &Palette) -> bool {
    let font = FontId::monospace(10.5);
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_string(), font.clone(), p.ink);
    let desired = Vec2::new(galley.size().x + 20.0, 26.0);
    let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let painter = ui.painter_at(rect);
    let (fill, stroke_col, fg) = if solid {
        let bg = if resp.hovered() {
            blend(p.invert_bg, p.canvas, 0.14)
        } else {
            p.invert_bg
        };
        (bg, bg, p.invert_fg)
    } else if resp.hovered() {
        (p.hover, p.rule_strong, p.ink)
    } else {
        (Color32::TRANSPARENT, p.hairline, p.ink_mid)
    };
    painter.rect(
        rect,
        Rounding::same(2.0),
        fill,
        Stroke::new(1.0_f32, stroke_col),
    );
    painter.text(rect.center(), Align2::CENTER_CENTER, label, font, fg);
    resp.clicked()
}

/// Minimal inline monochrome stamp.
pub fn stamp(ui: &mut egui::Ui, text: &str, inverted: bool, p: &Palette) {
    let (fill, border, fg) = if inverted {
        (p.invert_bg, p.invert_bg, p.invert_fg)
    } else {
        (Color32::TRANSPARENT, p.hairline, p.ink_mid)
    };
    egui::Frame::none()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, border))
        .rounding(Rounding::same(2.0))
        .inner_margin(Margin::symmetric(7.0, 2.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(text)
                    .monospace()
                    .size(9.5)
                    .strong()
                    .color(fg),
            );
        });
}

/// Full-width 1px architectural rule.
pub fn rule(ui: &mut egui::Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().line_segment(
        [rect.left_center(), rect.right_center()],
        Stroke::new(1.0_f32, p.hairline),
    );
}

/// Museum catalog key-value row separated by a crisp 1px bottom hairline.
pub fn catalog_row(
    ui: &mut egui::Ui,
    key: &str,
    value: &str,
    copyable: bool,
    p: &Palette,
) -> bool {
    let w = ui.available_width();
    let row_resp = egui::Frame::none()
        .inner_margin(Margin::symmetric(0.0, 5.5))
        .show(ui, |ui| {
            ui.set_width(w);
            ui.horizontal(|ui| {
                ui.add_sized(
                    [108.0, 16.0],
                    egui::Label::new(RichText::new(key).monospace().size(10.0).color(p.ink_dim))
                        .truncate(),
                );
                ui.add(
                    egui::Label::new(RichText::new(value).monospace().size(11.0).color(p.ink))
                        .wrap(),
                );
            });
        })
        .response;

    let clicked = if copyable {
        let r = row_resp.interact(Sense::click());
        if r.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            ui.painter().rect_filled(
                r.rect.expand2(Vec2::new(4.0, 0.0)),
                Rounding::same(2.0),
                with_alpha(p.invert_bg, 14),
            );
        }
        r.clicked()
    } else {
        false
    };

    rule(ui, p);
    clicked
}

pub fn with_alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

pub fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let r = (a.r() as f32 * (1.0 - t) + b.r() as f32 * t) as u8;
    let g = (a.g() as f32 * (1.0 - t) + b.g() as f32 * t) as u8;
    let bl = (a.b() as f32 * (1.0 - t) + b.b() as f32 * t) as u8;
    Color32::from_rgb(r, g, bl)
}
