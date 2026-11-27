use crate::analyzer::{
    BinaryAnalysis, ByteRegionClass, DIGRAPH_DIM, ENTROPY_POINTS, HILBERT_H, HILBERT_W,
};
use crate::store::VizMode;
use crate::theme::{blend, with_alpha, Palette};
use egui::{Align2, FontId, Pos2, Rect, Rounding, Sense, Stroke, Vec2};

#[derive(Debug, Clone)]
pub enum PlateAction {
    JumpOffset { offset: usize, reason: String },
    SearchByte { byte: u8 },
    DigraphSelect { bx: usize, by: usize, sample_offset: Option<usize> },
}

#[derive(Debug, Clone, Default)]
pub struct PlateInteraction {
    pub hover_telemetry: Option<String>,
    pub action: Option<PlateAction>,
}

/// Formats a 64-char hex digest into 2 lines of 8 × 4-char uppercase safety blocks.
pub fn format_safety_blocks(sha256_hex: &str) -> (String, String) {
    let up = sha256_hex.to_uppercase();
    let chunks: Vec<&str> = up
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    if chunks.len() < 16 {
        return (up, String::new());
    }
    (chunks[0..8].join("  "), chunks[8..16].join("  "))
}

/// Renders the gallery-framed monochrome Binary Exhibition Plate in 4 distinct interactive modes.
pub fn draw_binary_plate(
    ui: &mut egui::Ui,
    analysis: &BinaryAnalysis,
    mode: VizMode,
    show_trail: bool,
    reveal: f32,
    active_hex_offset: Option<usize>,
    selected_digraph_cell: Option<(usize, usize)>,
    avail_size: Vec2,
    p: &Palette,
) -> PlateInteraction {
    let plate_w = avail_size.x.clamp(420.0, 740.0);
    let plate_h = (plate_w * 0.62).min(avail_size.y).clamp(280.0, 460.0);

    let (rect, resp) = ui.allocate_exact_size(Vec2::new(plate_w, plate_h), Sense::click_and_drag());
    let painter = ui.painter_at(rect);

    draw_plate_frame(&painter, rect, p);

    let inner_box = rect.shrink2(Vec2::new(22.0, 22.0));
    painter.rect_stroke(
        inner_box,
        Rounding::ZERO,
        Stroke::new(1.0_f32, p.rule_strong),
    );

    let interaction = match mode {
        VizMode::Digraph => draw_mode_digraph(
            &painter,
            inner_box,
            analysis,
            reveal,
            selected_digraph_cell,
            &resp,
            ui.ctx(),
            p,
        ),
        VizMode::Entropy => draw_mode_entropy(
            &painter,
            inner_box,
            analysis,
            reveal,
            active_hex_offset,
            &resp,
            ui.ctx(),
            p,
        ),
        VizMode::Spectrum => draw_mode_spectrum(
            &painter,
            inner_box,
            analysis,
            reveal,
            &resp,
            ui.ctx(),
            p,
        ),
        VizMode::Hilbert => draw_mode_hilbert(
            &painter,
            inner_box,
            analysis,
            show_trail,
            reveal,
            active_hex_offset,
            &resp,
            ui.ctx(),
            p,
        ),
    };

    // Strict 1-word minimal cutout labels (no verbose subtitles)
    draw_cutout_labels(
        &painter,
        inner_box,
        &analysis.format.format_short,
        mode.cutout_tag(),
        p,
    );

    interaction
}

fn draw_plate_frame(painter: &egui::Painter, rect: Rect, p: &Palette) {
    painter.rect(
        rect,
        Rounding::same(3.0),
        p.well,
        Stroke::new(1.0_f32, p.hairline),
    );

    // Photographic print corner crop marks
    let arm = 9.0_f32;
    let m = 7.0_f32;
    let cs = Stroke::new(1.0_f32, p.rule_strong);
    painter.line_segment(
        [
            Pos2::new(rect.min.x + m, rect.min.y + m),
            Pos2::new(rect.min.x + m + arm, rect.min.y + m),
        ],
        cs,
    );
    painter.line_segment(
        [
            Pos2::new(rect.min.x + m, rect.min.y + m),
            Pos2::new(rect.min.x + m, rect.min.y + m + arm),
        ],
        cs,
    );
    painter.line_segment(
        [
            Pos2::new(rect.max.x - m, rect.min.y + m),
            Pos2::new(rect.max.x - m - arm, rect.min.y + m),
        ],
        cs,
    );
    painter.line_segment(
        [
            Pos2::new(rect.max.x - m, rect.min.y + m),
            Pos2::new(rect.max.x - m, rect.min.y + m + arm),
        ],
        cs,
    );
    painter.line_segment(
        [
            Pos2::new(rect.min.x + m, rect.max.y - m),
            Pos2::new(rect.min.x + m + arm, rect.max.y - m),
        ],
        cs,
    );
    painter.line_segment(
        [
            Pos2::new(rect.min.x + m, rect.max.y - m),
            Pos2::new(rect.min.x + m, rect.max.y - m - arm),
        ],
        cs,
    );
    painter.line_segment(
        [
            Pos2::new(rect.max.x - m, rect.max.y - m),
            Pos2::new(rect.max.x - m - arm, rect.max.y - m),
        ],
        cs,
    );
    painter.line_segment(
        [
            Pos2::new(rect.max.x - m, rect.max.y - m),
            Pos2::new(rect.max.x - m, rect.max.y - m - arm),
        ],
        cs,
    );
}

fn draw_cutout_labels(
    painter: &egui::Painter,
    inner_box: Rect,
    top_label: &str,
    bot_label: &str,
    p: &Palette,
) {
    let top_text = format!(" [ {} ] ", top_label.to_uppercase());
    let top_center = Pos2::new(inner_box.center().x, inner_box.min.y);
    let top_galley = painter.layout_no_wrap(top_text.clone(), FontId::monospace(10.0), p.ink);
    painter.rect_filled(
        Rect::from_center_size(top_center, Vec2::new(top_galley.size().x + 6.0, 14.0)),
        Rounding::ZERO,
        p.well,
    );
    painter.text(
        top_center,
        Align2::CENTER_CENTER,
        top_text,
        FontId::monospace(10.0),
        p.ink,
    );

    let bot_text = format!(" [ {} ] ", bot_label.to_uppercase());
    let bot_center = Pos2::new(inner_box.center().x, inner_box.max.y);
    let bot_galley = painter.layout_no_wrap(bot_text.clone(), FontId::monospace(9.5), p.ink_mid);
    painter.rect_filled(
        Rect::from_center_size(bot_center, Vec2::new(bot_galley.size().x + 6.0, 14.0)),
        Rounding::ZERO,
        p.well,
    );
    painter.text(
        bot_center,
        Align2::CENTER_CENTER,
        bot_text,
        FontId::monospace(9.5),
        p.ink_mid,
    );
}

// ============================================================================
// 01 DIGRAPH — Logarithmic 64x64 Byte-Pair Cloud with Precision Crosshairs
// ============================================================================

fn draw_mode_digraph(
    painter: &egui::Painter,
    inner_box: Rect,
    analysis: &BinaryAnalysis,
    reveal: f32,
    selected_cell: Option<(usize, usize)>,
    resp: &egui::Response,
    ctx: &egui::Context,
    p: &Palette,
) -> PlateInteraction {
    let mut out = PlateInteraction::default();

    let pad_t = 28.0_f32;
    let pad_b = 24.0_f32;
    let pad_l = 36.0_f32;
    let pad_r = 24.0_f32;

    let avail_w = (inner_box.width() - pad_l - pad_r).max(64.0);
    let avail_h = (inner_box.height() - pad_t - pad_b).max(64.0);
    let side = avail_w.min(avail_h);

    // Center the square plate cleanly inside inner_box
    let grid_origin = Pos2::new(
        inner_box.center().x - side * 0.5 + 6.0,
        inner_box.center().y - side * 0.5 + 2.0,
    );
    let grid_rect = Rect::from_min_size(grid_origin, Vec2::splat(side));
    let cell_sz = side / DIGRAPH_DIM as f32;

    // Subtle deep matte inset border around the 64x64 plate
    painter.rect(
        grid_rect,
        Rounding::ZERO,
        blend(p.well, p.canvas, 0.35),
        Stroke::new(1.0_f32, p.hairline),
    );

    // Precision ASCII quadrant frame (0x20..0x7E => bins 8..31)
    let ascii_min = 8.0 * cell_sz;
    let ascii_max = 31.5 * cell_sz;
    let ascii_rect = Rect::from_min_max(
        Pos2::new(grid_rect.min.x + ascii_min, grid_rect.min.y + ascii_min),
        Pos2::new(grid_rect.min.x + ascii_max, grid_rect.min.y + ascii_max),
    );
    painter.rect_stroke(
        ascii_rect,
        Rounding::ZERO,
        Stroke::new(1.0_f32, with_alpha(p.rule_strong, 90)),
    );

    // Axis ticks: 00, 40, 80, C0, FF
    let ticks = [(0.0, "00"), (0.25, "40"), (0.5, "80"), (0.75, "C0"), (1.0, "FF")];
    for (frac, lbl) in ticks {
        let tx = grid_rect.min.x + side * frac;
        let ty = grid_rect.min.y + side * frac;
        painter.text(
            Pos2::new(tx, grid_rect.min.y - 9.0),
            Align2::CENTER_CENTER,
            lbl,
            FontId::monospace(8.5),
            p.ink_dim,
        );
        painter.text(
            Pos2::new(grid_rect.min.x - 13.0, ty),
            Align2::CENTER_CENTER,
            lbl,
            FontId::monospace(8.5),
            p.ink_dim,
        );
    }

    // Marginal projection strips (right side: Y density, bottom: X density)
    let margin_w = 14.0_f32;
    let right_strip_x = grid_rect.max.x + 12.0;
    let left_info_x = grid_rect.min.x - 32.0;
    if right_strip_x + margin_w < inner_box.max.x - 8.0 {
        // Compute marginal row/col sums for clean side telemetry bars
        let mut row_max = 0.0_f32;
        let mut row_sums = [0.0_f32; DIGRAPH_DIM];
        for y in 0..DIGRAPH_DIM {
            let mut s = 0.0_f32;
            for x in 0..DIGRAPH_DIM {
                s += analysis.digraph[y * DIGRAPH_DIM + x];
            }
            row_sums[y] = s;
            if s > row_max {
                row_max = s;
            }
        }
        if row_max > 0.0 {
            for (y, &s) in row_sums.iter().enumerate() {
                let norm = (s / row_max) * reveal;
                if norm > 0.02 {
                    let y0 = grid_rect.min.y + y as f32 * cell_sz;
                    painter.rect_filled(
                        Rect::from_min_size(
                            Pos2::new(right_strip_x, y0),
                            Vec2::new(margin_w * norm, (cell_sz - 0.5).max(1.0)),
                        ),
                        Rounding::ZERO,
                        blend(p.hairline, p.ink_mid, norm),
                    );
                }
            }
        }
    }
    let _ = left_info_x;

    // Render 64x64 logarithmic halftone/photogram matrix
    for y in 0..DIGRAPH_DIM {
        for x in 0..DIGRAPH_DIM {
            let diag = (x + y) as f32 / ((DIGRAPH_DIM * 2 - 2) as f32);
            if diag > reveal * 1.15 {
                continue;
            }
            let d = analysis.digraph[y * DIGRAPH_DIM + x];
            if d <= 0.001 {
                continue;
            }
            let cell_reveal = ((reveal * 1.15 - diag) / 0.15).clamp(0.0, 1.0);
            let intensity = d * cell_reveal;

            // Scale micro-square slightly with density for optical photogram richness
            let scale = 0.42 + 0.58 * intensity.powf(0.7);
            let draw_sz = (cell_sz * scale).max(1.2);
            let center = Pos2::new(
                grid_rect.min.x + (x as f32 + 0.5) * cell_sz,
                grid_rect.min.y + (y as f32 + 0.5) * cell_sz,
            );
            let col = blend(p.well, p.ink, 0.16 + 0.84 * intensity.powf(0.85));
            painter.rect_filled(
                Rect::from_center_size(center, Vec2::splat(draw_sz)),
                Rounding::ZERO,
                col,
            );
        }
    }

    // Highlight previously selected cell
    if let Some((sx, sy)) = selected_cell {
        if sx < DIGRAPH_DIM && sy < DIGRAPH_DIM {
            let sr = Rect::from_min_size(
                Pos2::new(
                    grid_rect.min.x + sx as f32 * cell_sz,
                    grid_rect.min.y + sy as f32 * cell_sz,
                ),
                Vec2::splat(cell_sz),
            );
            painter.rect_stroke(
                sr.expand(1.5),
                Rounding::ZERO,
                Stroke::new(1.5_f32, p.ink),
            );
        }
    }

    // Live interactive hover crosshair + click-to-jump
    if let Some(pos) = resp.hover_pos() {
        if grid_rect.contains(pos) {
            ctx.set_cursor_icon(egui::CursorIcon::Crosshair);
            let gx = (((pos.x - grid_rect.min.x) / cell_sz) as usize).min(DIGRAPH_DIM - 1);
            let gy = (((pos.y - grid_rect.min.y) / cell_sz) as usize).min(DIGRAPH_DIM - 1);
            let idx = gy * DIGRAPH_DIM + gx;
            let count = analysis.digraph_counts[idx];
            let dens = analysis.digraph[idx];
            let sample_off = analysis.digraph_sample_offset[idx];

            let cx = grid_rect.min.x + (gx as f32 + 0.5) * cell_sz;
            let cy = grid_rect.min.y + (gy as f32 + 0.5) * cell_sz;

            // Precision full crosshairs
            let guide = Stroke::new(1.0_f32, with_alpha(p.ink, 110));
            painter.line_segment(
                [Pos2::new(cx, grid_rect.min.y), Pos2::new(cx, grid_rect.max.y)],
                guide,
            );
            painter.line_segment(
                [Pos2::new(grid_rect.min.x, cy), Pos2::new(grid_rect.max.x, cy)],
                guide,
            );

            // Crisp cell target reticle
            let cell_r = Rect::from_center_size(Pos2::new(cx, cy), Vec2::splat(cell_sz + 3.0));
            painter.rect_stroke(cell_r, Rounding::ZERO, Stroke::new(1.2_f32, p.ink));

            let b0_lo = gx * 4;
            let b0_hi = b0_lo + 3;
            let b1_lo = gy * 4;
            let b1_hi = b1_lo + 3;

            out.hover_telemetry = Some(if let Some(off) = sample_off {
                format!(
                    "PAIR ({:02X}..{:02X}, {:02X}..{:02X})  ·  COUNT {}  ·  DENSITY {:.0}%  ·  FIRST 0x{:08X}",
                    b0_lo,
                    b0_hi,
                    b1_lo,
                    b1_hi,
                    count,
                    dens * 100.0,
                    off
                )
            } else {
                format!(
                    "PAIR ({:02X}..{:02X}, {:02X}..{:02X})  ·  COUNT 0",
                    b0_lo, b0_hi, b1_lo, b1_hi
                )
            });

            if resp.clicked() {
                out.action = Some(PlateAction::DigraphSelect {
                    bx: gx,
                    by: gy,
                    sample_offset: sample_off,
                });
            }
        }
    }

    out
}

// ============================================================================
// 02 ENTROPY — Seismograph Entropy Waveform + Section Brackets
// ============================================================================

fn draw_mode_entropy(
    painter: &egui::Painter,
    inner_box: Rect,
    analysis: &BinaryAnalysis,
    reveal: f32,
    active_hex_offset: Option<usize>,
    resp: &egui::Response,
    ctx: &egui::Context,
    p: &Palette,
) -> PlateInteraction {
    let mut out = PlateInteraction::default();

    let has_sections = !analysis.format.sections.is_empty() && analysis.size > 0;
    let plot_rect = Rect::from_min_max(
        Pos2::new(inner_box.min.x + 42.0, inner_box.min.y + if has_sections { 42.0 } else { 26.0 }),
        Pos2::new(inner_box.max.x - 22.0, inner_box.max.y - 30.0),
    );

    // Subtle horizontal calibration rules (0.0, 2.0, 4.0, 6.0, 7.2, 8.0)
    for &(val, lbl, strong) in &[
        (0.0_f32, "0.0", false),
        (2.0, "2.0", false),
        (4.0, "4.0", true),
        (6.0, "6.0", false),
        (7.2, "7.2", true),
        (8.0, "8.0", false),
    ] {
        let y = plot_rect.max.y - (val / 8.0) * plot_rect.height();
        let col = if strong {
            p.rule_strong
        } else {
            with_alpha(p.hairline, 180)
        };
        painter.line_segment(
            [Pos2::new(plot_rect.min.x, y), Pos2::new(plot_rect.max.x, y)],
            Stroke::new(1.0_f32, col),
        );
        painter.text(
            Pos2::new(plot_rect.min.x - 8.0, y),
            Align2::RIGHT_CENTER,
            lbl,
            FontId::monospace(8.5),
            if strong { p.ink_mid } else { p.ink_dim },
        );
    }

    // Minimal right-aligned threshold captions
    let y72 = plot_rect.max.y - (7.2 / 8.0) * plot_rect.height();
    painter.text(
        Pos2::new(plot_rect.max.x - 4.0, y72 - 7.0),
        Align2::RIGHT_CENTER,
        "PACKED",
        FontId::monospace(8.0),
        p.ink_dim,
    );
    let y40 = plot_rect.max.y - (4.0 / 8.0) * plot_rect.height();
    painter.text(
        Pos2::new(plot_rect.max.x - 4.0, y40 - 7.0),
        Align2::RIGHT_CENTER,
        "TEXT",
        FontId::monospace(8.0),
        p.ink_dim,
    );

    // Section Brackets along the top of the seismograph
    if has_sections {
        let size_f = analysis.size as f32;
        let bracket_y = plot_rect.min.y - 12.0;
        let mut last_label_right = plot_rect.min.x - 4.0;

        for (si, sec) in analysis.format.sections.iter().enumerate() {
            if sec.raw_size == 0 {
                continue;
            }
            let x0 = plot_rect.min.x + (sec.raw_offset as f32 / size_f).clamp(0.0, 1.0) * plot_rect.width();
            let x1 = plot_rect.min.x
                + ((sec.raw_offset.saturating_add(sec.raw_size)) as f32 / size_f).clamp(0.0, 1.0)
                    * plot_rect.width();
            if x1 <= x0 + 1.0 {
                continue;
            }

            // Vertical hairline boundary through waveform
            painter.line_segment(
                [Pos2::new(x0, plot_rect.min.y), Pos2::new(x0, plot_rect.max.y)],
                Stroke::new(1.0_f32, with_alpha(p.rule_strong, 100)),
            );

            // Alternating subtle shade band for section clarity
            if si % 2 == 1 {
                painter.rect_filled(
                    Rect::from_min_max(Pos2::new(x0, plot_rect.min.y), Pos2::new(x1, plot_rect.max.y)),
                    Rounding::ZERO,
                    with_alpha(p.ink, 8),
                );
            }

            // Crisp architectural bracket tick
            let b_stroke = Stroke::new(1.0_f32, p.rule_strong);
            painter.line_segment([Pos2::new(x0, bracket_y), Pos2::new(x1, bracket_y)], b_stroke);
            painter.line_segment([Pos2::new(x0, bracket_y), Pos2::new(x0, bracket_y + 4.0)], b_stroke);
            painter.line_segment([Pos2::new(x1, bracket_y), Pos2::new(x1, bracket_y + 4.0)], b_stroke);

            let width = x1 - x0;
            if width >= 28.0 && x0 >= last_label_right {
                let cx = (x0 + x1) * 0.5;
                let short_name: String = sec.name.chars().take(7).collect();
                painter.text(
                    Pos2::new(cx, bracket_y - 7.0),
                    Align2::CENTER_CENTER,
                    short_name,
                    FontId::monospace(8.5),
                    p.ink_mid,
                );
                last_label_right = x1 + 4.0;
            }
        }
    }

    // Seismograph vertical stem needles + crisp top polyline
    let visible_n = ((ENTROPY_POINTS as f32) * reveal).ceil() as usize;
    let visible_n = visible_n.clamp(0, analysis.entropy_curve.len());

    let mut poly_pts: Vec<Pos2> = Vec::with_capacity(visible_n);
    for i in 0..visible_n {
        let t = i as f32 / (ENTROPY_POINTS.saturating_sub(1).max(1)) as f32;
        let x = plot_rect.min.x + t * plot_rect.width();
        let ent = analysis.entropy_curve[i].clamp(0.0, 8.0);
        let y = plot_rect.max.y - (ent / 8.0) * plot_rect.height();
        poly_pts.push(Pos2::new(x, y));

        // Architectural vertical needle shading underneath curve
        let stem_col = if ent >= 7.2 {
            with_alpha(p.ink, 115)
        } else {
            with_alpha(p.ink_mid, 72)
        };
        painter.line_segment(
            [Pos2::new(x, y + 1.0), Pos2::new(x, plot_rect.max.y)],
            Stroke::new(1.5_f32, stem_col),
        );
    }

    if poly_pts.len() >= 2 {
        painter.add(egui::Shape::line(poly_pts.clone(), Stroke::new(1.8_f32, p.ink)));
    }

    // Bottom offset ruler ticks: 0%, 25%, 50%, 75%, EOF
    for &(frac, lbl) in &[
        (0.0_f32, "0x0"),
        (0.25, "25%"),
        (0.5, "50%"),
        (0.75, "75%"),
        (1.0, "EOF"),
    ] {
        let x = plot_rect.min.x + frac * plot_rect.width();
        painter.text(
            Pos2::new(x, plot_rect.max.y + 10.0),
            Align2::CENTER_CENTER,
            lbl,
            FontId::monospace(8.5),
            p.ink_dim,
        );
    }

    // Active HEX cursor position needle
    if let Some(off) = active_hex_offset {
        if analysis.size > 0 {
            let frac = (off as f32 / analysis.size as f32).clamp(0.0, 1.0);
            let ax = plot_rect.min.x + frac * plot_rect.width();
            painter.line_segment(
                [Pos2::new(ax, plot_rect.min.y), Pos2::new(ax, plot_rect.max.y)],
                Stroke::new(1.0_f32, p.ink_mid),
            );
            // Small inverted marker triangle/square at top
            painter.rect_filled(
                Rect::from_center_size(Pos2::new(ax, plot_rect.min.y), Vec2::splat(5.0)),
                Rounding::ZERO,
                p.ink,
            );
        }
    }

    // Live interactive hover & click/drag scrub
    if let Some(pos) = resp.hover_pos() {
        if plot_rect.expand(6.0).contains(pos) {
            ctx.set_cursor_icon(egui::CursorIcon::Crosshair);
            let frac = ((pos.x - plot_rect.min.x) / plot_rect.width()).clamp(0.0, 1.0);
            let idx = ((frac * (ENTROPY_POINTS - 1) as f32).round() as usize).min(ENTROPY_POINTS - 1);
            let ent = analysis.entropy_curve[idx];
            let byte_off = if analysis.size > 0 {
                ((frac as f64 * (analysis.size - 1) as f64).round() as usize).min(analysis.size - 1)
            } else {
                0
            };

            let hx = plot_rect.min.x + frac * plot_rect.width();
            let hy = plot_rect.max.y - (ent / 8.0) * plot_rect.height();

            // Crisp full-height scanner line + inverted marker dot
            painter.line_segment(
                [Pos2::new(hx, plot_rect.min.y), Pos2::new(hx, plot_rect.max.y)],
                Stroke::new(1.0_f32, p.ink),
            );
            painter.circle_filled(Pos2::new(hx, hy), 4.0, p.ink);
            painter.circle_filled(Pos2::new(hx, hy), 1.8, p.well);

            let sec_str = analysis
                .section_at_offset(byte_off)
                .map(|s| format!("  ·  {}", s.name))
                .unwrap_or_default();

            out.hover_telemetry = Some(format!(
                "OFFSET 0x{:08X} ({:.1}%)  ·  H {:.2} b/B{}  ·  CLICK TO JUMP",
                byte_off,
                frac * 100.0,
                ent,
                sec_str
            ));

            if resp.clicked() || resp.dragged() {
                out.action = Some(PlateAction::JumpOffset {
                    offset: byte_off,
                    reason: format!("ENTROPY 0x{:08X}", byte_off),
                });
            }
        }
    }

    out
}

// ============================================================================
// 03 SPECTRUM — 256-Byte Precision Vertical Impulse Analyzer
// ============================================================================

fn draw_mode_spectrum(
    painter: &egui::Painter,
    inner_box: Rect,
    analysis: &BinaryAnalysis,
    reveal: f32,
    resp: &egui::Response,
    ctx: &egui::Context,
    p: &Palette,
) -> PlateInteraction {
    let mut out = PlateInteraction::default();

    let plot_rect = Rect::from_min_max(
        Pos2::new(inner_box.min.x + 34.0, inner_box.min.y + 28.0),
        Pos2::new(inner_box.max.x - 20.0, inner_box.max.y - 38.0),
    );

    // Subtle horizontal calibration rules (LOG scale)
    for frac in [0.0_f32, 0.25, 0.5, 0.75, 1.0] {
        let y = plot_rect.max.y - frac * plot_rect.height();
        painter.line_segment(
            [Pos2::new(plot_rect.min.x, y), Pos2::new(plot_rect.max.x, y)],
            Stroke::new(1.0_f32, with_alpha(p.hairline, 160)),
        );
    }
    painter.text(
        Pos2::new(plot_rect.min.x - 6.0, plot_rect.min.y),
        Align2::RIGHT_CENTER,
        "MAX",
        FontId::monospace(8.0),
        p.ink_dim,
    );
    painter.text(
        Pos2::new(plot_rect.min.x - 6.0, plot_rect.center().y),
        Align2::RIGHT_CENTER,
        "LOG",
        FontId::monospace(8.0),
        p.ink_dim,
    );
    painter.text(
        Pos2::new(plot_rect.min.x - 6.0, plot_rect.max.y),
        Align2::RIGHT_CENTER,
        "0",
        FontId::monospace(8.0),
        p.ink_dim,
    );

    // Subtle shaded ASCII printable band backdrop (0x20..0x7E)
    let bar_w = plot_rect.width() / 256.0;
    let ascii_x0 = plot_rect.min.x + 32.0 * bar_w;
    let ascii_x1 = plot_rect.min.x + 127.0 * bar_w;
    painter.rect_filled(
        Rect::from_min_max(
            Pos2::new(ascii_x0, plot_rect.min.y),
            Pos2::new(ascii_x1, plot_rect.max.y),
        ),
        Rounding::ZERO,
        with_alpha(p.ink, 9),
    );

    // Determine hovered byte first so we can spotlight it cleanly
    let hovered_byte: Option<usize> = resp.hover_pos().and_then(|pos| {
        if plot_rect.expand2(Vec2::new(0.0, 12.0)).contains(pos) {
            let b = (((pos.x - plot_rect.min.x) / bar_w) as isize).clamp(0, 255) as usize;
            Some(b)
        } else {
            None
        }
    });

    // Draw 256 precision impulse stems
    let log_max = ((analysis.byte_hist_max as f64) + 1.0).ln().max(1e-6);
    for b in 0..256usize {
        let wave_t = b as f32 / 255.0;
        if wave_t > reveal * 1.12 {
            continue;
        }
        let bar_reveal = ((reveal * 1.12 - wave_t) / 0.12).clamp(0.0, 1.0);
        let count = analysis.byte_hist[b];
        let norm = if count == 0 {
            0.0
        } else {
            (((count as f64) + 1.0).ln() / log_max) as f32
        };

        let h = norm * plot_rect.height() * bar_reveal;
        let x = plot_rect.min.x + b as f32 * bar_w;
        let is_hov = hovered_byte == Some(b);
        let is_ascii = (0x20..=0x7E).contains(&b);

        let col = if is_hov {
            p.ink
        } else if b == 0 {
            p.ink
        } else if is_ascii {
            blend(p.ink_mid, p.ink, 0.55 * norm + 0.25)
        } else {
            blend(p.ink_dim, p.ink_mid, norm)
        };

        if h > 0.5 {
            painter.rect_filled(
                Rect::from_min_max(
                    Pos2::new(x, plot_rect.max.y - h),
                    Pos2::new((x + (bar_w - 0.35).max(1.0)).min(plot_rect.max.x), plot_rect.max.y),
                ),
                Rounding::ZERO,
                col,
            );
            // Crisp peak cap pixel for high-frequency bytes
            if is_hov || norm > 0.72 {
                painter.rect_filled(
                    Rect::from_min_size(
                        Pos2::new(x, plot_rect.max.y - h - 2.0),
                        Vec2::new(bar_w.max(1.5), 1.5),
                    ),
                    Rounding::ZERO,
                    p.ink,
                );
            }
        }
    }

    // ASCII Bracket beneath baseline
    let br_y = plot_rect.max.y + 18.0;
    let bs = Stroke::new(1.0_f32, p.rule_strong);
    painter.line_segment([Pos2::new(ascii_x0, br_y), Pos2::new(ascii_x1, br_y)], bs);
    painter.line_segment([Pos2::new(ascii_x0, br_y - 4.0), Pos2::new(ascii_x0, br_y)], bs);
    painter.line_segment([Pos2::new(ascii_x1, br_y - 4.0), Pos2::new(ascii_x1, br_y)], bs);
    painter.text(
        Pos2::new((ascii_x0 + ascii_x1) * 0.5, br_y - 6.0),
        Align2::CENTER_CENTER,
        "ASCII 20..7E",
        FontId::monospace(8.0),
        p.ink_mid,
    );

    // Byte axis ticks
    for &(b, lbl) in &[
        (0usize, "00"),
        (0x20, "20"),
        (0x40, "40"),
        (0x7E, "7E"),
        (0xA0, "A0"),
        (0xC0, "C0"),
        (0xFF, "FF"),
    ] {
        let tx = plot_rect.min.x + (b as f32 + 0.5) * bar_w;
        painter.text(
            Pos2::new(tx, plot_rect.max.y + 7.5),
            Align2::CENTER_CENTER,
            lbl,
            FontId::monospace(8.0),
            p.ink_dim,
        );
    }

    // Interactive hover spotlight + click-to-search byte
    if let Some(b) = hovered_byte {
        ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
        let cx = plot_rect.min.x + (b as f32 + 0.5) * bar_w;
        painter.line_segment(
            [Pos2::new(cx, plot_rect.min.y), Pos2::new(cx, plot_rect.max.y)],
            Stroke::new(1.0_f32, with_alpha(p.ink, 130)),
        );

        let count = analysis.byte_hist[b];
        let pct = if analysis.size > 0 {
            count as f64 / analysis.size as f64 * 100.0
        } else {
            0.0
        };
        let glyph = if (0x20..=0x7E).contains(&b) {
            format!("'{}'", (b as u8) as char)
        } else if b == 0 {
            "NUL".to_string()
        } else if b == 0x0A {
            "LF".to_string()
        } else if b == 0x0D {
            "CR".to_string()
        } else if b == 0x09 {
            "TAB".to_string()
        } else {
            "CTRL/HI".to_string()
        };

        // Minimal top spotlight tag inside plot
        let pin = format!("0x{:02X} {}", b, glyph);
        let pin_x = cx.clamp(plot_rect.min.x + 36.0, plot_rect.max.x - 36.0);
        let pin_pos = Pos2::new(pin_x, plot_rect.min.y + 8.0);
        let pin_g = painter.layout_no_wrap(pin.clone(), FontId::monospace(9.0), p.invert_fg);
        painter.rect_filled(
            Rect::from_center_size(pin_pos, Vec2::new(pin_g.size().x + 8.0, 14.0)),
            Rounding::same(1.0),
            p.invert_bg,
        );
        painter.text(pin_pos, Align2::CENTER_CENTER, pin, FontId::monospace(9.0), p.invert_fg);

        out.hover_telemetry = Some(format!(
            "BYTE 0x{:02X} {}  ·  COUNT {} ({:.2}%)  ·  CLICK TO FIND IN HEX",
            b, glyph, count, pct
        ));

        if resp.clicked() {
            out.action = Some(PlateAction::SearchByte { byte: b as u8 });
        }
    }

    out
}

// ============================================================================
// 04 HILBERT — True 64x32 Space-Filling Hilbert Cartographic Atlas
// ============================================================================

fn draw_mode_hilbert(
    painter: &egui::Painter,
    inner_box: Rect,
    analysis: &BinaryAnalysis,
    show_trail: bool,
    reveal: f32,
    active_hex_offset: Option<usize>,
    resp: &egui::Response,
    ctx: &egui::Context,
    p: &Palette,
) -> PlateInteraction {
    let mut out = PlateInteraction::default();

    let pad_x = 24.0_f32;
    let pad_t = 24.0_f32;
    let pad_b = 26.0_f32;
    let avail_w = (inner_box.width() - pad_x * 2.0).max(64.0);
    let avail_h = (inner_box.height() - pad_t - pad_b).max(32.0);

    // Maintain exact 2:1 aspect ratio for 64x32 Hilbert squares
    let tile_sz = (avail_w / HILBERT_W as f32).min(avail_h / HILBERT_H as f32);
    let map_w = tile_sz * HILBERT_W as f32;
    let map_h = tile_sz * HILBERT_H as f32;
    let origin = Pos2::new(
        inner_box.center().x - map_w * 0.5,
        inner_box.center().y - map_h * 0.5,
    );
    let map_rect = Rect::from_min_size(origin, Vec2::new(map_w, map_h));

    painter.rect_stroke(map_rect, Rounding::ZERO, Stroke::new(1.0_f32, p.hairline));

    let max_d = ((analysis.hilbert_tiles.len() as f32) * reveal).ceil() as usize;

    // Render each tile with distinct monochrome cartographic texture by ByteRegionClass
    for tile in analysis.hilbert_tiles.iter().take(max_d) {
        let tr = Rect::from_min_size(
            Pos2::new(
                origin.x + tile.x as f32 * tile_sz,
                origin.y + tile.y as f32 * tile_sz,
            ),
            Vec2::splat(tile_sz),
        );
        let inset = tr.shrink(0.45);

        match tile.class {
            ByteRegionClass::Zero => {
                // Sparse architectural dot on dark well
                painter.rect_filled(
                    Rect::from_center_size(tr.center(), Vec2::splat((tile_sz * 0.22).max(1.2))),
                    Rounding::ZERO,
                    p.hairline,
                );
            }
            ByteRegionClass::Ascii => {
                // Crisp 45-degree diagonal architectural hatch for printable text continents
                painter.rect_filled(inset, Rounding::ZERO, blend(p.well, p.ink, 0.14));
                painter.line_segment(
                    [
                        Pos2::new(inset.min.x + 1.0, inset.max.y - 1.0),
                        Pos2::new(inset.max.x - 1.0, inset.min.y + 1.0),
                    ],
                    Stroke::new(1.0_f32, p.ink_mid),
                );
            }
            ByteRegionClass::Code => {
                // Luminance-stepped architectural blocks scaled smoothly by Shannon entropy
                let norm = (tile.entropy / 7.2).clamp(0.15, 0.92);
                let col = blend(p.well, p.ink, 0.20 + norm * 0.62);
                painter.rect_filled(inset, Rounding::ZERO, col);
            }
            ByteRegionClass::HighEntropy => {
                // Solid pure ink block with tiny contrast pinhole for packed/encrypted zones
                painter.rect_filled(inset, Rounding::ZERO, p.ink);
                if tile_sz >= 5.5 {
                    painter.rect_filled(
                        Rect::from_center_size(tr.center(), Vec2::splat((tile_sz * 0.22).max(1.2))),
                        Rounding::ZERO,
                        p.well,
                    );
                }
            }
        }
    }

    // Center seam hairline subtly dividing Quadrant I (0..50%) and Quadrant II (50..100%)
    let mid_x = origin.x + map_w * 0.5;
    painter.line_segment(
        [Pos2::new(mid_x, map_rect.min.y), Pos2::new(mid_x, map_rect.max.y)],
        Stroke::new(1.0_f32, with_alpha(p.well, 180)),
    );

    // Optional continuous Hilbert Space-Filling Curve TRAIL overlay
    if show_trail && max_d >= 2 {
        let mut pts = Vec::with_capacity(max_d);
        for tile in analysis.hilbert_tiles.iter().take(max_d) {
            pts.push(Pos2::new(
                origin.x + (tile.x as f32 + 0.5) * tile_sz,
                origin.y + (tile.y as f32 + 0.5) * tile_sz,
            ));
        }
        // Subtle matte halo + crisp hairline trail so it stays legible over both light & dark zones
        painter.add(egui::Shape::line(
            pts.clone(),
            Stroke::new(2.0_f32, with_alpha(p.well, 130)),
        ));
        painter.add(egui::Shape::line(
            pts,
            Stroke::new(0.85_f32, with_alpha(p.ink, 175)),
        ));
    }

    // Minimal inline cartographic legend at bottom left/right of inner_box
    let leg_y = map_rect.max.y + 11.0;
    painter.text(
        Pos2::new(map_rect.min.x, leg_y),
        Align2::LEFT_CENTER,
        "· ZERO   / ASCII   ■ CODE   ▣ PACKED",
        FontId::monospace(8.0),
        p.ink_dim,
    );
    painter.text(
        Pos2::new(map_rect.max.x, leg_y),
        Align2::RIGHT_CENTER,
        "0x0 → EOF",
        FontId::monospace(8.0),
        p.ink_dim,
    );

    // Active HEX cursor tile highlight
    if let Some(off) = active_hex_offset {
        if analysis.size > 0 && !analysis.hilbert_tiles.is_empty() {
            let d = ((off as f64 / analysis.size as f64) * analysis.hilbert_tiles.len() as f64)
                .floor() as usize;
            let d = d.min(analysis.hilbert_tiles.len() - 1);
            let t = analysis.hilbert_tiles[d];
            let tr = Rect::from_min_size(
                Pos2::new(
                    origin.x + t.x as f32 * tile_sz,
                    origin.y + t.y as f32 * tile_sz,
                ),
                Vec2::splat(tile_sz),
            );
            painter.rect_stroke(tr.expand(1.5), Rounding::ZERO, Stroke::new(1.5_f32, p.ink));
        }
    }

    // Live hover & click-to-jump
    if let Some(pos) = resp.hover_pos() {
        if map_rect.contains(pos) {
            ctx.set_cursor_icon(egui::CursorIcon::Crosshair);
            let gx = (((pos.x - origin.x) / tile_sz) as usize).min(HILBERT_W - 1);
            let gy = (((pos.y - origin.y) / tile_sz) as usize).min(HILBERT_H - 1);
            let d = analysis.hilbert_grid[gy * HILBERT_W + gx];
            let tile = analysis.hilbert_tiles[d];

            let tr = Rect::from_min_size(
                Pos2::new(origin.x + gx as f32 * tile_sz, origin.y + gy as f32 * tile_sz),
                Vec2::splat(tile_sz),
            );
            painter.rect_stroke(tr.expand(1.5), Rounding::ZERO, Stroke::new(1.5_f32, p.ink));
            painter.rect_stroke(tr.expand(2.5), Rounding::ZERO, Stroke::new(1.0_f32, p.well));

            let sec_str = analysis
                .section_at_offset(tile.start_offset)
                .map(|s| format!("  ·  {}", s.name))
                .unwrap_or_default();

            out.hover_telemetry = Some(format!(
                "0x{:08X}..{:08X}{}  ·  H {:.2}  ·  {}  ·  CLICK TO JUMP",
                tile.start_offset,
                tile.end_offset,
                sec_str,
                tile.entropy,
                tile.class.label()
            ));

            if resp.clicked() || resp.dragged() {
                out.action = Some(PlateAction::JumpOffset {
                    offset: tile.start_offset,
                    reason: format!("HILBERT 0x{:08X}", tile.start_offset),
                });
            }
        }
    }

    out
}

// ============================================================================
// Vector SVG Archival Poster Generator (1200 x 840)
// ============================================================================

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn generate_binary_svg(
    analysis: &BinaryAnalysis,
    mode: VizMode,
    show_trail: bool,
    dark_mode: bool,
    font_stack: &str,
) -> String {
    let (bg, well, hairline, strong, ink, ink_mid, ink_dim) = if dark_mode {
        (
            "#060607", "#030304", "#1E1E23", "#40404A", "#F5F5F7", "#9C9CA6", "#565660",
        )
    } else {
        (
            "#F4F3EE", "#ECEBE5", "#D6D4CC", "#94928A", "#0C0C0E", "#54545A", "#908E88",
        )
    };

    let mut svg = String::with_capacity(32 * 1024);
    svg.push_str(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="840" viewBox="0 0 1200 840">
"##,
    );
    svg.push_str(&format!(
        "<rect width=\"1200\" height=\"840\" fill=\"{bg}\"/>\n"
    ));

    // Outer archival margin & header
    svg.push_str(&format!(
        "<rect x=\"48\" y=\"48\" width=\"1104\" height=\"744\" fill=\"none\" stroke=\"{hairline}\" stroke-width=\"1\"/>\n"
    ));
    svg.push_str(&format!(
        "<text x=\"80\" y=\"96\" fill=\"{ink_dim}\" font-family=\"{font_stack}\" font-size=\"12\" letter-spacing=\"3\">BINVIEW // SPECIMEN PLATE</text>\n"
    ));
    svg.push_str(&format!(
        "<text x=\"80\" y=\"132\" fill=\"{ink}\" font-family=\"'Space Grotesk', sans-serif\" font-size=\"30\" font-weight=\"500\">{}</text>\n",
        escape_xml(&analysis.file_name)
    ));
    svg.push_str(&format!(
        "<text x=\"1120\" y=\"96\" text-anchor=\"end\" fill=\"{ink_mid}\" font-family=\"{font_stack}\" font-size=\"12\">{} · H {:.2} b/B · {}</text>\n",
        escape_xml(&analysis.format.format_short),
        analysis.entropy,
        escape_xml(analysis.entropy_class.label())
    ));

    // Plate frame (80, 160, 1040 x 520)
    let px = 80.0_f32;
    let py = 160.0_f32;
    let pw = 1040.0_f32;
    let ph = 520.0_f32;
    svg.push_str(&format!(
        "<rect x=\"{px}\" y=\"{py}\" width=\"{pw}\" height=\"{ph}\" rx=\"3\" fill=\"{well}\" stroke=\"{hairline}\" stroke-width=\"1\"/>\n"
    ));

    // Crop marks
    let arm = 14.0_f32;
    let cm = 12.0_f32;
    for (cx, cy, dx, dy) in [
        (px + cm, py + cm, arm, arm),
        (px + pw - cm, py + cm, -arm, arm),
        (px + cm, py + ph - cm, arm, -arm),
        (px + pw - cm, py + ph - cm, -arm, -arm),
    ] {
        svg.push_str(&format!(
            "<line x1=\"{cx}\" y1=\"{cy}\" x2=\"{}\" y2=\"{cy}\" stroke=\"{strong}\" stroke-width=\"1\"/>\n",
            cx + dx
        ));
        svg.push_str(&format!(
            "<line x1=\"{cx}\" y1=\"{cy}\" x2=\"{cx}\" y2=\"{}\" stroke=\"{strong}\" stroke-width=\"1\"/>\n",
            cy + dy
        ));
    }

    // Inner box
    let ix = px + 36.0;
    let iy = py + 34.0;
    let iw = pw - 72.0;
    let ih = ph - 68.0;
    svg.push_str(&format!(
        "<rect x=\"{ix}\" y=\"{iy}\" width=\"{iw}\" height=\"{ih}\" fill=\"none\" stroke=\"{strong}\" stroke-width=\"1\"/>\n"
    ));

    match mode {
        VizMode::Digraph => {
            let side = ih - 56.0;
            let gx = ix + (iw - side) * 0.5;
            let gy = iy + 28.0;
            let cell = side / DIGRAPH_DIM as f32;
            svg.push_str(&format!(
                "<rect x=\"{gx:.1}\" y=\"{gy:.1}\" width=\"{side:.1}\" height=\"{side:.1}\" fill=\"none\" stroke=\"{hairline}\" stroke-width=\"1\"/>\n"
            ));
            for y in 0..DIGRAPH_DIM {
                for x in 0..DIGRAPH_DIM {
                    let d = analysis.digraph[y * DIGRAPH_DIM + x];
                    if d <= 0.01 {
                        continue;
                    }
                    let op = (0.16 + 0.84 * d.powf(0.85)).clamp(0.0, 1.0);
                    let sz = (cell * (0.45 + 0.55 * d.powf(0.7))).max(1.5);
                    let cx = gx + (x as f32 + 0.5) * cell - sz * 0.5;
                    let cy = gy + (y as f32 + 0.5) * cell - sz * 0.5;
                    svg.push_str(&format!(
                        "<rect x=\"{cx:.1}\" y=\"{cy:.1}\" width=\"{sz:.1}\" height=\"{sz:.1}\" fill=\"{ink}\" fill-opacity=\"{op:.2}\"/>\n"
                    ));
                }
            }
        }
        VizMode::Entropy => {
            let rx = ix + 56.0;
            let ry = iy + 40.0;
            let rw = iw - 84.0;
            let rh = ih - 78.0;
            for val in [0.0_f32, 4.0, 7.2, 8.0] {
                let y = ry + rh - (val / 8.0) * rh;
                svg.push_str(&format!(
                    "<line x1=\"{rx:.1}\" y1=\"{y:.1}\" x2=\"{:.1}\" y2=\"{y:.1}\" stroke=\"{hairline}\" stroke-width=\"1\"/>\n",
                    rx + rw
                ));
                svg.push_str(&format!(
                    "<text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\" fill=\"{ink_dim}\" font-family=\"{font_stack}\" font-size=\"10\">{:.1}</text>\n",
                    rx - 8.0,
                    y + 3.5,
                    val
                ));
            }
            let mut poly = String::new();
            for (i, &ent) in analysis.entropy_curve.iter().enumerate() {
                let t = i as f32 / (ENTROPY_POINTS.saturating_sub(1).max(1)) as f32;
                let x = rx + t * rw;
                let y = ry + rh - (ent.clamp(0.0, 8.0) / 8.0) * rh;
                svg.push_str(&format!(
                    "<line x1=\"{x:.1}\" y1=\"{y:.1}\" x2=\"{x:.1}\" y2=\"{:.1}\" stroke=\"{ink_mid}\" stroke-opacity=\"0.35\" stroke-width=\"2\"/>\n",
                    ry + rh
                ));
                poly.push_str(&format!("{x:.1},{y:.1} "));
            }
            svg.push_str(&format!(
                "<polyline fill=\"none\" stroke=\"{ink}\" stroke-width=\"2.2\" points=\"{poly}\"/>\n"
            ));
        }
        VizMode::Spectrum => {
            let rx = ix + 44.0;
            let ry = iy + 32.0;
            let rw = iw - 72.0;
            let rh = ih - 72.0;
            let bw = rw / 256.0;
            let log_max = ((analysis.byte_hist_max as f64) + 1.0).ln().max(1e-6);
            for b in 0..256usize {
                let c = analysis.byte_hist[b];
                if c == 0 {
                    continue;
                }
                let norm = (((c as f64) + 1.0).ln() / log_max) as f32;
                let h = norm * rh;
                let x = rx + b as f32 * bw;
                let y = ry + rh - h;
                let op = if (0x20..=0x7E).contains(&b) || b == 0 {
                    0.92
                } else {
                    0.55
                };
                svg.push_str(&format!(
                    "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{:.1}\" height=\"{h:.1}\" fill=\"{ink}\" fill-opacity=\"{op:.2}\"/>\n",
                    (bw - 0.5).max(1.2)
                ));
            }
        }
        VizMode::Hilbert => {
            let tile = ((iw - 48.0) / HILBERT_W as f32).min((ih - 52.0) / HILBERT_H as f32);
            let mw = tile * HILBERT_W as f32;
            let mh = tile * HILBERT_H as f32;
            let ox = ix + (iw - mw) * 0.5;
            let oy = iy + (ih - mh) * 0.5;
            for t in &analysis.hilbert_tiles {
                let x = ox + t.x as f32 * tile;
                let y = oy + t.y as f32 * tile;
                match t.class {
                    ByteRegionClass::Zero => {
                        svg.push_str(&format!(
                            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"2\" height=\"2\" fill=\"{hairline}\"/>\n",
                            x + tile * 0.5 - 1.0,
                            y + tile * 0.5 - 1.0
                        ));
                    }
                    ByteRegionClass::Ascii => {
                        svg.push_str(&format!(
                            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{ink}\" fill-opacity=\"0.12\"/>\n",
                            x + 0.5,
                            y + 0.5,
                            tile - 1.0,
                            tile - 1.0
                        ));
                        svg.push_str(&format!(
                            "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"{ink_mid}\" stroke-width=\"1\"/>\n",
                            x + 1.5,
                            y + tile - 1.5,
                            x + tile - 1.5,
                            y + 1.5
                        ));
                    }
                    ByteRegionClass::Code => {
                        let op = (0.20 + (t.entropy / 7.2).clamp(0.15, 0.92) * 0.62).clamp(0.0, 1.0);
                        svg.push_str(&format!(
                            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{ink}\" fill-opacity=\"{op:.2}\"/>\n",
                            x + 0.5,
                            y + 0.5,
                            tile - 1.0,
                            tile - 1.0
                        ));
                    }
                    ByteRegionClass::HighEntropy => {
                        svg.push_str(&format!(
                            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{ink}\"/>\n",
                            x + 0.5,
                            y + 0.5,
                            tile - 1.0,
                            tile - 1.0
                        ));
                        svg.push_str(&format!(
                            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"2.5\" height=\"2.5\" fill=\"{well}\"/>\n",
                            x + tile * 0.5 - 1.25,
                            y + tile * 0.5 - 1.25
                        ));
                    }
                }
            }
            if show_trail {
                let mut pts = String::new();
                for t in &analysis.hilbert_tiles {
                    pts.push_str(&format!(
                        "{:.1},{:.1} ",
                        ox + (t.x as f32 + 0.5) * tile,
                        oy + (t.y as f32 + 0.5) * tile
                    ));
                }
                svg.push_str(&format!(
                    "<polyline fill=\"none\" stroke=\"{ink}\" stroke-opacity=\"0.65\" stroke-width=\"1\" points=\"{pts}\"/>\n"
                ));
            }
        }
    }

    // Minimal 1-word top & bottom cutouts
    let top_tag = format!("[ {} ]", analysis.format.format_short.to_uppercase());
    let bot_tag = format!("[ {} ]", mode.cutout_tag());
    let mid_x = ix + iw * 0.5;
    svg.push_str(&format!(
        "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"120\" height=\"18\" fill=\"{well}\"/>\n",
        mid_x - 60.0,
        iy - 9.0
    ));
    svg.push_str(&format!(
        "<text x=\"{mid_x:.1}\" y=\"{:.1}\" text-anchor=\"middle\" fill=\"{ink}\" font-family=\"{font_stack}\" font-size=\"12\">{}</text>\n",
        iy + 4.0,
        escape_xml(&top_tag)
    ));
    svg.push_str(&format!(
        "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"128\" height=\"18\" fill=\"{well}\"/>\n",
        mid_x - 64.0,
        iy + ih - 9.0
    ));
    svg.push_str(&format!(
        "<text x=\"{mid_x:.1}\" y=\"{:.1}\" text-anchor=\"middle\" fill=\"{ink_mid}\" font-family=\"{font_stack}\" font-size=\"11\">{}</text>\n",
        iy + ih + 4.0,
        escape_xml(&bot_tag)
    ));

    // Footer: 4x8x2 Safety-Number SHA-256 Digest
    let (l1, l2) = format_safety_blocks(&analysis.sha256);
    svg.push_str(&format!(
        "<text x=\"600\" y=\"726\" text-anchor=\"middle\" fill=\"{ink}\" font-family=\"{font_stack}\" font-size=\"14\" letter-spacing=\"1.5\">{}</text>\n",
        escape_xml(&l1)
    ));
    svg.push_str(&format!(
        "<text x=\"600\" y=\"752\" text-anchor=\"middle\" fill=\"{ink_mid}\" font-family=\"{font_stack}\" font-size=\"14\" letter-spacing=\"1.5\">{}</text>\n",
        escape_xml(&l2)
    ));
    svg.push_str("</svg>\n");
    svg
}
