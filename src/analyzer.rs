use chrono::{DateTime, Utc};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub const DIGRAPH_DIM: usize = 64;
pub const ENTROPY_POINTS: usize = 128;
pub const HILBERT_W: usize = 64;
pub const HILBERT_H: usize = 32;
pub const HILBERT_LEN: usize = HILBERT_W * HILBERT_H;
const MAX_STRINGS: usize = 2500;
const MAX_DIFF_RANGES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    Low,
    Text,
    Code,
    Packed,
}

impl EntropyClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Text => "TEXT",
            Self::Code => "CODE",
            Self::Packed => "COMPRESSED / ENCRYPTED",
        }
    }

    pub fn from_entropy(e: f32) -> Self {
        if e < 2.2 {
            Self::Low
        } else if e < 5.0 {
            Self::Text
        } else if e < 7.2 {
            Self::Code
        } else {
            Self::Packed
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRegionClass {
    Zero,
    Ascii,
    Code,
    HighEntropy,
}

impl ByteRegionClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Zero => "ZERO / PAD",
            Self::Ascii => "ASCII / TEXT",
            Self::Code => "CODE / DATA",
            Self::HighEntropy => "PACKED / HIGH-H",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_addr: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub flags: String,
    pub entropy: f32,
}

#[derive(Debug, Clone)]
pub struct FormatMetadata {
    pub format_short: String,
    pub format_long: String,
    pub details: Vec<(String, String)>,
    pub sections: Vec<SectionInfo>,
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub offset: usize,
    pub value: String,
}

#[derive(Debug, Clone, Copy)]
pub struct HilbertTile {
    pub x: usize,
    pub y: usize,
    pub start_offset: usize,
    pub end_offset: usize,
    pub entropy: f32,
    pub class: ByteRegionClass,
}

#[derive(Debug, Clone)]
pub struct BinaryAnalysis {
    pub file_name: String,
    pub file_path: String,
    pub size: usize,
    pub bytes: Arc<Vec<u8>>,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub entropy: f32,
    pub entropy_class: EntropyClass,
    pub null_pct: f32,
    pub ascii_pct: f32,
    pub format: FormatMetadata,

    // Precomputed visualization buffers
    pub digraph: Vec<f32>,
    pub digraph_counts: Vec<u64>,
    pub digraph_sample_offset: Vec<Option<usize>>,
    pub entropy_curve: Vec<f32>,
    pub byte_hist: [u64; 256],
    pub byte_hist_max: u64,
    pub hilbert_tiles: Vec<HilbertTile>,
    pub hilbert_grid: Vec<usize>, // y * HILBERT_W + x -> d

    // Extracted ASCII strings
    pub strings: Vec<ExtractedString>,
    pub strings_truncated: bool,
    pub min_string_len: usize,
    pub analyzed_ms: u64,
}

impl BinaryAnalysis {
    pub fn section_at_offset(&self, offset: usize) -> Option<&SectionInfo> {
        let off = offset as u64;
        self.format
            .sections
            .iter()
            .find(|s| s.raw_size > 0 && off >= s.raw_offset && off < s.raw_offset.saturating_add(s.raw_size))
    }

    pub fn re_extract_strings(&mut self, min_len: usize) {
        let (strings, truncated) = extract_ascii_strings(&self.bytes, min_len, MAX_STRINGS);
        self.strings = strings;
        self.strings_truncated = truncated;
        self.min_string_len = min_len;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    Auto,
    Hex,
    Ascii,
}

impl SearchMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Auto => "AUTO",
            Self::Hex => "HEX",
            Self::Ascii => "ASCII",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchOutcome {
    pub pattern: Vec<u8>,
    pub interpreted_as: &'static str,
    pub offsets: Vec<usize>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct DiffRange {
    pub offset: usize,
    pub len: usize,
    pub sample_a: Vec<u8>,
    pub sample_b: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BinaryDiff {
    pub other_name: String,
    pub other_path: String,
    pub other_sha256: String,
    pub size_a: usize,
    pub size_b: usize,
    pub size_delta: i64,
    pub sha256_match: bool,
    pub identical_bytes: usize,
    pub differing_bytes: usize,
    pub identical_pct: f32,
    pub ranges: Vec<DiffRange>,
    pub total_ranges: usize,
}

pub fn analyze_file(path: &Path, min_string_len: usize) -> Result<BinaryAnalysis, String> {
    let data = std::fs::read(path).map_err(|e| format!("READ FAILED: {}", e))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "binary".to_string());
    let path_str = path.display().to_string();
    Ok(analyze_bytes(name, path_str, data, min_string_len))
}

pub fn analyze_bytes(
    file_name: String,
    file_path: String,
    data: Vec<u8>,
    min_string_len: usize,
) -> BinaryAnalysis {
    let t0 = Instant::now();
    let size = data.len();

    // Cryptographic digests
    let sha256 = hex::encode(Sha256::digest(&data));
    let sha1 = hex::encode(Sha1::digest(&data));
    let md5 = hex::encode(Md5::digest(&data));

    // Byte frequency histogram
    let mut byte_hist = [0u64; 256];
    for &b in &data {
        byte_hist[b as usize] += 1;
    }
    let byte_hist_max = byte_hist.iter().copied().max().unwrap_or(0);

    let entropy = shannon_entropy_from_hist(&byte_hist, size);
    let entropy_class = EntropyClass::from_entropy(entropy);

    let null_count = byte_hist[0];
    let ascii_count: u64 = (0x20usize..=0x7E)
        .map(|i| byte_hist[i])
        .sum::<u64>()
        + byte_hist[b'\n' as usize]
        + byte_hist[b'\r' as usize]
        + byte_hist[b'\t' as usize];

    let (null_pct, ascii_pct) = if size > 0 {
        (
            (null_count as f64 / size as f64 * 100.0) as f32,
            (ascii_count as f64 / size as f64 * 100.0) as f32,
        )
    } else {
        (0.0, 0.0)
    };

    // Format & Header Parser
    let format = parse_format(&data);

    // 64x64 Binned Bigram Digraph (256x256 -> 64x64)
    let mut digraph_counts = vec![0u64; DIGRAPH_DIM * DIGRAPH_DIM];
    let mut digraph_sample_offset = vec![None; DIGRAPH_DIM * DIGRAPH_DIM];
    if data.len() >= 2 {
        // For huge files (>16MB), stride gracefully while keeping accuracy high
        let step = if data.len() > 16 * 1024 * 1024 {
            (data.len() / (8 * 1024 * 1024)).max(1)
        } else {
            1
        };
        let mut i = 0usize;
        let limit = data.len() - 1;
        while i < limit {
            let bx = (data[i] >> 2) as usize;
            let by = (data[i + 1] >> 2) as usize;
            let cell = by * DIGRAPH_DIM + bx;
            digraph_counts[cell] += 1;
            if digraph_sample_offset[cell].is_none() {
                digraph_sample_offset[cell] = Some(i);
            }
            i += step;
        }
    }
    let digraph_max_count = digraph_counts.iter().copied().max().unwrap_or(0);
    let log_denom = ((digraph_max_count as f64) + 1.0).ln().max(1e-6);
    let digraph: Vec<f32> = digraph_counts
        .iter()
        .map(|&c| {
            if c == 0 {
                0.0
            } else {
                (((c as f64) + 1.0).ln() / log_denom) as f32
            }
        })
        .collect();

    // 128-point Windowed Entropy Curve
    let mut entropy_curve = vec![0.0_f32; ENTROPY_POINTS];
    if size > 0 {
        for (i, slot) in entropy_curve.iter_mut().enumerate() {
            let start = (i * size) / ENTROPY_POINTS;
            let end = (((i + 1) * size) / ENTROPY_POINTS).max(start + 1).min(size);
            *slot = shannon_entropy(&data[start..end]);
        }
    }

    // 64x32 Space-Filling Hilbert Structural Atlas
    let (hilbert_tiles, hilbert_grid) = build_hilbert_map(&data);

    // Printable ASCII Strings
    let (strings, strings_truncated) = extract_ascii_strings(&data, min_string_len, MAX_STRINGS);

    let analyzed_ms = t0.elapsed().as_millis() as u64;

    BinaryAnalysis {
        file_name,
        file_path,
        size,
        bytes: Arc::new(data),
        sha256,
        sha1,
        md5,
        entropy,
        entropy_class,
        null_pct,
        ascii_pct,
        format,
        digraph,
        digraph_counts,
        digraph_sample_offset,
        entropy_curve,
        byte_hist,
        byte_hist_max,
        hilbert_tiles,
        hilbert_grid,
        strings,
        strings_truncated,
        min_string_len,
        analyzed_ms,
    }
}

pub fn shannon_entropy(slice: &[u8]) -> f32 {
    if slice.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in slice {
        counts[b as usize] += 1;
    }
    shannon_entropy_from_hist(&counts, slice.len())
}

fn shannon_entropy_from_hist(counts: &[u64; 256], len: usize) -> f32 {
    if len == 0 {
        return 0.0;
    }
    let total = len as f64;
    let mut ent = 0.0_f64;
    for &c in counts {
        if c > 0 {
            let p = c as f64 / total;
            ent -= p * p.log2();
        }
    }
    (ent as f32).clamp(0.0, 8.0)
}

/// Converts a 1D Hilbert index `d` in `[0, n*n)` to 2D coordinates `(x, y)` in `[0, n)`.
/// Standard orientation: `d=0 -> (0,0)`, `d=n*n-1 -> (n-1, 0)`.
pub fn hilbert_d2xy(n: usize, mut d: usize) -> (usize, usize) {
    let mut x = 0usize;
    let mut y = 0usize;
    let mut s = 1usize;
    while s < n {
        let rx = 1 & (d / 2);
        let ry = 1 & (d ^ rx);
        if ry == 0 {
            if rx == 1 {
                x = s - 1 - x;
                y = s - 1 - y;
            }
            std::mem::swap(&mut x, &mut y);
        }
        x += s * rx;
        y += s * ry;
        d /= 4;
        s *= 2;
    }
    (x, y)
}

/// Builds a continuous 64x32 Hilbert Atlas (two seamless 32x32 order-5 Hilbert squares).
fn build_hilbert_map(data: &[u8]) -> (Vec<HilbertTile>, Vec<usize>) {
    let mut tiles = Vec::with_capacity(HILBERT_LEN);
    let mut grid = vec![0usize; HILBERT_LEN];
    let size = data.len();

    for d in 0..HILBERT_LEN {
        let (x, y) = if d < 1024 {
            hilbert_d2xy(32, d)
        } else {
            let (rx, ry) = hilbert_d2xy(32, d - 1024);
            (rx + 32, ry)
        };

        let (start_offset, end_offset, entropy, class) = if size == 0 {
            (0, 0, 0.0, ByteRegionClass::Zero)
        } else {
            let start = (d * size) / HILBERT_LEN;
            let end = (((d + 1) * size) / HILBERT_LEN).max(start + 1).min(size);
            let slice = &data[start..end];
            // Cap per-tile sample stride if tile > 8192 bytes so huge binaries stay instant
            let mut counts = [0u64; 256];
            let mut sample_n = 0usize;
            let mut nulls = 0usize;
            let mut asciis = 0usize;
            let stride = if slice.len() > 8192 {
                slice.len() / 4096
            } else {
                1
            };
            let mut i = 0;
            while i < slice.len() {
                let b = slice[i];
                counts[b as usize] += 1;
                if b == 0 {
                    nulls += 1;
                } else if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                    asciis += 1;
                }
                sample_n += 1;
                i += stride;
            }
            let ent = shannon_entropy_from_hist(&counts, sample_n);
            let nr = if sample_n > 0 {
                nulls as f32 / sample_n as f32
            } else {
                0.0
            };
            let ar = if sample_n > 0 {
                asciis as f32 / sample_n as f32
            } else {
                0.0
            };
            let cls = if nr >= 0.72 || ent < 0.35 {
                ByteRegionClass::Zero
            } else if ent >= 7.15 {
                ByteRegionClass::HighEntropy
            } else if ar >= 0.75 {
                ByteRegionClass::Ascii
            } else {
                ByteRegionClass::Code
            };
            (start, end, ent, cls)
        };

        grid[y * HILBERT_W + x] = d;
        tiles.push(HilbertTile {
            x,
            y,
            start_offset,
            end_offset,
            entropy,
            class,
        });
    }

    (tiles, grid)
}

pub fn extract_ascii_strings(
    data: &[u8],
    min_len: usize,
    max_items: usize,
) -> (Vec<ExtractedString>, bool) {
    let min_len = min_len.max(2);
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut truncated = false;

    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..=0x7E).contains(&b);
        if printable {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(st) = start.take() {
            if i - st >= min_len {
                if out.len() >= max_items {
                    truncated = true;
                    break;
                }
                let end = i.min(st + 160);
                let mut s = String::from_utf8_lossy(&data[st..end]).to_string();
                if i - st > 160 {
                    s.push('…');
                }
                out.push(ExtractedString {
                    offset: st,
                    value: s,
                });
            }
        }
    }

    if !truncated {
        if let Some(st) = start {
            if data.len() - st >= min_len {
                if out.len() >= max_items {
                    truncated = true;
                } else {
                    let end = data.len().min(st + 160);
                    let mut s = String::from_utf8_lossy(&data[st..end]).to_string();
                    if data.len() - st > 160 {
                        s.push('…');
                    }
                    out.push(ExtractedString {
                        offset: st,
                        value: s,
                    });
                }
            }
        }
    }

    (out, truncated)
}

/// Searches a binary buffer by Hex byte sequence or ASCII string.
pub fn search_binary(
    data: &[u8],
    raw_query: &str,
    mode: SearchMode,
    max_results: usize,
) -> Result<SearchOutcome, String> {
    let q = raw_query.trim();
    if q.is_empty() {
        return Err("EMPTY QUERY".into());
    }

    let (pattern, interpreted_as) = match mode {
        SearchMode::Hex => (parse_hex_pattern(q)?, "HEX"),
        SearchMode::Ascii => (q.as_bytes().to_vec(), "ASCII"),
        SearchMode::Auto => {
            if let Some(rest) = q.strip_prefix("hex:").or_else(|| q.strip_prefix("HEX:")) {
                (parse_hex_pattern(rest.trim())?, "HEX")
            } else if looks_like_hex_sequence(q) {
                if let Ok(bytes) = parse_hex_pattern(q) {
                    (bytes, "HEX")
                } else {
                    (q.as_bytes().to_vec(), "ASCII")
                }
            } else {
                (q.as_bytes().to_vec(), "ASCII")
            }
        }
    };

    if pattern.is_empty() {
        return Err("EMPTY PATTERN".into());
    }

    let mut offsets = Vec::new();
    let mut truncated = false;
    if pattern.len() <= data.len() {
        let first = pattern[0];
        let mut i = 0usize;
        let last = data.len() - pattern.len();
        while i <= last {
            if data[i] == first && data[i..i + pattern.len()] == pattern[..] {
                if offsets.len() >= max_results {
                    truncated = true;
                    break;
                }
                offsets.push(i);
                i += 1;
            } else {
                i += 1;
            }
        }
    }

    Ok(SearchOutcome {
        pattern,
        interpreted_as,
        offsets,
        truncated,
    })
}

fn looks_like_hex_sequence(q: &str) -> bool {
    let tokens: Vec<&str> = q.split_whitespace().collect();
    if tokens.is_empty() {
        return false;
    }
    if tokens.len() == 1 {
        let t = tokens[0];
        if let Some(stripped) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            return !stripped.is_empty()
                && stripped.len() % 2 == 0
                && stripped.chars().all(|c| c.is_ascii_hexdigit());
        }
        return false;
    }
    tokens.iter().all(|t| {
        let s = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit())
    })
}

fn parse_hex_pattern(q: &str) -> Result<Vec<u8>, String> {
    let mut cleaned = String::new();
    for tok in q.split_whitespace() {
        let s = tok
            .strip_prefix("0x")
            .or_else(|| tok.strip_prefix("0X"))
            .unwrap_or(tok);
        cleaned.push_str(s);
    }
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return Err("HEX MUST BE EVEN DIGITS (E.G. 4D 5A 90 00)".into());
    }
    hex::decode(&cleaned).map_err(|_| "INVALID HEX BYTES".into())
}

pub fn compare_binaries(a: &BinaryAnalysis, b: &BinaryAnalysis) -> BinaryDiff {
    let ba = a.bytes.as_slice();
    let bb = b.bytes.as_slice();
    let min_len = ba.len().min(bb.len());
    let max_len = ba.len().max(bb.len());

    let mut identical = 0usize;
    let mut diff_count = max_len - min_len;
    let mut ranges: Vec<DiffRange> = Vec::new();
    let mut total_ranges = 0usize;

    let mut i = 0usize;
    while i < min_len {
        if ba[i] == bb[i] {
            identical += 1;
            i += 1;
        } else {
            let start = i;
            while i < min_len && ba[i] != bb[i] {
                diff_count += 1;
                i += 1;
            }
            let len = i - start;
            total_ranges += 1;
            if ranges.len() < MAX_DIFF_RANGES {
                let sample_len = len.min(12);
                ranges.push(DiffRange {
                    offset: start,
                    len,
                    sample_a: ba[start..start + sample_len].to_vec(),
                    sample_b: bb[start..start + sample_len].to_vec(),
                });
            }
        }
    }

    if max_len > min_len {
        total_ranges += 1;
        if ranges.len() < MAX_DIFF_RANGES {
            let tail_len = max_len - min_len;
            let sample_len = tail_len.min(12);
            ranges.push(DiffRange {
                offset: min_len,
                len: tail_len,
                sample_a: if ba.len() > min_len {
                    ba[min_len..min_len + sample_len].to_vec()
                } else {
                    Vec::new()
                },
                sample_b: if bb.len() > min_len {
                    bb[min_len..min_len + sample_len].to_vec()
                } else {
                    Vec::new()
                },
            });
        }
    }

    let identical_pct = if max_len == 0 {
        100.0
    } else {
        (identical as f64 / max_len as f64 * 100.0) as f32
    };

    BinaryDiff {
        other_name: b.file_name.clone(),
        other_path: b.file_path.clone(),
        other_sha256: b.sha256.clone(),
        size_a: a.size,
        size_b: b.size,
        size_delta: b.size as i64 - a.size as i64,
        sha256_match: a.sha256 == b.sha256,
        identical_bytes: identical,
        differing_bytes: diff_count,
        identical_pct,
        ranges,
        total_ranges,
    }
}

pub fn format_bytes(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB ({} B)", b / GB, bytes)
    } else if b >= MB {
        format!("{:.2} MB ({} B)", b / MB, bytes)
    } else if b >= KB {
        format!("{:.1} KB ({} B)", b / KB, bytes)
    } else {
        format!("{} B", bytes)
    }
}

pub fn format_bytes_compact(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

// ============================================================================
// Binary Format & Deep Header Parsers
// ============================================================================

fn parse_format(data: &[u8]) -> FormatMetadata {
    if data.is_empty() {
        return FormatMetadata {
            format_short: "EMPTY".into(),
            format_long: "Empty File (0 bytes)".into(),
            details: Vec::new(),
            sections: Vec::new(),
        };
    }

    if data.len() >= 64 && &data[0..2] == b"MZ" {
        if let Some(pe) = parse_pe(data) {
            return pe;
        }
    }

    if data.len() >= 52 && &data[0..4] == b"\x7FELF" {
        if let Some(elf) = parse_elf(data) {
            return elf;
        }
    }

    if data.len() >= 28 {
        let m = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if matches!(m, 0xFEEDFACE | 0xCEFAEDFE | 0xFEEDFACF | 0xCFFAEDFE | 0xCAFEBABE) {
            return parse_macho(data, m);
        }
    }

    if data.len() >= 24 && &data[0..8] == b"\x89PNG\r\n\x1A\n" {
        return parse_png(data);
    }

    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return FormatMetadata {
            format_short: "JPEG".into(),
            format_long: "JPEG Image (JFIF / EXIF)".into(),
            details: vec![("MAGIC".into(), "FF D8 FF".into())],
            sections: Vec::new(),
        };
    }

    if data.len() >= 10 && (&data[0..6] == b"GIF89a" || &data[0..6] == b"GIF87a") {
        let w = u16::from_le_bytes([data[6], data[7]]);
        let h = u16::from_le_bytes([data[8], data[9]]);
        return FormatMetadata {
            format_short: "GIF".into(),
            format_long: format!("GIF Image ({})", String::from_utf8_lossy(&data[0..6])),
            details: vec![("DIMENSIONS".into(), format!("{} × {} px", w, h))],
            sections: Vec::new(),
        };
    }

    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return FormatMetadata {
            format_short: "WEBP".into(),
            format_long: "WebP Image Container (RIFF)".into(),
            details: vec![("CONTAINER".into(), "RIFF / WEBP".into())],
            sections: Vec::new(),
        };
    }

    if data.len() >= 8 && &data[0..5] == b"%PDF-" {
        let ver_end = data.iter().take(16).position(|&b| b == b'\r' || b == b'\n').unwrap_or(8);
        let ver = String::from_utf8_lossy(&data[0..ver_end]).to_string();
        return FormatMetadata {
            format_short: "PDF".into(),
            format_long: "Portable Document Format".into(),
            details: vec![("HEADER".into(), ver)],
            sections: Vec::new(),
        };
    }

    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        return parse_zip(data);
    }

    if data.len() >= 10 && data[0] == 0x1F && data[1] == 0x8B {
        return FormatMetadata {
            format_short: "GZIP".into(),
            format_long: "GZIP Compressed Stream".into(),
            details: vec![
                ("METHOD".into(), format!("0x{:02X}", data[2])),
                ("FLAGS".into(), format!("0x{:02X}", data[3])),
            ],
            sections: Vec::new(),
        };
    }

    if data.len() >= 6 && &data[0..6] == b"7z\xBC\xAF\x27\x1C" {
        return FormatMetadata {
            format_short: "7Z".into(),
            format_long: "7-Zip Archive".into(),
            details: vec![("SIGNATURE".into(), "37 7A BC AF 27 1C".into())],
            sections: Vec::new(),
        };
    }

    if data.len() >= 100 && &data[0..16] == b"SQLite format 3\0" {
        let page_size_raw = u16::from_be_bytes([data[16], data[17]]);
        let page_size = if page_size_raw == 1 {
            65536u32
        } else {
            page_size_raw as u32
        };
        let pages = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
        return FormatMetadata {
            format_short: "SQLITE".into(),
            format_long: "SQLite 3 Database".into(),
            details: vec![
                ("PAGE SIZE".into(), format!("{} B", page_size)),
                ("PAGE COUNT".into(), format!("{}", pages)),
            ],
            sections: Vec::new(),
        };
    }

    if data.len() >= 8 && &data[0..4] == b"\x00asm" {
        let ver = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        return FormatMetadata {
            format_short: "WASM".into(),
            format_long: "WebAssembly Binary Module".into(),
            details: vec![("VERSION".into(), format!("{}", ver))],
            sections: Vec::new(),
        };
    }

    if data.len() >= 4 {
        if &data[0..4] == b"wOF2" {
            return FormatMetadata {
                format_short: "WOFF2".into(),
                format_long: "WOFF2 Web Font".into(),
                details: vec![("SIGNATURE".into(), "wOF2".into())],
                sections: Vec::new(),
            };
        }
        if &data[0..4] == b"OTTO" || &data[0..4] == b"\x00\x01\x00\x00" {
            let is_otf = &data[0..4] == b"OTTO";
            return FormatMetadata {
                format_short: if is_otf { "OTF" } else { "TTF" }.into(),
                format_long: if is_otf {
                    "OpenType Font (CFF)"
                } else {
                    "TrueType Font (SFNT)"
                }
                .into(),
                details: vec![("TABLES".into(), format!("{}", read_u16_be(data, 4).unwrap_or(0)))],
                sections: Vec::new(),
            };
        }
    }

    // UTF-8 Text heuristic
    let sample_len = data.len().min(8192);
    let has_null = data[..sample_len].contains(&0);
    if !has_null && std::str::from_utf8(&data[..sample_len]).is_ok() {
        let lines = data.iter().filter(|&&b| b == b'\n').count() + 1;
        return FormatMetadata {
            format_short: "UTF-8".into(),
            format_long: "UTF-8 Encoded Text".into(),
            details: vec![("LINES".into(), format!("{}", lines))],
            sections: Vec::new(),
        };
    }

    let magic_hex: String = data
        .iter()
        .take(8)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    FormatMetadata {
        format_short: "RAW".into(),
        format_long: "Raw Binary Data".into(),
        details: vec![("HEAD BYTES".into(), magic_hex)],
        sections: Vec::new(),
    }
}

fn parse_pe(data: &[u8]) -> Option<FormatMetadata> {
    let pe_off = read_u32_le(data, 0x3C)? as usize;
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }

    let coff = pe_off + 4;
    let machine = read_u16_le(data, coff)?;
    let num_sections = read_u16_le(data, coff + 2)? as usize;
    let timestamp = read_u32_le(data, coff + 4)?;
    let opt_size = read_u16_le(data, coff + 16)? as usize;
    let characteristics = read_u16_le(data, coff + 18)?;

    let machine_name = match machine {
        0x8664 => "x86_64 (AMD64)",
        0x014C => "x86 (i386)",
        0xAA64 => "ARM64 (AArch64)",
        0x01C4 => "ARM Thumb-2",
        0x5064 => "RISC-V 64",
        other => {
            return Some(FormatMetadata {
                format_short: "PE".into(),
                format_long: format!("PE Executable (0x{:04X})", other),
                details: Vec::new(),
                sections: Vec::new(),
            });
        }
    };

    let opt_off = coff + 20;
    let opt_magic = if opt_size >= 2 {
        read_u16_le(data, opt_off).unwrap_or(0)
    } else {
        0
    };
    let is_pe64 = opt_magic == 0x020B;
    let is_pe32 = opt_magic == 0x010B;

    let entry_rva = if opt_size >= 20 {
        read_u32_le(data, opt_off + 16).unwrap_or(0)
    } else {
        0
    };

    let image_base: u64 = if is_pe64 && opt_size >= 32 {
        read_u64_le(data, opt_off + 24).unwrap_or(0)
    } else if is_pe32 && opt_size >= 32 {
        read_u32_le(data, opt_off + 28).unwrap_or(0) as u64
    } else {
        0
    };

    let subsystem_code = if opt_size >= 70 {
        read_u16_le(data, opt_off + 68).unwrap_or(0)
    } else {
        0
    };
    let subsystem = match subsystem_code {
        1 => "NATIVE",
        2 => "WINDOWS GUI",
        3 => "WINDOWS CUI",
        7 => "POSIX CUI",
        10 => "EFI APPLICATION",
        11 => "EFI BOOT DRIVER",
        12 => "EFI RUNTIME",
        _ => "UNKNOWN",
    };

    let ts_str = DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("0x{:08X}", timestamp));

    let kind_tag = if characteristics & 0x2000 != 0 {
        "DLL"
    } else {
        "EXE"
    };

    let format_short = if is_pe64 { "PE64" } else { "PE32" }.to_string();
    let format_long = format!(
        "{} {} · {}",
        if is_pe64 { "PE32+" } else { "PE32" },
        kind_tag,
        machine_name
    );

    // Parse Section Headers (40 bytes each)
    let sec_table = opt_off + opt_size;
    let mut sections = Vec::new();
    for i in 0..num_sections.min(96) {
        let base = sec_table + i * 40;
        if base + 40 > data.len() {
            break;
        }
        let raw_name = &data[base..base + 8];
        let name = String::from_utf8_lossy(raw_name)
            .trim_end_matches('\0')
            .to_string();
        let virtual_size = read_u32_le(data, base + 8).unwrap_or(0) as u64;
        let virtual_addr = read_u32_le(data, base + 12).unwrap_or(0) as u64;
        let raw_size = read_u32_le(data, base + 16).unwrap_or(0) as u64;
        let raw_offset = read_u32_le(data, base + 20).unwrap_or(0) as u64;
        let sec_chars = read_u32_le(data, base + 36).unwrap_or(0);

        let r = if sec_chars & 0x4000_0000 != 0 { 'R' } else { '-' };
        let w = if sec_chars & 0x8000_0000 != 0 { 'W' } else { '-' };
        let x = if sec_chars & 0x2000_0000 != 0 { 'X' } else { '-' };
        let flags = format!("{}{}{}", r, w, x);

        let ent = if raw_size > 0 && (raw_offset as usize) < data.len() {
            let start = raw_offset as usize;
            let end = start.saturating_add(raw_size as usize).min(data.len());
            shannon_entropy(&data[start..end])
        } else {
            0.0
        };

        sections.push(SectionInfo {
            name: if name.is_empty() {
                format!("#{:02}", i)
            } else {
                name
            },
            virtual_addr,
            virtual_size,
            raw_offset,
            raw_size,
            flags,
            entropy: ent,
        });
    }

    let details = vec![
        ("ARCH".into(), machine_name.into()),
        ("SUBSYSTEM".into(), subsystem.into()),
        ("ENTRY RVA".into(), format!("0x{:08X}", entry_rva)),
        ("IMAGE BASE".into(), format!("0x{:016X}", image_base)),
        ("TIMESTAMP".into(), ts_str),
        ("SECTIONS".into(), format!("{}", sections.len())),
    ];

    Some(FormatMetadata {
        format_short,
        format_long,
        details,
        sections,
    })
}

fn parse_elf(data: &[u8]) -> Option<FormatMetadata> {
    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let endian = data[5]; // 1 = LE, 2 = BE
    let is_64 = class == 2;
    let is_le = endian == 1;

    let r16 = |off: usize| -> Option<u16> {
        if is_le {
            read_u16_le(data, off)
        } else {
            read_u16_be(data, off)
        }
    };
    let r32 = |off: usize| -> Option<u32> {
        if is_le {
            read_u32_le(data, off)
        } else {
            read_u32_be(data, off)
        }
    };
    let r64 = |off: usize| -> Option<u64> {
        if is_le {
            read_u64_le(data, off)
        } else {
            read_u64_be(data, off)
        }
    };

    let e_type = r16(16)?;
    let e_machine = r16(18)?;
    let (e_entry, e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        if data.len() < 64 {
            return None;
        }
        (
            r64(24)?,
            r64(40)? as usize,
            r16(58)? as usize,
            r16(60)? as usize,
            r16(62)? as usize,
        )
    } else {
        (
            r32(24)? as u64,
            r32(32)? as usize,
            r16(46)? as usize,
            r16(48)? as usize,
            r16(50)? as usize,
        )
    };

    let type_str = match e_type {
        1 => "RELOCATABLE",
        2 => "EXECUTABLE",
        3 => "SHARED OBJECT / PIE",
        4 => "CORE DUMP",
        _ => "OTHER",
    };
    let mach_str = match e_machine {
        3 => "x86",
        40 => "ARM",
        62 => "x86_64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "OTHER",
    };

    // Attempt ELF section table parse
    let mut sections = Vec::new();
    let strtab_slice: Option<&[u8]> = if e_shoff > 0 && e_shentsize >= 40 && e_shstrndx < e_shnum {
        let base = e_shoff + e_shstrndx * e_shentsize;
        if is_64 && base + 40 <= data.len() {
            let off = r64(base + 24).unwrap_or(0) as usize;
            let sz = r64(base + 32).unwrap_or(0) as usize;
            if off < data.len() {
                Some(&data[off..off.saturating_add(sz).min(data.len())])
            } else {
                None
            }
        } else if !is_64 && base + 24 <= data.len() {
            let off = r32(base + 16).unwrap_or(0) as usize;
            let sz = r32(base + 20).unwrap_or(0) as usize;
            if off < data.len() {
                Some(&data[off..off.saturating_add(sz).min(data.len())])
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    if e_shoff > 0 && e_shentsize >= 40 {
        for i in 0..e_shnum.min(64) {
            let base = e_shoff + i * e_shentsize;
            if base + e_shentsize > data.len() {
                break;
            }
            let name_off = r32(base).unwrap_or(0) as usize;
            let (sh_flags, sh_addr, sh_off, sh_size) = if is_64 {
                (
                    r64(base + 8).unwrap_or(0),
                    r64(base + 16).unwrap_or(0),
                    r64(base + 24).unwrap_or(0),
                    r64(base + 32).unwrap_or(0),
                )
            } else {
                (
                    r32(base + 8).unwrap_or(0) as u64,
                    r32(base + 12).unwrap_or(0) as u64,
                    r32(base + 16).unwrap_or(0) as u64,
                    r32(base + 20).unwrap_or(0) as u64,
                )
            };
            if sh_size == 0 {
                continue;
            }
            let name = strtab_slice
                .and_then(|st| {
                    if name_off < st.len() {
                        let end = st[name_off..]
                            .iter()
                            .position(|&b| b == 0)
                            .map(|p| name_off + p)
                            .unwrap_or(st.len());
                        Some(String::from_utf8_lossy(&st[name_off..end]).to_string())
                    } else {
                        None
                    }
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("SEC_{:02}", i));

            let r = if sh_flags & 0x2 != 0 { 'R' } else { '-' };
            let w = if sh_flags & 0x1 != 0 { 'W' } else { '-' };
            let x = if sh_flags & 0x4 != 0 { 'X' } else { '-' };

            let ent = if (sh_off as usize) < data.len() {
                let s = sh_off as usize;
                let e = s.saturating_add(sh_size as usize).min(data.len());
                shannon_entropy(&data[s..e])
            } else {
                0.0
            };

            sections.push(SectionInfo {
                name,
                virtual_addr: sh_addr,
                virtual_size: sh_size,
                raw_offset: sh_off,
                raw_size: sh_size,
                flags: format!("{}{}{}", r, w, x),
                entropy: ent,
            });
        }
    }

    Some(FormatMetadata {
        format_short: if is_64 { "ELF64" } else { "ELF32" }.into(),
        format_long: format!(
            "{} {} · {}",
            if is_64 { "ELF64" } else { "ELF32" },
            type_str,
            mach_str
        ),
        details: vec![
            ("CLASS".into(), if is_64 { "64-BIT" } else { "32-BIT" }.into()),
            ("ENDIAN".into(), if is_le { "LITTLE" } else { "BIG" }.into()),
            ("MACHINE".into(), mach_str.into()),
            ("ENTRY".into(), format!("0x{:016X}", e_entry)),
            ("SECTIONS".into(), format!("{}", e_shnum)),
        ],
        sections,
    })
}

fn parse_macho(data: &[u8], magic: u32) -> FormatMetadata {
    let desc = match magic {
        0xFEEDFACE | 0xCEFAEDFE => "Mach-O 32-bit Binary",
        0xFEEDFACF | 0xCFFAEDFE => "Mach-O 64-bit Binary",
        _ => "Mach-O Universal (Fat) Binary",
    };
    let endian = match magic {
        0xCEFAEDFE | 0xCFFAEDFE => "LITTLE",
        _ => "BIG",
    };
    FormatMetadata {
        format_short: "MACHO".into(),
        format_long: desc.into(),
        details: vec![
            ("MAGIC".into(), format!("0x{:08X}", magic)),
            ("ENDIAN".into(), endian.into()),
            ("SIZE".into(), format_bytes_compact(data.len())),
        ],
        sections: Vec::new(),
    }
}

fn parse_png(data: &[u8]) -> FormatMetadata {
    let mut details = Vec::new();
    let mut sections = Vec::new();
    let mut chunk_names = Vec::new();
    let mut pos = 8usize;

    while pos + 12 <= data.len() && sections.len() < 48 {
        let len = read_u32_be(data, pos).unwrap_or(0) as usize;
        let ctype = String::from_utf8_lossy(&data[pos + 4..pos + 8]).to_string();
        let data_start = pos + 8;
        let data_end = data_start.saturating_add(len).min(data.len());

        if ctype == "IHDR" && data_end >= data_start + 13 {
            let w = read_u32_be(data, data_start).unwrap_or(0);
            let h = read_u32_be(data, data_start + 4).unwrap_or(0);
            let depth = data[data_start + 8];
            let color = match data[data_start + 9] {
                0 => "GRAYSCALE",
                2 => "RGB",
                3 => "INDEXED",
                4 => "GRAY+ALPHA",
                6 => "RGBA",
                _ => "OTHER",
            };
            details.push(("DIMENSIONS".into(), format!("{} × {} px", w, h)));
            details.push(("COLOR".into(), format!("{} · {}-BIT", color, depth)));
        }

        let ent = shannon_entropy(&data[data_start..data_end]);
        chunk_names.push(ctype.clone());
        sections.push(SectionInfo {
            name: ctype.clone(),
            virtual_addr: pos as u64,
            virtual_size: (len + 12) as u64,
            raw_offset: pos as u64,
            raw_size: (len + 12) as u64,
            flags: "CHK".into(),
            entropy: ent,
        });

        let next = pos.saturating_add(12).saturating_add(len);
        if next <= pos || ctype == "IEND" {
            break;
        }
        pos = next;
    }

    details.push(("CHUNKS".into(), format!("{}", chunk_names.len())));

    FormatMetadata {
        format_short: "PNG".into(),
        format_long: "Portable Network Graphics (PNG)".into(),
        details,
        sections,
    }
}

fn parse_zip(data: &[u8]) -> FormatMetadata {
    // Search for End of Central Directory (EOCD) signature PK\x05\x06 from end
    let mut entry_count: Option<u16> = None;
    let search_start = data.len().saturating_sub(65557);
    if data.len() >= 22 {
        let mut i = data.len() - 22;
        loop {
            if &data[i..i + 4] == b"PK\x05\x06" {
                entry_count = read_u16_le(data, i + 10);
                break;
            }
            if i == search_start {
                break;
            }
            i -= 1;
        }
    }

    let count = entry_count.map(|c| c as usize).unwrap_or_else(|| {
        data.windows(4).filter(|w| *w == b"PK\x03\x04").count()
    });

    FormatMetadata {
        format_short: "ZIP".into(),
        format_long: "ZIP Archive Container".into(),
        details: vec![
            ("ENTRIES".into(), format!("{}", count)),
            ("SIGNATURE".into(), "50 4B 03 04".into()),
        ],
        sections: Vec::new(),
    }
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    let s = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u16_be(data: &[u8], off: usize) -> Option<u16> {
    let s = data.get(off..off + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    let s = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u32_be(data: &[u8], off: usize) -> Option<u32> {
    let s = data.get(off..off + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    let s = data.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn read_u64_be(data: &[u8], off: usize) -> Option<u64> {
    let s = data.get(off..off + 8)?;
    Some(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}
