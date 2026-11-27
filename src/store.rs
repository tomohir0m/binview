use crate::theme::{FontPreset, ThemeKind};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VizMode {
    Digraph,
    Entropy,
    Spectrum,
    Hilbert,
}

impl VizMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Digraph => "01 DIGRAPH",
            Self::Entropy => "02 ENTROPY",
            Self::Spectrum => "03 SPECTRUM",
            Self::Hilbert => "04 HILBERT",
        }
    }

    pub fn cutout_tag(&self) -> &'static str {
        match self {
            Self::Digraph => "DIGRAPH",
            Self::Entropy => "ENTROPY",
            Self::Spectrum => "SPECTRUM",
            Self::Hilbert => "HILBERT",
        }
    }

    pub fn all() -> &'static [VizMode] {
        &[Self::Digraph, Self::Entropy, Self::Spectrum, Self::Hilbert]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub dark_mode: bool,
    pub font_index: usize,        // 0: IBM Plex, 1: Space Mono, 2: JetBrains
    pub viz_mode_index: usize,    // 0: Digraph, 1: Entropy, 2: Spectrum, 3: Hilbert
    pub show_trail: bool,         // Optional Hilbert space-filling curve overlay
    pub min_string_len: usize,    // 4, 6, 8, 12
    pub hex_bytes_per_row: usize, // 8 or 16
    pub privacy_mask: bool,       // Masks user directory segments in displayed paths
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            dark_mode: true,
            font_index: 0,
            viz_mode_index: 0,
            show_trail: false,
            min_string_len: 6,
            hex_bytes_per_row: 16,
            privacy_mask: false,
        }
    }
}

impl AppSettings {
    pub fn theme_kind(&self) -> ThemeKind {
        if self.dark_mode {
            ThemeKind::Noir
        } else {
            ThemeKind::Paper
        }
    }

    pub fn font_preset(&self) -> FontPreset {
        match self.font_index {
            1 => FontPreset::SpaceMono,
            2 => FontPreset::JetBrains,
            _ => FontPreset::IbmPlex,
        }
    }

    pub fn set_font_preset(&mut self, fp: FontPreset) {
        self.font_index = match fp {
            FontPreset::IbmPlex => 0,
            FontPreset::SpaceMono => 1,
            FontPreset::JetBrains => 2,
        };
    }

    pub fn viz_mode(&self) -> VizMode {
        match self.viz_mode_index {
            1 => VizMode::Entropy,
            2 => VizMode::Spectrum,
            3 => VizMode::Hilbert,
            _ => VizMode::Digraph,
        }
    }

    pub fn set_viz_mode(&mut self, mode: VizMode) {
        self.viz_mode_index = match mode {
            VizMode::Digraph => 0,
            VizMode::Entropy => 1,
            VizMode::Spectrum => 2,
            VizMode::Hilbert => 3,
        };
    }

    pub fn sanitized_min_string_len(&self) -> usize {
        match self.min_string_len {
            4 | 6 | 8 | 12 => self.min_string_len,
            _ => 6,
        }
    }

    pub fn sanitized_hex_cols(&self) -> usize {
        match self.hex_bytes_per_row {
            8 | 16 => self.hex_bytes_per_row,
            _ => 16,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedStore {
    pub settings: AppSettings,
}

impl PersistedStore {
    /// Stored at `%APPDATA%\binview\state.json` on Windows.
    pub fn storage_path() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("binview").join("state.json")
    }

    pub fn load() -> Self {
        let path = Self::storage_path();
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(parsed) = serde_json::from_str::<Self>(&text) {
                return parsed;
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        let path = Self::storage_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
    }
}

/// Masks user home/profile path components when Privacy Mask is enabled.
pub fn mask_path_display(path: &str, masked: bool) -> String {
    if !masked {
        return path.to_string();
    }
    let sep = if path.contains('\\') { '\\' } else { '/' };
    let parts: Vec<&str> = path.split(sep).collect();
    if parts.len() <= 2 {
        return path.to_string();
    }
    let last = parts.last().copied().unwrap_or(path);
    format!("••••{}{}", sep, last)
}
