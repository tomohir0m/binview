# BINVIEW

**BINVIEW** is a museum-grade, monochrome Rust desktop studio for binary analysis, structural visualization, virtualized hex inspection, string extraction, and byte-level binary diffing.

Built with `eframe` / `egui` in pure Rust using an architectural Swiss-grid aesthetic: pure monochrome luminance (`NOIR` `#060607` and `PAPER` `#F4F3EE`), 1px hairlines, embedded studio typography, and zero RGB clutter.

## Exhibition Modes

Every loaded binary renders on a gallery-framed monochrome plate with photographic corner crop marks, live hover telemetry, direct click-to-jump interaction with the HEX viewer, and 1200×840 archival Vector SVG poster export (`SAVE SVG`).

| Mode | Visual Form | Direct Interaction |
|---|---|---|
| `01 DIGRAPH` | 64×64 logarithmic byte-pair density cloud (`b[i]`, `b[i+1]`) | Hover crosshairs + click cell to jump to bigram |
| `02 ENTROPY` | 128-point Shannon entropy seismograph + section brackets | Click or drag waveform to scrub HEX offset |
| `03 SPECTRUM` | 256-bar byte frequency impulse analyzer (`0x00..0xFF`) | Click any bar to find & jump to that byte |
| `04 HILBERT` | 64×32 space-filling Hilbert atlas (`ZERO` / `ASCII` / `CODE` / `PACKED`) | Toggle `TRAIL` curve + click tile to jump offset |

## Inspector Capabilities

- **Auto Self-Inspection**: Launches directly into a live PE64 analysis of `binview.exe`.
- **Format & Header Parsers**: Detects PE32/PE32+ (full COFF/Optional headers & per-section R/W/X flags + Shannon entropy), ELF32/ELF64, Mach-O, PNG (IHDR + chunks), JPEG, GIF, WebP, PDF, ZIP (entry count), GZIP, 7z, SQLite, WASM, TTF/OTF/WOFF2, and UTF-8 text.
- **Virtualized 60fps HEX Viewer**: Smooth `xxd`-style Hex + ASCII inspection (`8` or `16` bytes/row) powered by `ScrollArea::show_rows`, offset jump (`0x...` or decimal), and `AUTO` / `HEX` / `ASCII` byte pattern search.
- **Strings Catalog**: Configurable minimum string length (`4` / `6` / `8` / `12`), live filter, and one-click jump straight to the exact file offset in HEX view.
- **Binary Compare**: Load a second file (or drag & drop while on `COMPARE`) for SHA-256 verification, size delta, identical byte percentage, and clickable differing byte regions.
- **Persistent Studio Preferences**: `NOIR` / `PAPER` theme, embedded fonts (`Space Grotesk`, `IBM Plex Mono`, `Space Mono`, `JetBrains Mono` + Japanese fallback), default plate mode, Hilbert trail, hex width, and privacy path masking stored at `%APPDATA%\binview\state.json` (`Ctrl+,` to open Settings).

## Build

```powershell
cargo build --release
```

The standalone release binary is produced at `target/release/binview.exe`.
