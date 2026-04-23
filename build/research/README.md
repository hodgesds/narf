# build — Research

## Primary sources

- **The rustc book — Linker-plugin-based LTO**
  <https://doc.rust-lang.org/rustc/linker-plugin-lto.html>
- **`-Z build-std` tracking issue (rust-lang/wg-cargo-std-aware)**
  <https://github.com/rust-lang/wg-cargo-std-aware>
- **Rust Embedded Book — Starting a new project**
  <https://docs.rust-embedded.org/book/>

## Secondary sources

- **Redox OS build system** — prior art for a Rust OS workspace with
  cross-compile. <https://gitlab.redox-os.org/redox-os/redox>
- **Hubris** — Oxide's Rust embedded OS; clean `xtask` and sign-off flow.
  <https://github.com/oxidecomputer/hubris>
- **Limine boot protocol** — modern x86_64 bootloader with multi-arch support.
  <https://github.com/limine-bootloader/limine/blob/trunk/PROTOCOL.md>

## Distilled summaries

- (None required for Stage 1 — references are short enough to read whole.)

## Fetched this round

- summaries/rustc-linker-plugin-lto.md — Cross-language LTO, toolchain version matching, and domain isolation boundaries in build
- summaries/cargo-std-aware.md — Custom stdlib compilation, explicit sysroot declarations, and build reproducibility
- summaries/rust-embedded-book.md — Cross-compilation, custom targets, linker scripts, and panic isolation

## Open research questions

- LTO + `panic = "abort"` + `build-std` interactions with codegen-units.
- How to split debug info so release binaries stay small but we keep
  useful kernel crash decoding.
