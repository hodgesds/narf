//! Fixture DSDT for the ACPI video backlight (#958).
//!
//! A minimal, hand-encoded laptop DSDT fragment exposing one video
//! output device with the three ACPI video methods, so the
//! AML→registry→sysfs→`_BCM` conversation is exercised end to end
//! against real AML bytes instead of the pre-parsed ladders the
//! `__test_install` helpers inject.
//!
//! ASL source (the spec the bytes below encode — ACPI 6.5 §B.6.2
//! for `_BCL`, §B.6.3 for `_BCM`, §B.6.4 for `_BQC`):
//!
//! ```asl
//! Scope (\_SB) {
//!     Device (GFX0) {
//!         Device (DD0) {
//!             Name (LEVL, 50)
//!             Method (_BCL, 0, NotSerialized) {
//!                 Return (Package (0x0D) {
//!                     80, 100,   // AC default, battery default
//!                     0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100
//!                 })
//!             }
//!             // Firmware-side current-level cell. `_BCM` stores its
//!             // argument here and `_BQC` reads it back, so a test
//!             // can prove the dispatched argument actually landed
//!             // in firmware state instead of only in the driver's
//!             // `last` cache.
//!             Method (_BCM, 1, NotSerialized) {
//!                 Store (Arg0, \_SB.GFX0.DD0.LEVL)
//!             }
//!             Method (_BQC, 0, NotSerialized) {
//!                 Return (\_SB.GFX0.DD0.LEVL)
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! Encoding notes (ACPI 6.5 §20):
//!
//! - Names inside method bodies are fully qualified
//!   (`\_SB.GFX0.DD0.LEVL`, MultiNamePrefix `0x2F`) rather than
//!   relative (`LEVL`): the interpreter resolves a fully-qualified
//!   name by direct node lookup, while a bare relative name read
//!   from a method body resolves to `\LEVL` and misses (the eval
//!   does not yet thread the caller method's scope through
//!   `eval_term_arg`). Real firmware uses both spellings; the
//!   fixture uses the one this interpreter implements.
//! - `PkgLength` is computed from the assembled children, never
//!   hand-counted: each wrapper solves for its own 1- vs 2-byte
//!   form. The whole blob is 123 bytes.
//! - No `_ADR` / `_HID`: the backlight driver never reads them, so
//!   inventing values would be fabrication, not fidelity.

use alloc::vec::Vec;

// ── fixture constants (spec-derived, single source of truth) ────────

/// AML path of the fixture video output device.
pub(crate) const DD0_PATH: &str = r"\_SB.GFX0.DD0";

/// `_BCL` package as firmware returns it (ACPI 6.5 §B.6.2): element
/// 0 is the AC-power default, element 1 the battery default, the
/// rest is the supported ladder.
pub(crate) const BCL_PACKAGE: [u8; 13] = [80, 100, 0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

/// Ladder the driver must derive from [`BCL_PACKAGE`] (first two
/// entries stripped, sorted ascending, deduped).
pub(crate) const BCL_LADDER: [u32; 11] = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

/// Initial firmware-side current level (`LEVL`).
pub(crate) const INITIAL_LEVEL: u32 = 50;

// ── AML encoding helpers ────────────────────────────────────────────

/// Encode a `PkgLength` for `total` — the full length of the
/// enclosing object *including* the `PkgLength` bytes themselves
/// (ACPI 6.5 §20.2.5.2). The fixture stays under 4096 bytes, so
/// only the 1- and 2-byte forms are needed.
fn pkg_length(total: usize) -> Vec<u8> {
    assert!(
        total < 4096,
        "fixture DSDT exceeded the 2-byte PkgLength range"
    );
    if total < 64 {
        alloc::vec![total as u8]
    } else {
        alloc::vec![0x40 | (total as u8 & 0x0F), (total >> 4) as u8]
    }
}

/// Wrap `body` in a `PkgLength`-prefixed object: `prefix` +
/// `PkgLength` + `name` + `suffix` + `body`. The `PkgLength` width
/// is solved from the assembled length, so no size is hand-counted.
///
/// Per ACPI 6.5 §20.2.5.2 the `PkgLength` value counts from the
/// `PkgLength` byte itself — it includes the `PkgLength` bytes, the
/// name, and the body, but NOT the opcode bytes in `prefix`. (The
/// parser anchors `pkg_end` at the `PkgLength` byte, so counting
/// the opcode would overshoot the object by `prefix.len()` and
/// swallow the next sibling.)
fn pkg_wrap(prefix: &[u8], name: &[u8], suffix: &[u8], body: &[u8]) -> Vec<u8> {
    let content = name.len() + suffix.len() + body.len();
    let mut width = 1usize;
    let mut len = width + content;
    if len >= 64 {
        width = 2;
        len = width + content;
    }
    debug_assert_eq!(pkg_length(len).len(), width);
    let mut v = Vec::with_capacity(prefix.len() + len);
    v.extend_from_slice(prefix);
    v.extend_from_slice(&pkg_length(len));
    v.extend_from_slice(name);
    v.extend_from_slice(suffix);
    v.extend_from_slice(body);
    v
}

/// A 4-byte NameSeg, `_`-padded (ACPI 6.5 §20.2.2).
fn name_seg(s: &str) -> [u8; 4] {
    let b = s.as_bytes();
    debug_assert!(b.len() <= 4, "NameSeg longer than 4 chars");
    let mut seg = [b'_'; 4];
    seg[..b.len()].copy_from_slice(b);
    seg
}

/// Fully-qualified multi-segment NameString: root char +
/// MultiNamePrefix + segment count + segments.
fn root_multi_name(segs: &[&str]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + 4 * segs.len());
    v.push(0x5C); // RootChar '\\'
    v.push(0x2F); // MultiNamePrefix
    v.push(segs.len() as u8);
    for s in segs {
        v.extend_from_slice(&name_seg(s));
    }
    v
}

/// `Method(name, argc, NotSerialized) { body }` (MethodOp 0x14).
fn method(name: &str, argc: u8, body: &[u8]) -> Vec<u8> {
    pkg_wrap(&[0x14], &name_seg(name), &[argc], body)
}

/// `Device(name) { body }` (ExtOpPrefix 0x5B + DeviceOp 0x82).
fn device(name: &str, body: &[u8]) -> Vec<u8> {
    pkg_wrap(&[0x5B, 0x82], &name_seg(name), &[], body)
}

// ── the fixture ─────────────────────────────────────────────────────

/// The fixture DSDT body (no SDT header — pass to
/// [`narf_aml::__parse_body_for_test`] with root `"\\"`).
///
/// Parses into exactly 7 namespace nodes: Scope `\_SB`, Device
/// `\_SB.GFX0`, Device `\_SB.GFX0.DD0`, Name
/// `\_SB.GFX0.DD0.LEVL`, and Methods `\_SB.GFX0.DD0._BCL`,
/// `._BCM`, `._BQC`.
pub(crate) fn dsdt_bytes() -> Vec<u8> {
    // Method (_BCL, 0) { Return (Package { 80, 100, 0, …, 100 }) }
    let mut pkg = Vec::with_capacity(1 + 2 * BCL_PACKAGE.len());
    pkg.push(BCL_PACKAGE.len() as u8); // NumElements
    for v in BCL_PACKAGE {
        pkg.push(0x0A); // BytePrefix
        pkg.push(v);
    }
    let mut bcl_body = alloc::vec![0xA4, 0x12]; // ReturnOp, PackageOp
    bcl_body.extend_from_slice(&pkg_length(1 + pkg.len()));
    bcl_body.extend_from_slice(&pkg);
    let bcl = method("_BCL", 0, &bcl_body);

    // Method (_BCM, 1) { Store (Arg0, \_SB.GFX0.DD0.LEVL) }
    let mut bcm_body = alloc::vec![0x70, 0x68]; // StoreOp, Arg0
    bcm_body.extend_from_slice(&root_multi_name(&["_SB_", "GFX0", "DD0_", "LEVL"]));
    let bcm = method("_BCM", 1, &bcm_body);

    // Method (_BQC, 0) { Return (\_SB.GFX0.DD0.LEVL) }
    let mut bqc_body = alloc::vec![0xA4]; // ReturnOp
    bqc_body.extend_from_slice(&root_multi_name(&["_SB_", "GFX0", "DD0_", "LEVL"]));
    let bqc = method("_BQC", 0, &bqc_body);

    // Device (DD0) { Name (LEVL, 50) _BCL _BCM _BQC }
    let mut dd0_body = alloc::vec![0x08]; // NameOp
    dd0_body.extend_from_slice(b"LEVL");
    dd0_body.push(0x0A); // BytePrefix
    dd0_body.push(INITIAL_LEVEL as u8);
    dd0_body.extend_from_slice(&bcl);
    dd0_body.extend_from_slice(&bcm);
    dd0_body.extend_from_slice(&bqc);
    let dd0 = device("DD0_", &dd0_body);

    // Device (GFX0) { DD0 }
    let gfx0 = device("GFX0", &dd0);

    // Scope (\_SB) { GFX0 } — NameString is root char + "_SB_".
    pkg_wrap(&[0x10], b"\\_SB_", &[], &gfx0)
}
