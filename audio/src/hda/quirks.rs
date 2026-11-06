//! Realtek codec fixup data — per-chip init coef tables and
//! per-laptop pin-override quirks.
//!
//! ## Provenance (#783 rescue)
//!
//! This module is the data rescued from the retired legacy audio
//! stack in `narf-drivers-sound` (`codec/quirks.rs` +
//! `codec/realtek.rs`), excised in #783. The legacy stack's
//! transport/walker code was deliberately *not* ported — the live
//! equivalents live in [`crate::hda_codec`] and this crate's
//! `hda::runtime` — but its tables are the only copies in the tree,
//! distilled from Linux `sound/pci/hda/patch_realtek.c`
//! (`alc269_fixup_models[]`, per-chip `alc*_init` sequences), and
//! they are an asset, not garbage.
//!
//! ## Status: init tables consumed, pin quirks re-derived (#776, #1496)
//!
//! The live HDA path ([`super::runtime`]) reads the codec subsystem
//! ID at probe and applies the per-chip init coef tables for the
//! chips Linux inits with unconditional static coef ops — the
//! ALC256 family (`RealtekChip::uses_alc256_init`, Linux
//! `alc256_init`) and ALC282/283 (Linux `alc282_coefs` /
//! `alc283_coefs` via `alc_process_coef_fw`) — before the widget
//! graph is built, and re-applies them on resume. The HP-pin
//! tails of `alc282_init` / `alc283_init` run after the graph is
//! built (they need the HP pin, known only post-enumerate) and
//! again on resume; the ALC294/ALC700 parse-time coef updates
//! ([`parse_table_for`], Linux `patch_alc269`) run once at probe
//! before enumeration, never on resume. The re-derived pin quirks
//! in [`VERIFIED_QUIRK_TABLE`] are applied the same way:
//! every row and key was checked against Linux
//! `sound/hda/codecs/realtek/alc269.c` (master and v6.6, 2026-11-05)
//! before wiring, keyed on codec subsystem IDs from Linux's
//! `HDA_CODEC_QUIRK` entries. The rescued six-entry
//! [`QUIRK_TABLE`] below stays staged data: verification found none
//! of its keys is a codec subsystem ID — 0x17AA22BE is the PCI SSID
//! of the ThinkPad X1 Carbon 8th (not Gen 7), 0x103C8716 the PCI
//! SSID of the HP Elite Dragonfly G2 (not EliteBook 845 G8),
//! 0x10431A30 the PCI SSID of the ASUS X705UD (not ROG Strix), and
//! 0x17AA22F0 / 0x10280AB9 / 0x14621234 appear nowhere in Linux —
//! and the pin contents do not match the cited fixups (Linux's
//! ALC285_FIXUP_THINKPAD_X1_GEN7 re-routes DAC connections, it sets
//! no pins). Applying them would write other laptops' pins to the
//! wrong machines. The live path never consults that table; the
//! kernel tests under `audio/hda-quirks` pin its contents (counts +
//! spot entries) so an accidental edit of the staged data fails loudly.

// ── Chip identity ───────────────────────────────────────────────────

/// Realtek vendor ID (high half of the VENDOR_ID parameter response).
pub const REALTEK_VENDOR_ID: u16 = 0x10EC;

/// Realtek ALC-family codec SKUs known to the fixup tables. The
/// discriminants are the codec device IDs (low half of VENDOR_ID).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RealtekChip {
    Alc215 = 0x0215,
    Alc222 = 0x0222,
    Alc225 = 0x0225,
    Alc230 = 0x0230,
    Alc233 = 0x0233,
    Alc234 = 0x0234,
    Alc235 = 0x0235,
    Alc236 = 0x0236,
    Alc245 = 0x0245,
    Alc255 = 0x0255,
    Alc256 = 0x0256,
    Alc257 = 0x0257,
    Alc270 = 0x0270,
    Alc274 = 0x0274,
    Alc280 = 0x0280,
    Alc282 = 0x0282,
    Alc283 = 0x0283,
    Alc285 = 0x0285,
    Alc286 = 0x0286,
    Alc287 = 0x0287,
    Alc289 = 0x0289,
    Alc290 = 0x0290,
    Alc292 = 0x0292,
    Alc293 = 0x0293,
    Alc294 = 0x0294,
    Alc295 = 0x0295,
    Alc298 = 0x0298,
    Alc299 = 0x0299,
    Alc300 = 0x0300,
    Alc623 = 0x0623,
    Alc700 = 0x0700,
    Alc701 = 0x0701,
    Alc703 = 0x0703,
    Alc711 = 0x0711,
    /// "ALC3204" / "ALC3225" / ... are vendor-rebrands of ALC families
    /// for OEM SKUs. They share the underlying core register map but
    /// carry a distinct PCI subsystem ID.
    Alc3204 = 0x3204,
    Alc3225 = 0x3225,
    Alc3236 = 0x3236,
    Alc3254 = 0x3254,
    Alc3266 = 0x3266,
    Alc3268 = 0x3268,
    Alc3286 = 0x3286,
    Alc3287 = 0x3287,
}

impl RealtekChip {
    /// Decode a 32-bit VENDOR_ID response. High 16 bits = vendor,
    /// low 16 bits = device. Returns None if the vendor isn't
    /// Realtek or the device ID isn't one of the SKUs we know.
    pub const fn from_vendor_id(v: u32) -> Option<RealtekChip> {
        let vendor = ((v >> 16) & 0xFFFF) as u16;
        let device = (v & 0xFFFF) as u16;
        if vendor != REALTEK_VENDOR_ID {
            return None;
        }
        match device {
            0x0215 => Some(RealtekChip::Alc215),
            0x0222 => Some(RealtekChip::Alc222),
            0x0225 => Some(RealtekChip::Alc225),
            0x0230 => Some(RealtekChip::Alc230),
            0x0233 => Some(RealtekChip::Alc233),
            0x0234 => Some(RealtekChip::Alc234),
            0x0235 => Some(RealtekChip::Alc235),
            0x0236 => Some(RealtekChip::Alc236),
            0x0245 => Some(RealtekChip::Alc245),
            0x0255 => Some(RealtekChip::Alc255),
            0x0256 => Some(RealtekChip::Alc256),
            0x0257 => Some(RealtekChip::Alc257),
            0x0270 => Some(RealtekChip::Alc270),
            0x0274 => Some(RealtekChip::Alc274),
            0x0280 => Some(RealtekChip::Alc280),
            0x0282 => Some(RealtekChip::Alc282),
            0x0283 => Some(RealtekChip::Alc283),
            0x0285 => Some(RealtekChip::Alc285),
            0x0286 => Some(RealtekChip::Alc286),
            0x0287 => Some(RealtekChip::Alc287),
            0x0289 => Some(RealtekChip::Alc289),
            0x0290 => Some(RealtekChip::Alc290),
            0x0292 => Some(RealtekChip::Alc292),
            0x0293 => Some(RealtekChip::Alc293),
            0x0294 => Some(RealtekChip::Alc294),
            0x0295 => Some(RealtekChip::Alc295),
            0x0298 => Some(RealtekChip::Alc298),
            0x0299 => Some(RealtekChip::Alc299),
            0x0300 => Some(RealtekChip::Alc300),
            0x0623 => Some(RealtekChip::Alc623),
            0x0700 => Some(RealtekChip::Alc700),
            0x0701 => Some(RealtekChip::Alc701),
            0x0703 => Some(RealtekChip::Alc703),
            0x0711 => Some(RealtekChip::Alc711),
            0x3204 => Some(RealtekChip::Alc3204),
            0x3225 => Some(RealtekChip::Alc3225),
            0x3236 => Some(RealtekChip::Alc3236),
            0x3254 => Some(RealtekChip::Alc3254),
            0x3266 => Some(RealtekChip::Alc3266),
            0x3268 => Some(RealtekChip::Alc3268),
            0x3286 => Some(RealtekChip::Alc3286),
            0x3287 => Some(RealtekChip::Alc3287),
            _ => None,
        }
    }

    /// Human-readable codec name, used by diagnostics and the
    /// `CardInfo::name` field at probe time.
    pub const fn name(self) -> &'static str {
        match self {
            RealtekChip::Alc215 => "ALC215",
            RealtekChip::Alc222 => "ALC222",
            RealtekChip::Alc225 => "ALC225",
            RealtekChip::Alc230 => "ALC230",
            RealtekChip::Alc233 => "ALC233",
            RealtekChip::Alc234 => "ALC234",
            RealtekChip::Alc235 => "ALC235",
            RealtekChip::Alc236 => "ALC236",
            RealtekChip::Alc245 => "ALC245",
            RealtekChip::Alc255 => "ALC255",
            RealtekChip::Alc256 => "ALC256",
            RealtekChip::Alc257 => "ALC257",
            RealtekChip::Alc270 => "ALC270",
            RealtekChip::Alc274 => "ALC274",
            RealtekChip::Alc280 => "ALC280",
            RealtekChip::Alc282 => "ALC282",
            RealtekChip::Alc283 => "ALC283",
            RealtekChip::Alc285 => "ALC285",
            RealtekChip::Alc286 => "ALC286",
            RealtekChip::Alc287 => "ALC287",
            RealtekChip::Alc289 => "ALC289",
            RealtekChip::Alc290 => "ALC290",
            RealtekChip::Alc292 => "ALC292",
            RealtekChip::Alc293 => "ALC293",
            RealtekChip::Alc294 => "ALC294",
            RealtekChip::Alc295 => "ALC295",
            RealtekChip::Alc298 => "ALC298",
            RealtekChip::Alc299 => "ALC299",
            RealtekChip::Alc300 => "ALC300",
            RealtekChip::Alc623 => "ALC623",
            RealtekChip::Alc700 => "ALC700",
            RealtekChip::Alc701 => "ALC701",
            RealtekChip::Alc703 => "ALC703",
            RealtekChip::Alc711 => "ALC711",
            RealtekChip::Alc3204 => "ALC3204",
            RealtekChip::Alc3225 => "ALC3225",
            RealtekChip::Alc3236 => "ALC3236",
            RealtekChip::Alc3254 => "ALC3254",
            RealtekChip::Alc3266 => "ALC3266",
            RealtekChip::Alc3268 => "ALC3268",
            RealtekChip::Alc3286 => "ALC3286",
            RealtekChip::Alc3287 => "ALC3287",
        }
    }

    /// Whether Linux runs `alc256_init` for this chip (Linux
    /// `sound/hda/codecs/realtek/alc269.c` init-hook dispatch:
    /// 0x10ec0230/0235/0236/0255/0256/0257, plus 0x19e58326).
    /// `alc256_init`'s unconditional tail is one masked update
    /// plus the (0x36, 0x5757) plain write; the sense-gated and
    /// `ultra_low_power` parts are not static tables, so they stay
    /// unwired. ALC282/283 run their own hooks (`alc282_init` /
    /// `alc283_init`, whose unconditional part is the `alc*_coefs`
    /// table) — see [`RealtekChip::has_verified_coef_init`].
    pub const fn uses_alc256_init(self) -> bool {
        matches!(
            self,
            RealtekChip::Alc230
                | RealtekChip::Alc235
                | RealtekChip::Alc236
                | RealtekChip::Alc255
                | RealtekChip::Alc256
                | RealtekChip::Alc257
        )
    }

    /// Whether this chip has a verified unconditional coef-init
    /// table the live path applies (`init_table_for` is non-empty
    /// AND verified against Linux): the `alc256_init` family plus
    /// ALC282/283, whose `alc282_coefs` / `alc283_coefs` tables
    /// (`alc_process_coef_fw`) are verified row-for-row against
    /// Linux master and v6.6 (#1496). Every other chip's
    /// `init_table_for` is either empty (no unconditional static
    /// coef ops in its Linux init hook — ALC215/225/245/274/299/
    /// 300/623/700) or rescued-but-unverified staged data (#776),
    /// so the live path must not apply it.
    pub const fn has_verified_coef_init(self) -> bool {
        self.uses_alc256_init() || matches!(self, RealtekChip::Alc282 | RealtekChip::Alc283)
    }
}

// ── Per-chip init coef tables ───────────────────────────────────────
//
// Realtek codecs expose an internal Processing Coefficient table
// that is the entire chip configuration surface, written through
// VERB_SET_COEF_INDEX (0x500) + VERB_SET_PROC_COEF (0x400). Most
// Realtek init sequences are an `(idx, value)` table. These are
// the universal "speaker comes up at boot" baselines; they are NOT
// the full per-OEM fixup tables — those are the pin quirks below,
// picked by codec subsystem ID. Without these baseline pokes, the
// chip won't produce sound even with a correctly-routed graph.

/// One Realtek coef operation in a per-chip init table, mirroring
/// Linux's `struct coef_fw` (`sound/hda/codecs/realtek/realtek.h`):
/// `{nid, idx, mask, val}`. A plain write when `mask == 0xFFFF`
/// (Linux `WRITE_COEF`, mask `-1`); otherwise a masked
/// read-modify-write update, `new = (old & ~mask) | value` (Linux
/// `UPDATE_COEF` / `alc_update_coef_idx`). The `nid` is the coef
/// node for almost every row (`0x20`, [`COEF_NODE`]); the
/// exceptions are the `UPDATE_COEFEX` rows that address another
/// widget (ALC283's `0x53` row, ALC256's `0x53` depop pulse).
/// Tables are applied in order, exactly as Linux's
/// `alc_process_coef_fw` walks its table — order matters where a
/// later row reads a value an earlier row wrote, and where
/// repeated writes to one index form a multi-word coef command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CoefOp {
    pub nid: u8,
    pub idx: u16,
    pub mask: u16,
    pub value: u16,
}

impl CoefOp {
    pub const fn new(nid: u8, idx: u16, mask: u16, value: u16) -> Self {
        CoefOp {
            nid,
            idx,
            mask,
            value,
        }
    }
    /// Plain write to the coef node (`WRITE_COEF`).
    pub const fn write(idx: u16, value: u16) -> Self {
        CoefOp::new(COEF_NODE, idx, 0xFFFF, value)
    }
    /// Masked update on the coef node (`UPDATE_COEF` /
    /// `alc_update_coef_idx`).
    pub const fn update(idx: u16, mask: u16, value: u16) -> Self {
        CoefOp::new(COEF_NODE, idx, mask, value)
    }
    /// Masked update on another widget (`UPDATE_COEFEX`).
    pub const fn update_nid(nid: u8, idx: u16, mask: u16, value: u16) -> Self {
        CoefOp::new(nid, idx, mask, value)
    }
    /// True for a plain write (`mask == 0xFFFF`, Linux's
    /// `mask == (unsigned short)-1` in `alc_process_coef_fw`).
    pub const fn is_write(self) -> bool {
        self.mask == 0xFFFF
    }
}

/// The vendor-defined widget Realtek coef writes address (Linux
/// `alc_write_coef_idx` → `alc_write_coefex_idx(codec, 0x20, ...)`
/// in `sound/hda/codecs/realtek/alc269.c`). Coef verbs go here,
/// never to the AFG node: the AFG does not implement the coef
/// registers, and a write there is silently dropped.
pub const COEF_NODE: u8 = 0x20;

/// Pin Widget Control — "Output Enable" (HDA §7.3.3.13, bit 6).
pub const PIN_WIDGET_OUT: u8 = 0x40;
/// "Headphone Enable" (HDA §7.3.3.13, bit 7).
pub const PIN_WIDGET_HP: u8 = 0x80;
/// Both — common for headphone-jack pins that also drive the speaker.
pub const PIN_WIDGET_OUT_HP: u8 = 0xC0;
/// "Input Enable" (HDA §7.3.3.13, bit 5).
pub const PIN_WIDGET_IN: u8 = 0x20;

/// EAPD = External Amplifier Power Down. Setting bit 1 of the
/// EAPD/BTL verb (0x70C) powers the external speaker amp.
pub const EAPD_ENABLE: u8 = 0x02;
/// Setting bit 0 of EAPD/BTL puts the codec amp into BTL (bridge-tied
/// load) mode — used by some laptop speakers.
pub const BTL_ENABLE: u8 = 0x01;

/// ALC256 init (Linux `alc269.c::alc256_init` unconditional tail,
/// verified against master and v6.6, 2026-11-05 — order is Linux's
/// order). The `ultra_low_power` and jack-sense-gated parts of the
/// hook are not static tables, so they stay unwired.
pub const ALC256_INIT: &[CoefOp] = &[
    // 3k pull-low control for the headset jack (Linux:
    // alc_update_coef_idx(codec, 0x46, 3 << 12, 0)). The rescued
    // plain write (0x46, 0x0000) was verified-wrong (#776) and is
    // NOT restored as a write: a plain 0 would clear bits Linux
    // preserves. This masked update is the #1496 RMW primitive's
    // reason to exist.
    CoefOp::update(0x46, 0x3000, 0x0000),
    // "Clear bit" pulse on nid 0x53, idx 0x02: set bit 15, then
    // clear it again (net-zero final state; the edge is the point).
    CoefOp::update_nid(0x53, 0x02, 0x8000, 0x8000),
    CoefOp::update_nid(0x53, 0x02, 0x8000, 0x0000),
    // PC-Beep noise gate workaround: expose headphone mic on NID 0x1A
    // instead of PC Beep, and disable 1Ah loopback. Linux:
    // alc_write_coef_idx(codec, 0x36, 0x5757)
    CoefOp::write(0x36, 0x5757),
];

/// ALC255 init — the same `alc256_init` hook (Linux dispatch
/// 0x10ec0235/0255), so the same table.
pub const ALC255_INIT: &[CoefOp] = ALC256_INIT;

/// ALC230 init — the same `alc256_init` hook (Linux dispatch
/// 0x10ec0230), so the same table (#1496 enum gap).
pub const ALC230_INIT: &[CoefOp] = ALC256_INIT;

/// ALC233 init (Linux `alc269.c::alc233_init`).
pub const ALC233_INIT: &[CoefOp] = &[
    CoefOp::write(0x35, 0x0000), // clear class-D digital pattern
];

/// ALC235 init — the same `alc256_init` hook (Linux dispatch
/// 0x10ec0235), so the same table as ALC256.
pub const ALC235_INIT: &[CoefOp] = ALC256_INIT;

/// ALC236 init — the same `alc256_init` hook (Linux dispatch
/// 0x10ec0236), so the same table as ALC256.
/// NOTE (#776, verified 2026-11-05): the rescued second row,
/// (0x1B, 0x0c0b) "pop-noise reduction", was DELETED — 0x1b=0x0c0b
/// is ALC255's value in Linux's `alc255_set_default_jack_type`
/// (`alc255fw[]`); ALC236 takes 0x0c4b (`alc256fw[]`), and only
/// under the headset-mode fixup, not unconditional init.
pub const ALC236_INIT: &[CoefOp] = ALC256_INIT;

/// ALC215 / ALC225 / ALC245 / ALC299 init — Linux runs
/// `alc225_init` for these (dispatch 0x10ec0215/0225/0245/0299,
/// plus 0x0285/0289 by coef0 variant), and that hook issues no
/// unconditional static coef ops: the `ultra_low_power` updates
/// are flag-gated, `alc285_hp_init` is boot/S3/S4-gated, and the
/// rest is jack-sense-gated. Empty table, by verification — not by
/// omission (#1496).
pub const ALC225_INIT: &[CoefOp] = &[];

/// ALC270 init.
pub const ALC270_INIT: &[CoefOp] = &[CoefOp::write(0x14, 0x0080)];

/// ALC274 / ALC700 init — Linux runs `alc294_init` for these
/// (dispatch 0x10ec0274/0700, plus 0x0234/0294/0701/0703/0711),
/// and that hook is `alc294_hp_init` (a depop procedure with a
/// poll loop — not a static table) plus `alc_default_init`
/// (jack-sense-gated only). Empty table, by verification. The
/// parse-time masked updates Linux issues for these arms
/// (`alc_update_coef_idx(codec, 0x6b, 0x0018, ...)` for the ALC294
/// arm, `alc_update_coef_idx(codec, 0x4a, 1 << 15, 0)` for the
/// ALC700 arm) run at codec patch, not at init/resume — they live
/// in [`parse_table_for`], not here. Still unwired, as remainders:
/// `alc294_hp_init`'s depop procedure (coefex nid 0x58 poll loop,
/// 20 × 50 ms) and `alc_default_init`'s sense-gated PIN_OUT +
/// amp-unmute tail.
pub const ALC294_INIT: &[CoefOp] = &[];

/// ALC280 init.
pub const ALC280_INIT: &[CoefOp] = &[CoefOp::write(0x35, 0x1080)];

/// ALC282 init — Linux `alc282_init`'s unconditional part,
/// `alc282_restore_default_value`, i.e. the `alc282_coefs` table
/// via `alc_process_coef_fw`, transcribed row-for-row in Linux's
/// order (verified against master and v6.6, 2026-11-05 — the two
/// tables are identical in both). The rescued rows
/// (0x35, 0x0000), (0x36, 0x0000) are absent from Linux entirely
/// and were replaced. The sense-gated tail of `alc282_init`
/// (0x78 capless HP-amp sequence, HP-pin mute / PIN_OUT) is not
/// a static table: it is wired as the HP-pin tail in
/// `runtime.rs::apply_hp_tail`, gated on the graph's HP pin
/// (`hda_codec::Codec::hp_pin`) and jack sense. #1496 asked for
/// the WRITE_COEF subset at minimum; the full table is wired because the RMW
/// primitive built in this lane expresses the UPDATE_COEF rows
/// exactly, in the same order — a write-only subset would leave
/// the FIFO/clock, jack-detect and class-D bits Linux sets at
/// reset defaults.
pub const ALC282_INIT: &[CoefOp] = &[
    CoefOp::write(0x03, 0x0002),          // Power Down Control
    CoefOp::update(0x05, 0xff3f, 0x0700), // FIFO and filter clock
    CoefOp::write(0x07, 0x0200),          // DMIC control
    CoefOp::update(0x06, 0x00f0, 0x0000), // Analog clock
    CoefOp::update(0x08, 0xfffc, 0x0c2c), // JD
    CoefOp::write(0x0a, 0xcccc),          // JD offset1
    CoefOp::write(0x0b, 0xcccc),          // JD offset2
    CoefOp::write(0x0e, 0x6e00),          // LDO1/2/3, DAC/ADC
    CoefOp::update(0x0f, 0xf800, 0x1000), // JD
    CoefOp::update(0x10, 0xfc00, 0x0c00), // Capless
    CoefOp::write(0x6f, 0x0000),          // Class D test 4
    CoefOp::update(0x0c, 0xfe00, 0x0000), // IO power down directly
    CoefOp::write(0x34, 0xa0c0),          // ANC
    CoefOp::update(0x16, 0x0008, 0x0000), // AGC MUX
    CoefOp::update(0x1d, 0x00e0, 0x0000), // DAC simple content protection
    CoefOp::update(0x1f, 0x00e0, 0x0000), // ADC simple content protection
    CoefOp::write(0x21, 0x8804),          // DAC ADC Zero Detection
    CoefOp::write(0x63, 0x2902),          // PLL
    CoefOp::write(0x68, 0xa080),          // capless control 2
    CoefOp::write(0x69, 0x3400),          // capless control 3
    CoefOp::write(0x6a, 0x2f3e),          // capless control 4
    CoefOp::write(0x6b, 0x0000),          // capless control 5
    CoefOp::update(0x6d, 0x0fff, 0x0900), // class D test 2
    CoefOp::write(0x6e, 0x110a),          // class D test 3
    CoefOp::update(0x70, 0x00f8, 0x00d8), // class D test 5
    CoefOp::write(0x71, 0x0014),          // class D test 6
    CoefOp::write(0x72, 0xc2ba),          // classD OCP
    CoefOp::update(0x77, 0x0f80, 0x0000), // classD pure DC test
    CoefOp::write(0x6c, 0xfc06),          // Class D amp control
];

/// ALC283 init — Linux `alc283_init`'s unconditional part,
/// `alc283_restore_default_value`, i.e. the `alc283_coefs` table
/// via `alc_process_coef_fw`, transcribed row-for-row in Linux's
/// order (verified against master and v6.6, 2026-11-05 — the two
/// tables are identical in both). The rescued rows
/// (0x1A, 0x2c11), (0x06, 0x2104) are absent from Linux entirely
/// and were replaced. Note the `UPDATE_COEFEX(0x53, ...)` row: it
/// addresses nid 0x53, not the coef node — the reason `CoefOp`
/// carries a nid. The sense-gated tail of `alc283_init` (0x43
/// capless HP-amp sequence, 0x46 update, HP-pin mute / PIN_OUT)
/// is not a static table: it is wired as the HP-pin tail in
/// `runtime.rs::apply_hp_tail`, gated on the graph's HP pin
/// (`hda_codec::Codec::hp_pin`) and jack sense. The 0x46 update
/// there is the same masked update ALC256's tail carries, but
/// gated on the HP pin existing. Same full-table rationale as ALC282.
pub const ALC283_INIT: &[CoefOp] = &[
    CoefOp::write(0x03, 0x0002),                    // Power Down Control
    CoefOp::update(0x05, 0xff3f, 0x0700),           // FIFO and filter clock
    CoefOp::write(0x07, 0x0200),                    // DMIC control
    CoefOp::update(0x06, 0x00f0, 0x0000),           // Analog clock
    CoefOp::update(0x08, 0xfffc, 0x0c2c),           // JD
    CoefOp::write(0x0a, 0xcccc),                    // JD offset1
    CoefOp::write(0x0b, 0xcccc),                    // JD offset2
    CoefOp::write(0x0e, 0x6fc0),                    // LDO1/2/3, DAC/ADC
    CoefOp::update(0x0f, 0xf800, 0x1000),           // JD
    CoefOp::update(0x10, 0xfc00, 0x0c00),           // Capless
    CoefOp::write(0x3a, 0x0000),                    // Class D test 4
    CoefOp::update(0x0c, 0xfe00, 0x0000),           // IO power down directly
    CoefOp::write(0x22, 0xa0c0),                    // ANC
    CoefOp::update_nid(0x53, 0x01, 0x000f, 0x0008), // AGC MUX
    CoefOp::update(0x1d, 0x00e0, 0x0000),           // DAC simple content protection
    CoefOp::update(0x1f, 0x00e0, 0x0000),           // ADC simple content protection
    CoefOp::write(0x21, 0x8804),                    // DAC ADC Zero Detection
    CoefOp::write(0x2e, 0x2902),                    // PLL
    CoefOp::write(0x33, 0xa080),                    // capless control 2
    CoefOp::write(0x34, 0x3400),                    // capless control 3
    CoefOp::write(0x35, 0x2f3e),                    // capless control 4
    CoefOp::write(0x36, 0x0000),                    // capless control 5
    CoefOp::update(0x38, 0x0fff, 0x0900),           // class D test 2
    CoefOp::write(0x39, 0x110a),                    // class D test 3
    CoefOp::update(0x3b, 0x00f8, 0x00d8),           // class D test 5
    CoefOp::write(0x3c, 0x0014),                    // class D test 6
    CoefOp::write(0x3d, 0xc2ba),                    // classD OCP
    CoefOp::update(0x42, 0x0f80, 0x0000),           // classD pure DC test
    CoefOp::write(0x49, 0x0000),                    // test mode
    CoefOp::update(0x40, 0xf800, 0x9800),           // Class D DC enable
    CoefOp::update(0x42, 0xf000, 0x2000),           // DC offset
    CoefOp::write(0x37, 0xfc06),                    // Class D amp control
    CoefOp::update(0x1b, 0x8000, 0x0000),           // HP JD control
];

/// ALC285 init (Linux `alc269.c::alc285_init`).
pub const ALC285_INIT: &[CoefOp] = &[
    // Enable the standard speaker path (typical HP / Lenovo bring-up).
    CoefOp::write(0x36, 0x5757),
    // Bottom-end speaker boost.
    CoefOp::write(0x6F, 0x0007),
];

/// ALC286 init.
pub const ALC286_INIT: &[CoefOp] = &[CoefOp::write(0x10, 0xFA34), CoefOp::write(0x11, 0x6810)];

/// ALC287 init — same baseline as ALC285 with one HP-amp-fix bit.
pub const ALC287_INIT: &[CoefOp] = &[
    CoefOp::write(0x36, 0x5757),
    CoefOp::write(0x6F, 0x0007),
    CoefOp::write(0x38, 0x4901), // HP amp routing.
];

/// ALC289 init.
pub const ALC289_INIT: &[CoefOp] = &[CoefOp::write(0x36, 0x5757)];

/// ALC290 init.
pub const ALC290_INIT: &[CoefOp] = &[CoefOp::write(0x10, 0x0E40)];

/// ALC292 init.
pub const ALC292_INIT: &[CoefOp] = &[CoefOp::write(0x6, 0x2104)];

/// ALC293 init.
pub const ALC293_INIT: &[CoefOp] = &[CoefOp::write(0x35, 0x0000)];

/// ALC294 init — see the empty verified table above: the rescued
/// rows (0x36, 0x5757), (0x67, 0x4060) are NOT restored here.
/// Linux's `alc294_init` has no unconditional static coef ops
/// (depop poll loop + sense-gated default init), so the table is
/// empty; the rescued rows stay deleted as unverified (#776).

/// ALC295 init (Linux `alc269.c::alc295_init`).
pub const ALC295_INIT: &[CoefOp] = &[
    CoefOp::write(0x36, 0x5757),
    // Speaker boost (Linux Asus / HP fixup).
    CoefOp::write(0x4A, 0xA050),
];

/// ALC298 init.
pub const ALC298_INIT: &[CoefOp] = &[CoefOp::write(0x36, 0x5757), CoefOp::write(0x6F, 0x0007)];

/// ALC300 init — Linux runs no init hook for 0x10ec0300 (the
/// default `alc_default_init`, jack-sense-gated only), so the
/// table is empty, by verification (#1496).
pub const ALC300_INIT: &[CoefOp] = &[];

/// ALC623 init — Linux runs `alc222_init` for 0x10ec0623
/// (dispatch shared with 0x10ec0222), and that hook is
/// jack-sense-gated pin control only, with no coef writes at all.
/// Empty table, by verification (#1496). `alc222_init`'s
/// sense-gated PIN_OUT + amp-unmute tail (HP pin + pin 0x14) is
/// not a coef table and stays unwired, a remainder (#776).
pub const ALC623_INIT: &[CoefOp] = &[];

// "ALC32xx" rebrands share their core silicon with one of the above —
// reuse the matching base table.
pub const ALC3204_INIT: &[CoefOp] = ALC287_INIT;
pub const ALC3225_INIT: &[CoefOp] = ALC295_INIT;
pub const ALC3236_INIT: &[CoefOp] = ALC236_INIT;
pub const ALC3254_INIT: &[CoefOp] = ALC287_INIT;
pub const ALC3266_INIT: &[CoefOp] = ALC256_INIT;
pub const ALC3268_INIT: &[CoefOp] = ALC256_INIT;
pub const ALC3286_INIT: &[CoefOp] = ALC287_INIT;
pub const ALC3287_INIT: &[CoefOp] = ALC287_INIT;

/// Pick the init table for a known chip.
pub fn init_table_for(chip: RealtekChip) -> &'static [CoefOp] {
    match chip {
        RealtekChip::Alc215 => ALC225_INIT,
        RealtekChip::Alc222 => ALC623_INIT,
        RealtekChip::Alc225 => ALC225_INIT,
        RealtekChip::Alc230 => ALC230_INIT,
        RealtekChip::Alc233 => ALC233_INIT,
        RealtekChip::Alc234 => ALC294_INIT,
        RealtekChip::Alc235 => ALC235_INIT,
        RealtekChip::Alc236 => ALC236_INIT,
        RealtekChip::Alc245 => ALC225_INIT,
        RealtekChip::Alc255 => ALC255_INIT,
        RealtekChip::Alc256 => ALC256_INIT,
        RealtekChip::Alc257 => ALC256_INIT,
        RealtekChip::Alc270 => ALC270_INIT,
        RealtekChip::Alc274 => ALC294_INIT,
        RealtekChip::Alc280 => ALC280_INIT,
        RealtekChip::Alc282 => ALC282_INIT,
        RealtekChip::Alc283 => ALC283_INIT,
        RealtekChip::Alc285 => ALC285_INIT,
        RealtekChip::Alc286 => ALC286_INIT,
        RealtekChip::Alc287 => ALC287_INIT,
        RealtekChip::Alc289 => ALC289_INIT,
        RealtekChip::Alc290 => ALC290_INIT,
        RealtekChip::Alc292 => ALC292_INIT,
        RealtekChip::Alc293 => ALC293_INIT,
        RealtekChip::Alc294 => ALC294_INIT,
        RealtekChip::Alc295 => ALC295_INIT,
        RealtekChip::Alc298 => ALC298_INIT,
        RealtekChip::Alc299 => ALC225_INIT,
        RealtekChip::Alc300 => ALC300_INIT,
        RealtekChip::Alc623 => ALC623_INIT,
        RealtekChip::Alc700 => ALC294_INIT,
        RealtekChip::Alc701 => ALC294_INIT,
        RealtekChip::Alc703 => ALC294_INIT,
        RealtekChip::Alc711 => ALC294_INIT,
        RealtekChip::Alc3204 => ALC3204_INIT,
        RealtekChip::Alc3225 => ALC3225_INIT,
        RealtekChip::Alc3236 => ALC3236_INIT,
        RealtekChip::Alc3254 => ALC3254_INIT,
        RealtekChip::Alc3266 => ALC3266_INIT,
        RealtekChip::Alc3268 => ALC3268_INIT,
        RealtekChip::Alc3286 => ALC3286_INIT,
        RealtekChip::Alc3287 => ALC3287_INIT,
    }
}

// ── Per-chip parse-time coef updates ──────────────────────────────
//
// Linux `sound/hda/codecs/realtek/alc269.c::patch_alc269` issues
// two masked coef updates from its codec-variant dispatch switch,
// before fixup selection (`snd_hda_pick_fixup`) and before the
// auto-config parse (`alc269_parse_auto_config`) builds the widget
// graph — i.e. at codec patch time, once, never re-run on resume
// (the init hook is what re-runs on resume). The live path
// mirrors that: [`parse_table_for`] is applied at probe before
// enumeration, and NOT re-applied at reinit. Verified against
// Linux master (2026-11-06, HEAD f66469d).
//
// - ALC294 arm (0x10ec0234/0274/0294):
//   `alc_update_coef_idx(codec, 0x6b, 0x0018, (1<<4) | (1<<3))`
//   — "UAJ MIC Vref control by verb".
// - ALC700 arm (0x10ec0700/0701/0703/0711):
//   `alc_update_coef_idx(codec, 0x4a, 1 << 15, 0)`
//   — "Combo jack auto trigger control".
//
// The values are masked updates, not plain writes: bits outside
// the mask are preserved, exactly as `alc_update_coef_idx` (and
// the live path's `update_coef_idx`) requires — a failed coef
// read skips the write, as Linux does on -1.

/// ALC294-arm parse-time update (ALC234/274/294): set coef 0x6b
/// bits 3–4 (UAJ MIC Vref control by verb).
pub const ALC294_PARSE: &[CoefOp] = &[CoefOp::update(0x6b, 0x0018, 0x0018)];

/// ALC700-arm parse-time update (ALC700/701/703/711): clear coef
/// 0x4a bit 15 (Combo jack auto trigger control).
pub const ALC700_PARSE: &[CoefOp] = &[CoefOp::update(0x4a, 0x8000, 0x0000)];

/// Pick the parse-time coef table for a known chip. Empty for
/// every chip outside the ALC294 and ALC700 dispatch arms.
pub fn parse_table_for(chip: RealtekChip) -> &'static [CoefOp] {
    match chip {
        RealtekChip::Alc215 => &[],
        RealtekChip::Alc222 => &[],
        RealtekChip::Alc225 => &[],
        RealtekChip::Alc230 => &[],
        RealtekChip::Alc233 => &[],
        RealtekChip::Alc234 => ALC294_PARSE,
        RealtekChip::Alc235 => &[],
        RealtekChip::Alc236 => &[],
        RealtekChip::Alc245 => &[],
        RealtekChip::Alc255 => &[],
        RealtekChip::Alc256 => &[],
        RealtekChip::Alc257 => &[],
        RealtekChip::Alc270 => &[],
        RealtekChip::Alc274 => ALC294_PARSE,
        RealtekChip::Alc280 => &[],
        RealtekChip::Alc282 => &[],
        RealtekChip::Alc283 => &[],
        RealtekChip::Alc285 => &[],
        RealtekChip::Alc286 => &[],
        RealtekChip::Alc287 => &[],
        RealtekChip::Alc289 => &[],
        RealtekChip::Alc290 => &[],
        RealtekChip::Alc292 => &[],
        RealtekChip::Alc293 => &[],
        RealtekChip::Alc294 => ALC294_PARSE,
        RealtekChip::Alc295 => &[],
        RealtekChip::Alc298 => &[],
        RealtekChip::Alc299 => &[],
        RealtekChip::Alc300 => &[],
        RealtekChip::Alc623 => &[],
        RealtekChip::Alc700 => ALC700_PARSE,
        RealtekChip::Alc701 => ALC700_PARSE,
        RealtekChip::Alc703 => ALC700_PARSE,
        RealtekChip::Alc711 => ALC700_PARSE,
        RealtekChip::Alc3204 => &[],
        RealtekChip::Alc3225 => &[],
        RealtekChip::Alc3236 => &[],
        RealtekChip::Alc3254 => &[],
        RealtekChip::Alc3266 => &[],
        RealtekChip::Alc3268 => &[],
        RealtekChip::Alc3286 => &[],
        RealtekChip::Alc3287 => &[],
    }
}

// ── Per-laptop pin-override quirks ──────────────────────────────────
//
// HDA codecs ship with a vendor-default pin / connection layout that
// is correct on the chip's reference board. Every laptop OEM
// re-routes pins to fit their physical jack layout, but the codec's
// Get-Config-Default response is the OEM's value — so a stock
// `alc_init` only produces sound on the literal Realtek reference
// board. Linux solves this with a giant `alc269_fixup_models[]`
// table; we ship a smaller distilled version for the codecs +
// laptop families the user actually runs.
//
// Each entry is `(codec_subsystem_id, override_table)`. The
// `subsystem_id` comes from `VERB_GET_SUBSYSTEM_ID` (codec response,
// formatted as `subvendor << 16 | subdevice`); a match swaps in a
// per-laptop override of the chip's pin defaults.

/// One pin override — `(nid, config_default)`. Applied to the
/// decoded graph after enumeration (Linux
/// `snd_hda_codec_set_pincfg`: the value lives in the driver's
/// pin cache, higher priority than the hardware's
/// Get-Config-Default response — no SET_CONFIG_DEFAULT verb is
/// issued, in Linux or here).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PinOverride {
    pub nid: u8,
    pub cfg: u32,
}

/// One connection-list override — `(nid, replacement list)`.
/// Applied to the decoded graph after enumeration (Linux
/// `snd_hda_override_conn_list`: the list lives in the driver's
/// connection cache — no verb is issued, and the
/// connection-select index a path later sends is the index into
/// this overridden list).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConnListOverride {
    pub nid: u8,
    pub conns: &'static [u8],
}

/// One preferred-DAC pair — `(pin, dac)`. Applied to the decoded
/// graph after enumeration (Linux `spec->gen.preferred_dacs`):
/// when the output path for `pin` is built, `dac` wins over
/// connection-list order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PreferredDac {
    pub pin: u8,
    pub dac: u8,
}

/// One verb in a chained fixup's verb sequence — `(nid, verb)`,
/// where `verb` is the 20-bit verb+payload word as passed to
/// `make_verb` (e.g. `verb::SET_COEF_INDEX | 0x26`). Issued
/// verbatim, in order, before enumeration (Linux `HDA_FIXUP_VERBS`).
/// This is the only quirk component that touches the wire: a
/// sequence like the YOGA9 bass-speaker enable writes
/// SET_PROC_COEF several times after one SET_COEF_INDEX — a
/// multi-word coef command — so it cannot be expressed as
/// (index, value) pairs, which would re-issue the index before
/// every value and break the command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SeqVerb {
    pub nid: u8,
    pub verb: u32,
}

impl SeqVerb {
    pub const fn new(nid: u8, verb: u32) -> Self {
        SeqVerb { nid, verb }
    }
}

/// One quirk entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Quirk {
    /// Codec subsystem ID = `(subvendor << 16) | subdevice`.
    pub subsystem_id: u32,
    /// Matching codec.
    pub chip: RealtekChip,
    /// Pin overrides to apply.
    pub pins: &'static [PinOverride],
    /// Connection-list overrides to apply.
    pub conns: &'static [ConnListOverride],
    /// Preferred DACs for path building.
    pub preferred_dacs: &'static [PreferredDac],
    /// Chained coef verb sequence, issued before enumeration.
    pub coef_seq: &'static [SeqVerb],
    /// Friendly identifier (e.g. `"Lenovo Yoga 7 2-in-1 16AKP10"`).
    pub name: &'static str,
}

// ── Lenovo ThinkPad bring-up tables ─────────────────────────────────
//
// Source: Linux `alc269_fixup_models[]` entries
// ALC285_FIXUP_THINKPAD_X1_GEN7,
// ALC285_FIXUP_LENOVO_HEADPHONE_NOISE,
// ALC287_FIXUP_LENOVO_THINKPAD_T14_GEN3.

pub const QUIRK_X1_CARBON_GEN7: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    }, // speaker @ "Internal mid"
    PinOverride {
        nid: 0x17,
        cfg: 0x90170150,
    }, // boost amp speaker
    PinOverride {
        nid: 0x19,
        cfg: 0x03A11030,
    }, // mic @ jack
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    }, // headphone @ jack
];

pub const QUIRK_THINKPAD_T14_GEN3: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x17,
        cfg: 0x90170150,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x04A11040,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x04211020,
    },
];

// ── HP EliteBook / Pavilion bring-up tables ─────────────────────────

pub const QUIRK_HP_ELITEBOOK_845_G8: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x03a11020,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x03211030,
    },
];

// ── Dell Latitude / XPS bring-up tables ─────────────────────────────

pub const QUIRK_DELL_LATITUDE_5430: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x90a60140,
    }, // internal mic.
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    },
];

// ── ASUS ROG / Zephyrus bring-up tables ─────────────────────────────

pub const QUIRK_ASUS_ROG: &[PinOverride] = &[
    PinOverride {
        nid: 0x12,
        cfg: 0x90A60130,
    },
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x17,
        cfg: 0x90170120,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    },
];

// ── MSI bring-up tables ─────────────────────────────────────────────

pub const QUIRK_MSI: &[PinOverride] = &[
    PinOverride {
        nid: 0x14,
        cfg: 0x90170110,
    },
    PinOverride {
        nid: 0x19,
        cfg: 0x03A11040,
    },
    PinOverride {
        nid: 0x21,
        cfg: 0x03211020,
    },
];

// ── Quirk table ─────────────────────────────────────────────────────

/// Static quirk table. Indexed by subsystem ID through `find_quirk`.
///
/// VERIFICATION STATUS (#776, 2026-11-05): none of these six keys
/// verified as a codec subsystem ID against Linux
/// `sound/hda/codecs/realtek/alc269.c` (master and v6.6) — see the
/// module docs. The live path does not consult this table until
/// its entries are re-derived with correct codec SSIDs.
pub const QUIRK_TABLE: &[Quirk] = &[
    Quirk {
        subsystem_id: 0x17AA_22BE, // Lenovo X1 Carbon Gen 7
        chip: RealtekChip::Alc285,
        pins: QUIRK_X1_CARBON_GEN7,
        conns: &[],
        preferred_dacs: &[],
        coef_seq: &[],
        name: "Lenovo ThinkPad X1 Carbon Gen 7",
    },
    Quirk {
        subsystem_id: 0x17AA_22F0,
        chip: RealtekChip::Alc287,
        pins: QUIRK_THINKPAD_T14_GEN3,
        conns: &[],
        preferred_dacs: &[],
        coef_seq: &[],
        name: "Lenovo ThinkPad T14 Gen 3",
    },
    Quirk {
        subsystem_id: 0x103C_8716, // HP EliteBook 845 G8 (AMD Renoir)
        chip: RealtekChip::Alc285,
        pins: QUIRK_HP_ELITEBOOK_845_G8,
        conns: &[],
        preferred_dacs: &[],
        coef_seq: &[],
        name: "HP EliteBook 845 G8",
    },
    Quirk {
        subsystem_id: 0x1028_0AB9, // Dell Latitude 5430
        chip: RealtekChip::Alc256,
        pins: QUIRK_DELL_LATITUDE_5430,
        conns: &[],
        preferred_dacs: &[],
        coef_seq: &[],
        name: "Dell Latitude 5430",
    },
    Quirk {
        subsystem_id: 0x1043_1A30, // ASUS ROG Strix
        chip: RealtekChip::Alc295,
        pins: QUIRK_ASUS_ROG,
        conns: &[],
        preferred_dacs: &[],
        coef_seq: &[],
        name: "ASUS ROG Strix",
    },
    Quirk {
        subsystem_id: 0x1462_1234, // MSI generic
        chip: RealtekChip::Alc256,
        pins: QUIRK_MSI,
        conns: &[],
        preferred_dacs: &[],
        coef_seq: &[],
        name: "MSI laptop",
    },
];

/// Look up a quirk by codec subsystem ID. Returns the first matching
/// entry — the table is short enough that a linear scan is fine.
pub fn find_quirk(subsystem_id: u32) -> Option<&'static Quirk> {
    QUIRK_TABLE.iter().find(|q| q.subsystem_id == subsystem_id)
}

/// Find a quirk for a known chip ignoring subsystem ID. NOT used by
/// the live path (#776): Linux has no such fallback, and applying
/// another laptop's pin overrides to a machine that merely shares
/// the codec would misroute its pins. Kept for diagnostics and
/// tests only.
pub fn first_for_chip(chip: RealtekChip) -> Option<&'static Quirk> {
    QUIRK_TABLE.iter().find(|q| q.chip == chip)
}

/// Number of registered quirks.
pub const fn quirk_count() -> usize {
    QUIRK_TABLE.len()
}

// ── Re-derived pin quirks (verified against Linux, #1496) ──────────
//
// Linux `sound/hda/codecs/realtek/alc269.c::alc287_fixup_yoga9_
// 14iap7_bass_spk_pin`, verified against master and v6.6
// (2026-11-05 — the function is identical in both; the
// `HDA_CODEC_QUIRK` entries below are master-only, v6.6 matched
// the same fixup by PCI SSID only):
//
// ```c
// static const struct hda_pintbl pincfgs[] = {
//     { 0x17, 0x90170121 },
// };
// static const hda_nid_t conn[] = { 0x02, 0x03 };
// static const hda_nid_t preferred_pairs[] = {
//     0x14, 0x02, 0x17, 0x02, 0x21, 0x03, 0
// };
// snd_hda_apply_pincfgs(codec, pincfgs);
// snd_hda_override_conn_list(codec, 0x17, 2, conn);
// spec->gen.preferred_dacs = preferred_pairs;
// ```
//
// The fixup also calls `hda_fixup_ideapad_acpi` (keyboard mute
// LEDs via ACPI, `sound/hda/codecs/helpers/ideapad_hotkey_led.c`)
// and chains `ALC287_FIXUP_YOGA9_14IAP7_BASS_SPK`, the coef verb
// sequence below. The LED half is NOT ported (remainder, #776):
// Linux's helper (PRE_PROBE, gated on subsystem vendor 0x17aa +
// ACPI LHK2019/VPC2004 present) registers mute / mic-mute LED
// class devices bound to the `audio-mute` / `mic-mute` triggers,
// driven on the platform side by the Lenovo WMI hotkey-utilities
// driver. NARF has the LED registry (`drivers/leds`), the ACPI
// HID lookup (`narf_aml::find_device_by_hid`), and WMI hotkey
// *event* decoding — but no `audio-mute` / `mic-mute` LED
// trigger, no vmaster mute hook in the HDA path, and no Lenovo
// WMI hotkey-utilities LED driver, so there is no sink for the
// fixup half to drive. The pin half is why
// the fixup exists at all: pin 0x17 (bass speakers) is wrongly
// reported as unconnected (BIOS pin default 0x411111f0), so
// without it the kernel configures speaker_outs=0 for the bass
// and only the tweeters (pin 0x14) play; and DACs 0x06/0x08 have
// no volume controls, so the connection list must avoid them.

/// YOGA9 pin override: pin 0x17 becomes a fixed speaker.
pub const QUIRK_YOGA9_BASS_SPK_PINS: &[PinOverride] = &[PinOverride {
    nid: 0x17,
    cfg: 0x9017_0121,
}];

/// YOGA9 connection-list override: pin 0x17 connects to DACs
/// 0x02/0x03 only.
pub const QUIRK_YOGA9_BASS_SPK_CONNS: &[ConnListOverride] = &[ConnListOverride {
    nid: 0x17,
    conns: &[0x02, 0x03],
}];

/// YOGA9 preferred DACs: speakers (0x14, 0x17) on DAC 0x02,
/// headphones (0x21) on DAC 0x03.
pub const QUIRK_YOGA9_BASS_SPK_PREFS: &[PreferredDac] = &[
    PreferredDac {
        pin: 0x14,
        dac: 0x02,
    },
    PreferredDac {
        pin: 0x17,
        dac: 0x02,
    },
    PreferredDac {
        pin: 0x21,
        dac: 0x03,
    },
];

/// YOGA9 chained bass-speaker enable sequence
/// (`ALC287_FIXUP_YOGA9_14IAP7_BASS_SPK`, `HDA_FIXUP_VERBS`),
/// transcribed verb-for-verb from Linux in order. Each group is
/// one SET_COEF_INDEX followed by several SET_PROC_COEF writes —
/// a multi-word coef command, not (index, value) pairs. Left
/// speaker (coef 0x24 = 0x41), then four 0x26 command groups;
/// right speaker (coef 0x24 = 0x46), then four more.
pub const QUIRK_YOGA9_BASS_SPK_SEQ: &[SeqVerb] = &[
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x24),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x41),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x0c),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x1a),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x0f),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x42),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x10),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x40),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x02),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x24),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x46),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x0c),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x2a),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x0f),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x46),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x10),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x44),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_COEF_INDEX | 0x26),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x02),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0x00),
    SeqVerb::new(COEF_NODE, crate::hda_codec::verb::SET_PROC_COEF | 0xb020),
];

/// Verified quirk table. One entry per codec subsystem ID Linux
/// matches on `HDA_CODEC_QUIRK` for
/// `ALC287_FIXUP_YOGA9_14IAP7_BASS_SPK_PIN` (master
/// `alc269_fixup_tbl`; names are Linux's quirk-table labels).
/// The live path consults THIS table, never [`QUIRK_TABLE`].
pub const VERIFIED_QUIRK_TABLE: &[Quirk] = &[
    Quirk {
        subsystem_id: 0x17AA_38B1, // Lenovo Yoga Pro 7 14IRH8
        chip: RealtekChip::Alc287,
        pins: QUIRK_YOGA9_BASS_SPK_PINS,
        conns: QUIRK_YOGA9_BASS_SPK_CONNS,
        preferred_dacs: QUIRK_YOGA9_BASS_SPK_PREFS,
        coef_seq: QUIRK_YOGA9_BASS_SPK_SEQ,
        name: "Lenovo Yoga Pro 7 14IRH8",
    },
    Quirk {
        subsystem_id: 0x17AA_386A, // Lenovo Yoga 7 16IAP7
        chip: RealtekChip::Alc287,
        pins: QUIRK_YOGA9_BASS_SPK_PINS,
        conns: QUIRK_YOGA9_BASS_SPK_CONNS,
        preferred_dacs: QUIRK_YOGA9_BASS_SPK_PREFS,
        coef_seq: QUIRK_YOGA9_BASS_SPK_SEQ,
        name: "Lenovo Yoga 7 16IAP7",
    },
    Quirk {
        subsystem_id: 0x17AA_391A, // Lenovo Yoga Slim 7 14AKP10
        chip: RealtekChip::Alc287,
        pins: QUIRK_YOGA9_BASS_SPK_PINS,
        conns: QUIRK_YOGA9_BASS_SPK_CONNS,
        preferred_dacs: QUIRK_YOGA9_BASS_SPK_PREFS,
        coef_seq: QUIRK_YOGA9_BASS_SPK_SEQ,
        name: "Lenovo Yoga Slim 7 14AKP10",
    },
    Quirk {
        subsystem_id: 0x17AA_391C, // Lenovo Yoga 7 2-in-1 14AKP10
        chip: RealtekChip::Alc287,
        pins: QUIRK_YOGA9_BASS_SPK_PINS,
        conns: QUIRK_YOGA9_BASS_SPK_CONNS,
        preferred_dacs: QUIRK_YOGA9_BASS_SPK_PREFS,
        coef_seq: QUIRK_YOGA9_BASS_SPK_SEQ,
        name: "Lenovo Yoga 7 2-in-1 14AKP10",
    },
    Quirk {
        subsystem_id: 0x17AA_391D, // Lenovo Yoga 7 2-in-1 16AKP10
        chip: RealtekChip::Alc287,
        pins: QUIRK_YOGA9_BASS_SPK_PINS,
        conns: QUIRK_YOGA9_BASS_SPK_CONNS,
        preferred_dacs: QUIRK_YOGA9_BASS_SPK_PREFS,
        coef_seq: QUIRK_YOGA9_BASS_SPK_SEQ,
        name: "Lenovo Yoga 7 2-in-1 16AKP10",
    },
    Quirk {
        subsystem_id: 0x17AA_3926, // Legion Pro 5 16ADR10
        chip: RealtekChip::Alc287,
        pins: QUIRK_YOGA9_BASS_SPK_PINS,
        conns: QUIRK_YOGA9_BASS_SPK_CONNS,
        preferred_dacs: QUIRK_YOGA9_BASS_SPK_PREFS,
        coef_seq: QUIRK_YOGA9_BASS_SPK_SEQ,
        name: "Legion Pro 5 16ADR10",
    },
    Quirk {
        subsystem_id: 0x17AA_394C, // Lenovo Yoga Slim 7 14AGP11
        chip: RealtekChip::Alc287,
        pins: QUIRK_YOGA9_BASS_SPK_PINS,
        conns: QUIRK_YOGA9_BASS_SPK_CONNS,
        preferred_dacs: QUIRK_YOGA9_BASS_SPK_PREFS,
        coef_seq: QUIRK_YOGA9_BASS_SPK_SEQ,
        name: "Lenovo Yoga Slim 7 14AGP11",
    },
];

/// Look up a verified quirk by codec subsystem ID. The live path
/// additionally requires the entry's chip to match the detected
/// codec — a subsystem id on a different codec is not a match.
/// The rescued [`QUIRK_TABLE`] keys must never match here: they
/// are PCI SSIDs or nonexistent values, not codec subsystem IDs.
pub fn find_verified_quirk(subsystem_id: u32) -> Option<&'static Quirk> {
    VERIFIED_QUIRK_TABLE
        .iter()
        .find(|q| q.subsystem_id == subsystem_id)
}

/// Number of verified quirks.
pub const fn verified_quirk_count() -> usize {
    VERIFIED_QUIRK_TABLE.len()
}
