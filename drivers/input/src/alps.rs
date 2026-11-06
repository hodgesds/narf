//! ALPS PS/2 touchpad absolute-mode protocol, versions 1–8.
//!
//! The device behind the i8042 AUX channel is usually more than a
//! bare 3-byte mouse. This module owns the ALPS half of that: the
//! model table, the E6/E7/EC identification reports, the
//! absolute-mode enable sequences, and the pure packet decoders
//! for every protocol version. The decoders are pure functions
//! over a byte slice (plus a small state struct for the
//! multi-packet bitmap sequences); the IRQ path in
//! `crate::i8042_mouse` owns the byte stream and calls into them.
//!
//! Grounding (all read in-session, Linux v6.6 unless noted):
//! * `drivers/input/mouse/alps.c` — `alps_model_data`,
//!   `alps_identify`, `alps_process_packet_v1_v2`,
//!   `alps_decode_pinnacle` / `alps_decode_rushmore` /
//!   `alps_decode_dolphin`, `alps_process_touchpad_packet_v3_v5`,
//!   `alps_process_packet_v4` / `_v6` / `_v7`,
//!   `alps_decode_ss4_v2` / `alps_process_packet_ss4_v2`,
//!   `alps_process_bitmap`, `alps_absolute_mode_v1_v2` / `_v3` /
//!   `_v4` / `_v6`, `alps_hw_init_v3` / `_rushmore_v3` / `_v4` /
//!   `_v7` / `_ss4_v2` / `_dolphin_v1`, `alps_enter_command_mode`,
//!   `alps_command_mode_read_reg` / `alps_command_mode_write_reg`,
//!   `alps_rpt_cmd`, `alps_check_valid_firmware_id`.
//! * `drivers/input/mouse/alps.h` (v6.6) — `ALPS_PROTO_V*`,
//!   `struct alps_fields`, the `SS4_*_V2` coordinate macros,
//!   `V7_PACKET_ID`, `MAX_TOUCHES`.
//! * `Documentation/input/alps.txt` (v3.19 — the last kernel tree
//!   that shipped it; the doc was later removed, v6/v7/v8 formats
//!   live only in `alps.c`) — the per-version packet layouts.
//! * `drivers/input/serio/libps2.c` (`__ps2_command`) and
//!   `drivers/input/mouse/psmouse.h` (`PSMOUSE_CMD_*`) — the
//!   command-word encoding (`send = (cmd >> 12) & 0xf`,
//!   `receive = (cmd >> 8) & 0xf`) behind the nibble tables.
//!
//! Two grounding notes, recorded so a reviewer does not have to
//! rediscover them:
//! * The E6/E7/EC report wire here follows `alps.txt` literally
//!   (`E8-E6-E6-E6-E9`, `E8-E7-E7-E7-E9`, `E8-EC-EC-EC-E9`) and
//!   matches the fixture-pinned wire in PR #1676. The literal
//!   Linux wire differs in one byte: `alps_rpt_cmd` sends
//!   `SETRES` with argument `0x00` (`param[0] = 0` before
//!   `ps2_command`), so the kernel actually puts
//!   `E8-00-E6-E6-E6-E9` on the wire. The firmware keys off the
//!   `SETRES` + 3x `SETSCALE` + `GETINFO` pattern, not the
//!   resolution argument, and the reply semantics are identical
//!   either way; if the literal kernel wire is preferred it is a
//!   one-byte change in [`e6_report`], [`e7_report`] and
//!   [`ec_report`].
//! * V9 (`73-03-C8`) is deliberately NOT implemented: Linux
//!   identifies it only to refuse it (`alps_identify` returns
//!   `-EINVAL`, "Unsupported ALPS V9 touchpad"), and its packet
//!   format is not in `alps.c` v6.6. [`identify`] returns `None`
//!   for it, like Linux refuses it.
//! * Every wire packet's first byte must satisfy the model's
//!   `(b0 & mask0) == byte0` check — Linux `alps_process_byte`
//!   applies it to every packet, including bitmap and IDLE
//!   packets. Bits the coordinate macros ignore still carry
//!   the sync pattern: a v3 bitmap packet starts `0xCF` (bit
//!   `0x40` marks the bitmap, `0x8F` is the sync), a v7 TWO
//!   packet starts `0xC8` (left `0x80` + sync `0x48`), a v7
//!   IDLE packet starts `0x48`, and v8 packets carry `0x18`
//!   in bits 3–4 of byte 0. Fixture vectors that omit the
//!   sync bits decode the right coordinates in isolation but
//!   are refused on the wire — the tests pin the wire forms.
//!
//! Rebase note: this module is self-contained on main
//! (`254a3c424`). PR #1676 (open draft) rewrites `psmouse.rs`
//! with the vendor-probe negotiation (`negotiate_protocol`,
//! `Ps2Transport`, the wheel decoders) and generalises
//! `i8042_mouse.rs` to 4-byte packets. When #1676 lands, this
//! module's [`AlpsTransport`] should be unified with
//! `psmouse::Ps2Transport` (same method shapes), and
//! `negotiate_protocol`'s boolean ALPS check should call
//! [`probe_alps`] so the negotiated model (not just "ALPS")
//! selects the decoder. Nothing else in this file depends on
//! #1676.

/// Set resolution (0xE8) — takes one resolution byte.
pub const CMD_SET_RES: u8 = 0xE8;
/// Get info / status (0xE9) — three reply bytes.
pub const CMD_GET_INFO: u8 = 0xE9;
/// Set scaling 1:1 (0xE6).
pub const CMD_SET_SCALE11: u8 = 0xE6;
/// Set scaling 2:1 (0xE7).
pub const CMD_SET_SCALE21: u8 = 0xE7;
/// Set stream mode (0xEA) — exits ALPS command mode.
pub const CMD_SET_STREAM: u8 = 0xEA;
/// Read data / poll (0xEB).
pub const CMD_POLL: u8 = 0xEB;
/// Reset wrap / command mode (0xEC).
pub const CMD_RESET_WRAP: u8 = 0xEC;
/// Set remote (poll) mode (0xF0).
pub const CMD_SET_POLL: u8 = 0xF0;
/// Get device ID (0xF2) — reply byte(s).
pub const CMD_GET_ID: u8 = 0xF2;
/// Set sample rate (0xF3) — takes one rate byte.
pub const CMD_SET_RATE: u8 = 0xF3;
/// Enable data reporting (0xF4).
pub const CMD_ENABLE: u8 = 0xF4;
/// Disable data reporting (0xF5).
pub const CMD_DISABLE: u8 = 0xF5;
/// Set defaults (0xF6).
pub const CMD_SET_DEFAULTS: u8 = 0xF6;
/// Reset (0xFF) — replies ACK, BAT (0xAA), device-id byte.
pub const CMD_RESET: u8 = 0xFF;

/// ACK byte (0xFA) sent after every accepted command byte.
pub const ACK: u8 = 0xFA;
/// BAT-ok byte (0xAA) sent after a reset.
pub const BAT_OK: u8 = 0xAA;

/// Command-mode register address used by the v3/v4 absolute-mode
/// enable (`alps_absolute_mode_v3` / `_v4` read this register and
/// set bit 1 (v3: `|= 0x06`) or bit 1 (v4: `|= 0x02`)).
pub const REG_ABSOLUTE_MODE: u16 = 0x0004;

// ── Protocol versions ───────────────────────────────────────────────────────

/// ALPS protocol version, mirroring Linux `ALPS_PROTO_V*`
/// (`drivers/input/mouse/alps.h`). `V3Rushmore` is the Rushmore
/// flavour of v3 (same 6-byte packets, different bitmap decode —
/// `alps_decode_rushmore` vs `alps_decode_pinnacle`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AlpsVersion {
    V1,
    V2,
    V3,
    V3Rushmore,
    V4,
    V5,
    V6,
    V7,
    V8,
}

impl AlpsVersion {
    /// Linux `ALPS_PROTO_V*` code (`alps.h`).
    pub const fn code(self) -> u16 {
        match self {
            AlpsVersion::V1 => 0x100,
            AlpsVersion::V2 => 0x200,
            AlpsVersion::V3 => 0x300,
            AlpsVersion::V3Rushmore => 0x310,
            AlpsVersion::V4 => 0x400,
            AlpsVersion::V5 => 0x500,
            AlpsVersion::V6 => 0x600,
            AlpsVersion::V7 => 0x700,
            AlpsVersion::V8 => 0x800,
        }
    }

    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x100 => Some(AlpsVersion::V1),
            0x200 => Some(AlpsVersion::V2),
            0x300 => Some(AlpsVersion::V3),
            0x310 => Some(AlpsVersion::V3Rushmore),
            0x400 => Some(AlpsVersion::V4),
            0x500 => Some(AlpsVersion::V5),
            0x600 => Some(AlpsVersion::V6),
            0x700 => Some(AlpsVersion::V7),
            0x800 => Some(AlpsVersion::V8),
            _ => None,
        }
    }

    /// Movement-packet length in bytes (Linux `alps_init`:
    /// `psmouse->pktsize = proto == V4 ? 8 : 6`).
    pub const fn packet_len(self) -> usize {
        match self {
            AlpsVersion::V4 => 8,
            _ => 6,
        }
    }

    /// Largest possible X position (`alps_set_protocol` defaults
    /// 2000/1400, overridden per version: v1/v2 1023/767,
    /// v6 2047/1535, v7 0xfff/0x7ff).
    pub const fn x_max(self) -> i32 {
        match self {
            AlpsVersion::V1 | AlpsVersion::V2 => 1023,
            AlpsVersion::V6 => 2047,
            AlpsVersion::V7 => 0xfff,
            _ => 2000,
        }
    }

    /// Largest possible Y position (see [`AlpsVersion::x_max`]).
    pub const fn y_max(self) -> i32 {
        match self {
            AlpsVersion::V1 | AlpsVersion::V2 => 767,
            AlpsVersion::V6 => 1535,
            AlpsVersion::V7 => 0x7ff,
            _ => 1400,
        }
    }

    /// Number of X bits in the MT bitmap (`alps_set_protocol`
    /// default 15; Rushmore 16, Dolphin/v5 23).
    pub const fn x_bits(self) -> u32 {
        match self {
            AlpsVersion::V3Rushmore => 16,
            AlpsVersion::V5 => 23,
            _ => 15,
        }
    }

    /// Number of Y bits in the MT bitmap (default 11; Rushmore
    /// and Dolphin/v5 12).
    pub const fn y_bits(self) -> u32 {
        match self {
            AlpsVersion::V3Rushmore | AlpsVersion::V5 => 12,
            _ => 11,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            AlpsVersion::V1 => "v1",
            AlpsVersion::V2 => "v2",
            AlpsVersion::V3 => "v3",
            AlpsVersion::V3Rushmore => "v3-rushmore",
            AlpsVersion::V4 => "v4",
            AlpsVersion::V5 => "v5",
            AlpsVersion::V6 => "v6",
            AlpsVersion::V7 => "v7",
            AlpsVersion::V8 => "v8",
        }
    }
}

// ── Model flags ─────────────────────────────────────────────────────────────

/// Touchpad has a trackstick (DualPoint).
pub const FLAG_DUALPOINT: u16 = 0x02;
/// Device has a pass-through port.
pub const FLAG_PASS: u16 = 0x04;
/// Hardware wheel present.
pub const FLAG_WHEEL: u16 = 0x08;
/// Front & back buttons present (variant 1).
pub const FLAG_FW_BK_1: u16 = 0x10;
/// Front & back buttons present (variant 2).
pub const FLAG_FW_BK_2: u16 = 0x20;
/// 4 direction buttons present.
pub const FLAG_FOUR_BUTTONS: u16 = 0x40;
/// 3-byte PS/2 packet interleaved with the 6-byte ALPS packet.
pub const FLAG_PS2_INTERLEAVED: u16 = 0x80;
/// Separate stick button bits (DMI-selected on some Dell models;
/// set by the caller, never by the model table).
pub const FLAG_STICK_BITS: u16 = 0x100;
/// Device is a clickpad (buttonpad).
pub const FLAG_BUTTONPAD: u16 = 0x200;
/// Device can report trackpoint pressure.
pub const FLAG_DUALPOINT_WITH_PRESSURE: u16 = 0x400;

// ── Model table ─────────────────────────────────────────────────────────────

/// One row of Linux `alps_model_data` (`alps.c`): the E7
/// signature, the protocol it selects, the first-byte check
/// (`(byte0 & mask0) == byte0` — `alps_is_valid_first_byte`),
/// and the capability flags. `name` is the comment Linux
/// carries on the row (machine model), kept so a probed pad can
/// be identified in logs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AlpsModel {
    pub signature: [u8; 3],
    pub version: AlpsVersion,
    pub byte0: u8,
    pub mask0: u8,
    pub flags: u16,
    pub name: &'static str,
}

impl AlpsModel {
    pub const fn protocol(self) -> AlpsProtocol {
        AlpsProtocol {
            version: self.version,
            byte0: self.byte0,
            mask0: self.mask0,
            flags: self.flags,
        }
    }
}

/// The negotiated protocol for a detected pad: version, the
/// first-byte check, and the capability flags. This is Linux
/// `struct alps_protocol_info` (`version`, `byte0`, `mask0`,
/// `flags`) without the table's signature/name.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AlpsProtocol {
    pub version: AlpsVersion,
    pub byte0: u8,
    pub mask0: u8,
    pub flags: u16,
}

impl AlpsProtocol {
    /// First-byte check, verbatim from Linux
    /// `alps_is_valid_first_byte`.
    pub const fn is_valid_first_byte(self, b0: u8) -> bool {
        (b0 & self.mask0) == self.byte0
    }

    pub const fn packet_len(self) -> usize {
        self.version.packet_len()
    }
}

/// Linux `alps_model_data` (`drivers/input/mouse/alps.c`,
/// v6.6), verbatim — same signatures, same byte0/mask0, same
/// flags, same order. The first entry carries Linux's own
/// "XXX This entry is suspicious" comment: its first byte has a
/// zero low nibble (what a normal mouse reports) and `0x0e`
/// is not a valid PS/2 value — it is kept because Linux keeps
/// it, and removing it would change identification behaviour.
pub static ALPS_MODEL_TABLE: &[AlpsModel] = &[
    AlpsModel {
        signature: [0x20, 0x02, 0x0e],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: FLAG_PASS | FLAG_DUALPOINT,
        name: "suspicious entry (Linux XXX comment)",
    },
    AlpsModel {
        signature: [0x22, 0x02, 0x0a],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: FLAG_PASS | FLAG_DUALPOINT,
        name: "unknown",
    },
    AlpsModel {
        signature: [0x22, 0x02, 0x14],
        version: AlpsVersion::V2,
        byte0: 0xff,
        mask0: 0xff,
        flags: FLAG_PASS | FLAG_DUALPOINT,
        name: "Dell Latitude D600",
    },
    AlpsModel {
        signature: [0x32, 0x02, 0x14],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: FLAG_PASS | FLAG_DUALPOINT,
        name: "Toshiba Satellite Pro M10",
    },
    AlpsModel {
        signature: [0x33, 0x02, 0x0a],
        version: AlpsVersion::V1,
        byte0: 0x88,
        mask0: 0xf8,
        flags: 0,
        name: "UMAX-530T",
    },
    AlpsModel {
        signature: [0x52, 0x01, 0x14],
        version: AlpsVersion::V2,
        byte0: 0xff,
        mask0: 0xff,
        flags: FLAG_PASS | FLAG_DUALPOINT | FLAG_PS2_INTERLEAVED,
        name: "Toshiba Tecra A11-11L",
    },
    AlpsModel {
        signature: [0x53, 0x02, 0x0a],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: 0,
        name: "unknown",
    },
    AlpsModel {
        signature: [0x53, 0x02, 0x14],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: 0,
        name: "unknown",
    },
    AlpsModel {
        signature: [0x60, 0x03, 0xc8],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: 0,
        name: "HP ze1115",
    },
    AlpsModel {
        signature: [0x62, 0x02, 0x14],
        version: AlpsVersion::V2,
        byte0: 0xcf,
        mask0: 0xcf,
        flags: FLAG_PASS | FLAG_DUALPOINT | FLAG_PS2_INTERLEAVED,
        name: "Dell Latitude E5500, E6400, E6500, Precision M4400",
    },
    AlpsModel {
        signature: [0x63, 0x02, 0x0a],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: 0,
        name: "unknown",
    },
    AlpsModel {
        signature: [0x63, 0x02, 0x14],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: 0,
        name: "unknown",
    },
    AlpsModel {
        signature: [0x63, 0x02, 0x28],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: FLAG_FW_BK_2,
        name: "Fujitsu Siemens S6010",
    },
    AlpsModel {
        signature: [0x63, 0x02, 0x3c],
        version: AlpsVersion::V2,
        byte0: 0x8f,
        mask0: 0x8f,
        flags: FLAG_WHEEL,
        name: "Toshiba Satellite S2400-103",
    },
    AlpsModel {
        signature: [0x63, 0x02, 0x50],
        version: AlpsVersion::V2,
        byte0: 0xef,
        mask0: 0xef,
        flags: FLAG_FW_BK_1,
        name: "NEC Versa L320",
    },
    AlpsModel {
        signature: [0x63, 0x02, 0x64],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: 0,
        name: "unknown",
    },
    AlpsModel {
        signature: [0x63, 0x03, 0xc8],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: FLAG_PASS | FLAG_DUALPOINT,
        name: "Dell Latitude D800",
    },
    AlpsModel {
        signature: [0x73, 0x00, 0x0a],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: FLAG_DUALPOINT,
        name: "ThinkPad R61 8918-5QG",
    },
    AlpsModel {
        signature: [0x73, 0x00, 0x14],
        version: AlpsVersion::V6,
        byte0: 0xff,
        mask0: 0xff,
        flags: FLAG_DUALPOINT,
        name: "Dell XT2",
    },
    AlpsModel {
        signature: [0x73, 0x02, 0x0a],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: 0,
        name: "unknown",
    },
    AlpsModel {
        signature: [0x73, 0x02, 0x14],
        version: AlpsVersion::V2,
        byte0: 0xf8,
        mask0: 0xf8,
        flags: FLAG_FW_BK_2,
        name: "Ahtec Laptop",
    },
    AlpsModel {
        signature: [0x73, 0x02, 0x50],
        version: AlpsVersion::V2,
        byte0: 0xcf,
        mask0: 0xcf,
        flags: FLAG_FOUR_BUTTONS,
        name: "Dell Vostro 1400",
    },
];

/// The non-table protocol infos Linux keeps beside the table
/// (`alps_v3_protocol_data`, `alps_v3_rushmore_data`,
/// `alps_v4_protocol_data`, `alps_v5_protocol_data`,
/// `alps_v7_protocol_data`, `alps_v8_protocol_data`): the
/// version, byte0/mask0 and flags selected by the E7/EC
/// fallback rules in [`identify`] when no table row matches.
pub const ALPS_V3_PROTOCOL: AlpsProtocol = AlpsProtocol {
    version: AlpsVersion::V3,
    byte0: 0x8f,
    mask0: 0x8f,
    flags: FLAG_DUALPOINT | FLAG_DUALPOINT_WITH_PRESSURE,
};
pub const ALPS_V3_RUSHMORE_PROTOCOL: AlpsProtocol = AlpsProtocol {
    version: AlpsVersion::V3Rushmore,
    byte0: 0x8f,
    mask0: 0x8f,
    flags: FLAG_DUALPOINT | FLAG_DUALPOINT_WITH_PRESSURE,
};
pub const ALPS_V4_PROTOCOL: AlpsProtocol = AlpsProtocol {
    version: AlpsVersion::V4,
    byte0: 0x8f,
    mask0: 0x8f,
    flags: 0,
};
pub const ALPS_V5_PROTOCOL: AlpsProtocol = AlpsProtocol {
    version: AlpsVersion::V5,
    byte0: 0xc8,
    mask0: 0xd8,
    flags: 0,
};
pub const ALPS_V7_PROTOCOL: AlpsProtocol = AlpsProtocol {
    version: AlpsVersion::V7,
    byte0: 0x48,
    mask0: 0x48,
    flags: FLAG_DUALPOINT | FLAG_DUALPOINT_WITH_PRESSURE,
};
pub const ALPS_V8_PROTOCOL: AlpsProtocol = AlpsProtocol {
    version: AlpsVersion::V8,
    byte0: 0x18,
    mask0: 0x18,
    flags: 0,
};

/// Look a model up by its E7 signature (Linux
/// `alps_match_table` — a byte-exact table match; the EC
/// report plays no part in the table lookup).
pub fn lookup_model(e7: &[u8; 3]) -> Option<&'static AlpsModel> {
    ALPS_MODEL_TABLE.iter().find(|m| m.signature == *e7)
}

/// Validate an EC (command-mode) report (Linux
/// `alps_check_valid_firmware_id`): `0x73...` is valid, as is
/// `0x88` with second byte `0x07`, `0x08`, or a `0xb0`/`0xc0`
/// high nibble.
pub fn valid_firmware_id(ec: &[u8; 3]) -> bool {
    if ec[0] == 0x73 {
        return true;
    }
    ec[0] == 0x88
        && (ec[1] == 0x07 || ec[1] == 0x08 || (ec[1] & 0xf0) == 0xb0 || (ec[1] & 0xf0) == 0xc0)
}

/// Validate an E6 report reply (Linux `alps_identify`):
/// `00-00-0A` or `00-00-64` with no buttons pressed; bits 0–2
/// of the first byte are 1 when buttons are pressed, so only
/// the top five bits must be zero.
pub fn e6_report_valid(resp: &[u8; 3]) -> bool {
    resp[0] & 0xf8 == 0 && resp[1] == 0x00 && (resp[2] == 0x0a || resp[2] == 0x64)
}

/// SS4-Plus device check (Linux `IS_SS4PLUS_DEV`): the v8
/// (SS4v2) decode uses different multi-finger macros for the
/// `73-03-28` device id.
pub fn is_ss4plus_device(dev_id: &[u8; 3]) -> bool {
    dev_id[0] == 0x73 && dev_id[1] == 0x03 && dev_id[2] == 0x28
}

/// Identify an ALPS pad from its E7 + EC reports — Linux
/// `alps_identify`'s selection, verbatim and in order: exact
/// table match first, then the E7/EC fallback chain. Returns
/// `None` when the reports do not identify an ALPS pad (Linux
/// `-EINVAL`, "Likely not an ALPS touchpad") and for V9
/// (`73-03-C8`, which Linux identifies only to refuse).
pub fn identify(e7: &[u8; 3], ec: &[u8; 3]) -> Option<AlpsProtocol> {
    if let Some(model) = lookup_model(e7) {
        return Some(model.protocol());
    }
    if e7[0] == 0x73 && e7[1] == 0x02 && e7[2] == 0x64 && ec[2] == 0x8a {
        Some(ALPS_V4_PROTOCOL)
    } else if e7[0] == 0x73
        && e7[1] == 0x03
        && e7[2] == 0x50
        && ec[0] == 0x73
        && (ec[1] == 0x01 || ec[1] == 0x02)
    {
        Some(ALPS_V5_PROTOCOL)
    } else if ec[0] == 0x88 && ((ec[1] & 0xf0) == 0xb0 || (ec[1] & 0xf0) == 0xc0) {
        Some(ALPS_V7_PROTOCOL)
    } else if ec[0] == 0x88 && ec[1] == 0x08 {
        Some(ALPS_V3_RUSHMORE_PROTOCOL)
    } else if ec[0] == 0x88 && ec[1] == 0x07 && ec[2] >= 0x90 && ec[2] <= 0x9d {
        Some(ALPS_V3_PROTOCOL)
    } else if e7[0] == 0x73 && e7[1] == 0x03 && (e7[2] == 0x14 || e7[2] == 0x28) {
        Some(ALPS_V8_PROTOCOL)
    } else {
        None
    }
}

// ── Transport + identification reports ──────────────────────────────────────

/// Byte transport to the PS/2 device. This mirrors the shape of
/// `psmouse::Ps2Transport` from PR #1676 (same `send` / `recv` /
/// `send_param` / `recv_exact` / `reset` contract) so the two can
/// be unified on rebase; it is defined here so this module stays
/// self-contained on main, where `psmouse.rs` is still the old
/// stub. The real implementation lives in `i8042_mouse`
/// (0xD4-prefixed port I/O); tests use a fake that records sends
/// and replays canned replies, so the knock sequences are
/// fixture-pinned byte-for-byte instead of trusted from the impl.
pub trait AlpsTransport {
    /// Send one byte to the device. Returns `true` if the device
    /// ACKed (`0xFA`). Detection ignores ACK failures (Linux
    /// ignores the `SET RATE` results too — only the reply bytes
    /// decide).
    fn send(&mut self, byte: u8) -> bool;

    /// Read one reply byte, if one arrives within the transport's
    /// timeout.
    fn recv(&mut self) -> Option<u8>;

    /// Send a command byte followed by one parameter byte.
    fn send_param(&mut self, cmd: u8, param: u8) -> bool {
        self.send(cmd) && self.send(param)
    }

    /// Read exactly `buf.len()` reply bytes.
    fn recv_exact(&mut self, buf: &mut [u8]) -> bool {
        for b in buf.iter_mut() {
            match self.recv() {
                Some(v) => *b = v,
                None => return false,
            }
        }
        true
    }

    /// Full device reset: `0xFF`, expect ACK (consumed by
    /// `send`), then BAT (`0xAA`), then the device-id byte.
    /// Restores power-on defaults (3-byte packets, rate 100,
    /// reporting disabled).
    fn reset(&mut self) -> bool {
        if !self.send(CMD_RESET) {
            return false;
        }
        if self.recv() != Some(BAT_OK) {
            return false;
        }
        self.recv().is_some()
    }
}

/// One `alps_rpt_cmd` report (Linux `alps.c`): `SETRES(arg)`,
/// then the repeated command three times, then `GETINFO` for the
/// 3 reply bytes. `arg` is the `SETRES` argument byte — per the
/// module docs this follows `alps.txt` (`0xE6` / `0xE7` /
/// `0xEC`), not the literal kernel `0x00`.
fn report_cmd<T: AlpsTransport>(t: &mut T, arg: u8, repeated: u8) -> Option<[u8; 3]> {
    let _ = t.send_param(CMD_SET_RES, arg);
    let _ = t.send(repeated);
    let _ = t.send(repeated);
    if !t.send(CMD_GET_INFO) {
        return None;
    }
    let mut resp = [0u8; 3];
    if !t.recv_exact(&mut resp) {
        return None;
    }
    Some(resp)
}

/// ALPS "E6 report" (`alps.txt`): wire `E8-E6-E6-E6-E9`, i.e.
/// `SETRES(0xE6)`, `SETSCALE11`, `SETSCALE11`, `GETINFO`. An
/// ALPS pad answers `00-00-0A` or `00-00-64` (bits 0–2 of the
/// first byte are 1 when buttons are pressed).
pub fn e6_report<T: AlpsTransport>(t: &mut T) -> Option<[u8; 3]> {
    report_cmd(t, 0xE6, CMD_SET_SCALE11)
}

/// ALPS "E7 report" (`alps.txt`): wire `E8-E7-E7-E7-E9`, i.e.
/// `SETRES(0xE7)`, `SETSCALE21`, `SETSCALE21`, `GETINFO`. The
/// reply is the model signature; v3/v4 pads answer `73-02-64`,
/// newer pads `73-03-50` / `73-03-0A` — all start with `0x73`.
pub fn e7_report<T: AlpsTransport>(t: &mut T) -> Option<[u8; 3]> {
    report_cmd(t, 0xE7, CMD_SET_SCALE21)
}

/// ALPS "EC report" (Linux `alps_identify`): wire
/// `E8-EC-EC-EC-E9`, i.e. `SETRES(0xEC)`, `RESET_WRAP`
/// (`0xEC`) three times, `GETINFO`. The reply is the firmware
/// id (`88-07` + byte for v3/v4, `88-08` / `88-b*` / `88-c*`
/// for the newer pads, `73...` for v5) — see
/// [`valid_firmware_id`] and [`identify`].
pub fn ec_report<T: AlpsTransport>(t: &mut T) -> Option<[u8; 3]> {
    report_cmd(t, 0xEC, CMD_RESET_WRAP)
}

/// Identify an ALPS pad over the wire — Linux `alps_identify`:
/// the E6 report must validate, then the E7 + EC reports select
/// the protocol via [`identify`]. Command mode is exited
/// afterwards (`EA`, `alps_exit_command_mode` — the EC report
/// leaves the device in command mode). Returns `None` when the
/// device does not answer like an ALPS pad.
pub fn probe_alps<T: AlpsTransport>(t: &mut T) -> Option<AlpsProtocol> {
    let e6 = e6_report(t)?;
    if !e6_report_valid(&e6) {
        return None;
    }
    let e7 = e7_report(t)?;
    let ec = ec_report(t)?;
    let _ = exit_command_mode(t);
    identify(&e7, &ec)
}

/// Enter ALPS command mode (Linux `alps_enter_command_mode`):
/// `EC-EC-EC-E9` via `alps_rpt_cmd` with no init command, and
/// the reply must be a valid firmware id
/// ([`valid_firmware_id`]). Returns the 3 reply bytes.
pub fn enter_command_mode<T: AlpsTransport>(t: &mut T) -> Option<[u8; 3]> {
    let _ = t.send(CMD_RESET_WRAP);
    let _ = t.send(CMD_RESET_WRAP);
    let _ = t.send(CMD_RESET_WRAP);
    if !t.send(CMD_GET_INFO) {
        return None;
    }
    let mut resp = [0u8; 3];
    if !t.recv_exact(&mut resp) {
        return None;
    }
    if !valid_firmware_id(&resp) {
        return None;
    }
    Some(resp)
}

/// Exit ALPS command mode (Linux `alps_exit_command_mode`):
/// `SETSTREAM` (0xEA).
pub fn exit_command_mode<T: AlpsTransport>(t: &mut T) -> bool {
    t.send(CMD_SET_STREAM)
}

// ── Command-mode nibble machinery ───────────────────────────────────────────

/// One nibble encoding (Linux `struct alps_nibble_commands`):
/// the PS/2 command to send for this nibble, the parameter byte
/// to send with it (`None` = no parameter byte), and how many
/// reply bytes the command returns (consumed and discarded —
/// only nibble `0xa` in the v3/v4 tables and `0x8`/`0x9` in the
/// v6 table expect replies: `GETID` / `GETINFO`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NibbleCmd {
    pub command: u8,
    pub data: Option<u8>,
    pub replies: u8,
}

const fn nibble(command: u8, data: Option<u8>, replies: u8) -> NibbleCmd {
    NibbleCmd {
        command,
        data,
        replies,
    }
}

/// Nibble commands for v3, v5, v7 and v8 (Linux
/// `alps_v3_nibble_commands`). Nibble `0xa` is
/// `ALPS_CMD_NIBBLE_10` (`0x01f2`): `GETID` with one reply byte.
pub static V3_NIBBLE_COMMANDS: [NibbleCmd; 16] = [
    nibble(CMD_SET_POLL, None, 0),       // 0
    nibble(CMD_SET_DEFAULTS, None, 0),   // 1
    nibble(CMD_SET_SCALE21, None, 0),    // 2
    nibble(CMD_SET_RATE, Some(0x0a), 0), // 3
    nibble(CMD_SET_RATE, Some(0x14), 0), // 4
    nibble(CMD_SET_RATE, Some(0x28), 0), // 5
    nibble(CMD_SET_RATE, Some(0x3c), 0), // 6
    nibble(CMD_SET_RATE, Some(0x50), 0), // 7
    nibble(CMD_SET_RATE, Some(0x64), 0), // 8
    nibble(CMD_SET_RATE, Some(0xc8), 0), // 9
    nibble(CMD_GET_ID, None, 1),         // a
    nibble(CMD_SET_RES, Some(0x00), 0),  // b
    nibble(CMD_SET_RES, Some(0x01), 0),  // c
    nibble(CMD_SET_RES, Some(0x02), 0),  // d
    nibble(CMD_SET_RES, Some(0x03), 0),  // e
    nibble(CMD_SET_SCALE11, None, 0),    // f
];

/// Nibble commands for v4 (Linux `alps_v4_nibble_commands`):
/// identical to the v3 table except nibble `0` is `ENABLE`
/// instead of `SETPOLL`.
pub static V4_NIBBLE_COMMANDS: [NibbleCmd; 16] = [
    nibble(CMD_ENABLE, None, 0),         // 0
    nibble(CMD_SET_DEFAULTS, None, 0),   // 1
    nibble(CMD_SET_SCALE21, None, 0),    // 2
    nibble(CMD_SET_RATE, Some(0x0a), 0), // 3
    nibble(CMD_SET_RATE, Some(0x14), 0), // 4
    nibble(CMD_SET_RATE, Some(0x28), 0), // 5
    nibble(CMD_SET_RATE, Some(0x3c), 0), // 6
    nibble(CMD_SET_RATE, Some(0x50), 0), // 7
    nibble(CMD_SET_RATE, Some(0x64), 0), // 8
    nibble(CMD_SET_RATE, Some(0xc8), 0), // 9
    nibble(CMD_GET_ID, None, 1),         // a
    nibble(CMD_SET_RES, Some(0x00), 0),  // b
    nibble(CMD_SET_RES, Some(0x01), 0),  // c
    nibble(CMD_SET_RES, Some(0x02), 0),  // d
    nibble(CMD_SET_RES, Some(0x03), 0),  // e
    nibble(CMD_SET_SCALE11, None, 0),    // f
];

/// Nibble commands for v6 (Linux `alps_v6_nibble_commands`).
/// Nibble `0x8` is `GETID` (`PSMOUSE_CMD_GETID = 0x02f2`, two
/// reply bytes) and `0x9` is `GETINFO` (`0x03e9`, three reply
/// bytes).
pub static V6_NIBBLE_COMMANDS: [NibbleCmd; 16] = [
    nibble(CMD_ENABLE, None, 0),         // 0
    nibble(CMD_SET_RATE, Some(0x0a), 0), // 1
    nibble(CMD_SET_RATE, Some(0x14), 0), // 2
    nibble(CMD_SET_RATE, Some(0x28), 0), // 3
    nibble(CMD_SET_RATE, Some(0x3c), 0), // 4
    nibble(CMD_SET_RATE, Some(0x50), 0), // 5
    nibble(CMD_SET_RATE, Some(0x64), 0), // 6
    nibble(CMD_SET_RATE, Some(0xc8), 0), // 7
    nibble(CMD_GET_ID, None, 2),         // 8
    nibble(CMD_GET_INFO, None, 3),       // 9
    nibble(CMD_SET_RES, Some(0x00), 0),  // a
    nibble(CMD_SET_RES, Some(0x01), 0),  // b
    nibble(CMD_SET_RES, Some(0x02), 0),  // c
    nibble(CMD_SET_RES, Some(0x03), 0),  // d
    nibble(CMD_SET_SCALE21, None, 0),    // e
    nibble(CMD_SET_SCALE11, None, 0),    // f
];

/// The nibble table and address command for a protocol version
/// (Linux `alps_set_protocol`: v3/v5/v7/v8 use the v3 table
/// with `RESET_WRAP` (`0xEC`) as the address command; v4 uses
/// the v4 table with `DISABLE` (`0xF5`)). v1/v2/v6 do not use
/// command-mode register access (`None`).
pub fn nibble_commands(version: AlpsVersion) -> Option<(&'static [NibbleCmd; 16], u8)> {
    match version {
        AlpsVersion::V3
        | AlpsVersion::V3Rushmore
        | AlpsVersion::V5
        | AlpsVersion::V7
        | AlpsVersion::V8 => Some((&V3_NIBBLE_COMMANDS, CMD_RESET_WRAP)),
        AlpsVersion::V4 => Some((&V4_NIBBLE_COMMANDS, CMD_DISABLE)),
        _ => None,
    }
}

/// Send one nibble in command mode (Linux
/// `alps_command_mode_send_nibble`): the table's command (+
/// data byte), then discard the command's reply bytes.
pub fn send_nibble<T: AlpsTransport>(t: &mut T, table: &[NibbleCmd; 16], nibble_value: u8) -> bool {
    let cmd = table[(nibble_value & 0x0f) as usize];
    let ok = match cmd.data {
        Some(data) => t.send_param(cmd.command, data),
        None => t.send(cmd.command),
    };
    if !ok {
        return false;
    }
    for _ in 0..cmd.replies {
        if t.recv().is_none() {
            return false;
        }
    }
    true
}

/// Set the command-mode register address (Linux
/// `alps_command_mode_set_addr`): the address command, then the
/// four nibbles of the 16-bit address, most significant first.
pub fn set_addr<T: AlpsTransport>(
    t: &mut T,
    table: &[NibbleCmd; 16],
    addr_command: u8,
    addr: u16,
) -> bool {
    if !t.send(addr_command) {
        return false;
    }
    for shift in [12, 8, 4, 0] {
        if !send_nibble(t, table, ((addr >> shift) & 0xf) as u8) {
            return false;
        }
    }
    true
}

/// Read a command-mode register (Linux
/// `alps_command_mode_read_reg`): set the address, then
/// `GETINFO`; the first two reply bytes echo the address being
/// read and the third is the value. Returns `None` when the
/// echo does not match.
pub fn read_reg<T: AlpsTransport>(
    t: &mut T,
    table: &[NibbleCmd; 16],
    addr_command: u8,
    addr: u16,
) -> Option<u8> {
    if !set_addr(t, table, addr_command, addr) {
        return None;
    }
    if !t.send(CMD_GET_INFO) {
        return None;
    }
    let mut resp = [0u8; 3];
    if !t.recv_exact(&mut resp) {
        return None;
    }
    if addr != ((resp[0] as u16) << 8 | resp[1] as u16) {
        return None;
    }
    Some(resp[2])
}

/// Write a command-mode register (Linux
/// `alps_command_mode_write_reg`): set the address, then send
/// the value high nibble first, then low nibble.
pub fn write_reg<T: AlpsTransport>(
    t: &mut T,
    table: &[NibbleCmd; 16],
    addr_command: u8,
    addr: u16,
    value: u8,
) -> bool {
    if !set_addr(t, table, addr_command, addr) {
        return false;
    }
    send_nibble(t, table, (value >> 4) & 0xf) && send_nibble(t, table, value & 0xf)
}

/// Write a value to the register whose address was already set
/// (Linux `__alps_command_mode_write_reg`): value high nibble
/// first, then low nibble.
fn write_current_reg<T: AlpsTransport>(t: &mut T, table: &[NibbleCmd; 16], value: u8) -> bool {
    send_nibble(t, table, (value >> 4) & 0xf) && send_nibble(t, table, value & 0xf)
}

/// Sign-extend the low nibble of `v` to a signed value
/// (-8..=7). Used by [`v3_v7_resolution`]; written as an
/// explicit mask-and-adjust so no shift can overflow.
fn sext_nibble(v: i32) -> i32 {
    let n = v & 0x0f;
    if n & 0x08 != 0 {
        n - 16
    } else {
        n
    }
}

/// Read the v3/v7 sensor resolution registers (Linux
/// `alps_get_v3_v7_resolution`): two register reads at
/// `reg_pitch` and `reg_pitch + 1`, decoded into X/Y
/// resolution (units/mm). Returns `None` when a read fails or
/// the geometry is degenerate.
pub fn v3_v7_resolution<T: AlpsTransport>(
    t: &mut T,
    table: &[NibbleCmd; 16],
    addr_command: u8,
    reg_pitch: u16,
    x_max: i32,
    y_max: i32,
) -> Option<(u32, u32)> {
    let reg = read_reg(t, table, addr_command, reg_pitch)? as i32;
    // Sign-extend the low / high nibbles (Linux: `(s8)(reg << 4) >> 4`
    // and `(s8)reg >> 4`).
    let x_pitch = 50 + 2 * sext_nibble(reg);
    let y_pitch = 36 + 2 * sext_nibble(reg >> 4);
    let reg2 = read_reg(t, table, addr_command, reg_pitch + 1)? as i32;
    let x_electrode = 17 + sext_nibble(reg2);
    let y_electrode = 13 + sext_nibble(reg2 >> 4);
    let x_phys = x_pitch * (x_electrode - 1);
    let y_phys = y_pitch * (y_electrode - 1);
    if x_phys <= 0 || y_phys <= 0 {
        return None;
    }
    Some(((x_max * 10 / x_phys) as u32, (y_max * 10 / y_phys) as u32))
}

// ── Absolute-mode enable ────────────────────────────────────────────────────

/// Enter absolute mode on a v1/v2 pad (Linux
/// `alps_absolute_mode_v1_v2`): the ALPS magic knock — four
/// `DISABLE` (0xF5) before `ENABLE` (0xF4) — then switch the
/// mouse to poll (remote) mode (`SETPOLL`, 0xF0) so motion data
/// will not get in the way.
pub fn absolute_mode_v1_v2<T: AlpsTransport>(t: &mut T) -> bool {
    for _ in 0..4 {
        if !t.send(CMD_DISABLE) {
            return false;
        }
    }
    if !t.send(CMD_ENABLE) {
        return false;
    }
    t.send(CMD_SET_POLL)
}

/// Enter absolute mode on a v3 Pinnacle pad (Linux
/// `alps_absolute_mode_v3`, called with the device already in
/// command mode): read register `0x0004` and set bits 1–2
/// (`|= 0x06`).
fn absolute_mode_v3<T: AlpsTransport>(
    t: &mut T,
    table: &[NibbleCmd; 16],
    addr_command: u8,
) -> bool {
    let reg = match read_reg(t, table, addr_command, REG_ABSOLUTE_MODE) {
        Some(v) => v,
        None => return false,
    };
    write_current_reg(t, table, reg | 0x06)
}

/// Enter absolute mode on a v4 pad (Linux
/// `alps_absolute_mode_v4`, called with the device already in
/// command mode): read register `0x0004` and set bit 1
/// (`|= 0x02`).
fn absolute_mode_v4<T: AlpsTransport>(
    t: &mut T,
    table: &[NibbleCmd; 16],
    addr_command: u8,
) -> bool {
    let reg = match read_reg(t, table, addr_command, REG_ABSOLUTE_MODE) {
        Some(v) => v,
        None => return false,
    };
    write_current_reg(t, table, reg | 0x02)
}

/// Send one 12-bit word in v6 monitor mode (Linux
/// `alps_monitor_mode_send_word`): nibbles least significant
/// first (word `0x0123` goes out as `3, 2, 1`).
fn monitor_mode_send_word<T: AlpsTransport>(t: &mut T, word: u16) -> bool {
    for shift in [0, 4, 8] {
        if !send_nibble(t, &V6_NIBBLE_COMMANDS, ((word >> shift) & 0xf) as u8) {
            return false;
        }
    }
    true
}

/// Write a v6 monitor-mode register (Linux
/// `alps_monitor_mode_write_reg`): `ENABLE`, then the words
/// `0x0A0` (write command), `addr`, `value`, then `DISABLE`.
fn monitor_mode_write_reg<T: AlpsTransport>(t: &mut T, addr: u16, value: u16) -> bool {
    if !t.send(CMD_ENABLE) {
        return false;
    }
    if !monitor_mode_send_word(t, 0x0A0)
        || !monitor_mode_send_word(t, addr)
        || !monitor_mode_send_word(t, value)
    {
        return false;
    }
    t.send(CMD_DISABLE)
}

/// Enter/exit v6 monitor mode (Linux `alps_monitor_mode`):
/// enable is `EC E9 F5 F5 E7 E6 E7 E9`, disable is a lone `EC`.
fn monitor_mode<T: AlpsTransport>(t: &mut T, enable: bool) -> bool {
    if enable {
        for b in [
            CMD_RESET_WRAP,
            CMD_GET_INFO,
            CMD_DISABLE,
            CMD_DISABLE,
            CMD_SET_SCALE21,
            CMD_SET_SCALE11,
            CMD_SET_SCALE21,
            CMD_GET_INFO,
        ] {
            if !t.send(b) {
                return false;
            }
        }
        true
    } else {
        t.send(CMD_RESET_WRAP)
    }
}

/// Enter absolute mode on a v6 pad (Linux
/// `alps_absolute_mode_v6`): enter monitor mode, write register
/// `0x000 = 0x181`, exit monitor mode. (The trackstick
/// passthrough setup in `alps_hw_init_v6` is a separate concern
/// and is not done here.)
pub fn absolute_mode_v6<T: AlpsTransport>(t: &mut T) -> bool {
    if !monitor_mode(t, true) {
        return false;
    }
    let ret = monitor_mode_write_reg(t, 0x000, 0x181);
    if !monitor_mode(t, false) {
        return false;
    }
    ret
}

/// Enter absolute mode on a v5 Dolphin pad (Linux
/// `alps_hw_init_dolphin_v1` — "dolphin v1 as empirically
/// defined by florin9doi"): `SETSTREAM`, `SETRATE 0x64`,
/// `SETRATE 0x28`.
pub fn absolute_mode_v5<T: AlpsTransport>(t: &mut T) -> bool {
    if !t.send(CMD_SET_STREAM) {
        return false;
    }
    if !t.send_param(CMD_SET_RATE, 0x64) {
        return false;
    }
    t.send_param(CMD_SET_RATE, 0x28)
}

/// Enter absolute mode on a v8 (SS4v2) pad (Linux
/// `alps_hw_init_ss4_v2`): `SETSTREAM`, `SETSTREAM`,
/// `SETRATE 0x64`, `SETRATE 0x28`; then exit command mode,
/// enter it again, write register `0x001D = 0x20`, exit command
/// mode, and `ENABLE` data reporting.
pub fn absolute_mode_v8<T: AlpsTransport>(t: &mut T) -> bool {
    if !t.send(CMD_SET_STREAM) || !t.send(CMD_SET_STREAM) {
        return false;
    }
    if !t.send_param(CMD_SET_RATE, 0x64) || !t.send_param(CMD_SET_RATE, 0x28) {
        return false;
    }
    if !exit_command_mode(t) || enter_command_mode(t).is_none() {
        let _ = exit_command_mode(t);
        return false;
    }
    let (table, addr_command) = match nibble_commands(AlpsVersion::V8) {
        Some(v) => v,
        None => return false,
    };
    let ok = write_reg(t, table, addr_command, 0x001D, 0x20);
    let _ = exit_command_mode(t);
    if !ok {
        return false;
    }
    t.send(CMD_ENABLE)
}

/// Enter absolute mode for any version — the per-version
/// enable step, dispatching on [`AlpsVersion`]. The v3/v4/v7
/// paths enter command mode themselves and exit it on every
/// path (Linux `alps_hw_init_v3` / `_v4` / `_v7` exit command
/// mode in their `error:` path too — leaving a pad in command
/// mode renders it unusable until reboot). The v3 Pinnacle
/// path additionally performs the sensitivity register writes
/// from `alps_hw_init_v3` (`0x0006` / `0x0007 |= 0x01`,
/// `0x0144 → 0x04`, `0x0159 → 0x03`, `0x0163 = 0x03`,
/// `0x0162 = 0x04`) and the Rushmore path the full
/// `alps_hw_init_rushmore_v3` sequence, because those writes
/// are part of the pads' absolute-mode bring-up, not tap
/// configuration. Trackstick setup (`alps_setup_trackstick_v3`,
/// the v6 passthrough extended mode) is NOT done here — it
/// needs the trackstick presence probe and stays a follow-up.
pub fn enter_absolute_mode<T: AlpsTransport>(t: &mut T, version: AlpsVersion) -> bool {
    match version {
        AlpsVersion::V1 | AlpsVersion::V2 => absolute_mode_v1_v2(t),
        AlpsVersion::V3 => enter_absolute_mode_v3_pinnacle(t),
        AlpsVersion::V3Rushmore => enter_absolute_mode_v3_rushmore(t),
        AlpsVersion::V4 => enter_absolute_mode_v4(t),
        AlpsVersion::V5 => absolute_mode_v5(t),
        AlpsVersion::V6 => absolute_mode_v6(t),
        AlpsVersion::V7 => enter_absolute_mode_v7(t),
        AlpsVersion::V8 => absolute_mode_v8(t),
    }
}

/// v3 Pinnacle bring-up (Linux `alps_hw_init_v3` minus the
/// trackstick setup): enter command mode, `absolute_mode_v3`,
/// then the sensitivity registers, exit command mode, and
/// `SETRATE 0x64` + `ENABLE`.
fn enter_absolute_mode_v3_pinnacle<T: AlpsTransport>(t: &mut T) -> bool {
    let (table, addr_command) = match nibble_commands(AlpsVersion::V3) {
        Some(v) => v,
        None => return false,
    };
    if enter_command_mode(t).is_none() || !absolute_mode_v3(t, table, addr_command) {
        let _ = exit_command_mode(t);
        return false;
    }
    let ok = (|| {
        let reg = read_reg(t, table, addr_command, 0x0006)?;
        if !write_current_reg(t, table, reg | 0x01) {
            return None;
        }
        let reg = read_reg(t, table, addr_command, 0x0007)?;
        if !write_current_reg(t, table, reg | 0x01) {
            return None;
        }
        if read_reg(t, table, addr_command, 0x0144).is_none() {
            return None;
        }
        if !write_current_reg(t, table, 0x04) {
            return None;
        }
        if read_reg(t, table, addr_command, 0x0159).is_none() {
            return None;
        }
        if !write_current_reg(t, table, 0x03) {
            return None;
        }
        if !write_reg(t, table, addr_command, 0x0163, 0x03) {
            return None;
        }
        if read_reg(t, table, addr_command, 0x0162).is_none() {
            return None;
        }
        if !write_reg(t, table, addr_command, 0x0162, 0x04) {
            return None;
        }
        Some(())
    })()
    .is_some();
    let _ = exit_command_mode(t);
    if !ok {
        return false;
    }
    if !t.send_param(CMD_SET_RATE, 0x64) {
        return false;
    }
    t.send(CMD_ENABLE)
}

/// v3 Rushmore bring-up (Linux `alps_hw_init_rushmore_v3`
/// minus the trackstick setup): enter command mode, read
/// `0xc2d9`, write `0xc2cb = 0x00`, read the resolution
/// registers at `0xc2da`, clear bit 1 of `0xc2c6`, write
/// `0xc2c9 = 0x64`, set bit 1 of `0xc2c4`, exit command mode,
/// `ENABLE`.
fn enter_absolute_mode_v3_rushmore<T: AlpsTransport>(t: &mut T) -> bool {
    let (table, addr_command) = match nibble_commands(AlpsVersion::V3Rushmore) {
        Some(v) => v,
        None => return false,
    };
    if enter_command_mode(t).is_none() {
        let _ = exit_command_mode(t);
        return false;
    }
    let ok = (|| {
        if read_reg(t, table, addr_command, 0xc2d9).is_none() {
            return None;
        }
        if !write_reg(t, table, addr_command, 0xc2cb, 0x00) {
            return None;
        }
        let _ = v3_v7_resolution(
            t,
            table,
            addr_command,
            0xc2da,
            AlpsVersion::V3Rushmore.x_max(),
            AlpsVersion::V3Rushmore.y_max(),
        )?;
        let reg = read_reg(t, table, addr_command, 0xc2c6)?;
        if !write_current_reg(t, table, reg & 0xfd) {
            return None;
        }
        if !write_reg(t, table, addr_command, 0xc2c9, 0x64) {
            return None;
        }
        let reg = read_reg(t, table, addr_command, 0xc2c4)?;
        if !write_current_reg(t, table, reg | 0x02) {
            return None;
        }
        Some(())
    })()
    .is_some();
    let _ = exit_command_mode(t);
    if !ok {
        return false;
    }
    t.send(CMD_ENABLE)
}

/// v4 bring-up (Linux `alps_hw_init_v4`): enter command mode,
/// `absolute_mode_v4`, the configuration registers
/// (`0x0007 = 0x8c`, `0x0149` / `0x0160` / `0x0168` /
/// `0x014a` / `0x0161 = 0x03`, `0x017f = 0x15`,
/// `0x0151 = 0x01`), exit command mode, then the rate sequence
/// that switches the pad from the 9-byte to the 8-byte packet
/// format (`SETRATE 0xc8`, `0x64`, `0x50`, `GETID`), and
/// `SETRATE 0x64` + `ENABLE`.
fn enter_absolute_mode_v4<T: AlpsTransport>(t: &mut T) -> bool {
    let (table, addr_command) = match nibble_commands(AlpsVersion::V4) {
        Some(v) => v,
        None => return false,
    };
    if enter_command_mode(t).is_none() || !absolute_mode_v4(t, table, addr_command) {
        let _ = exit_command_mode(t);
        return false;
    }
    let ok = (|| {
        for (addr, value) in [
            (0x0007u16, 0x8cu8),
            (0x0149, 0x03),
            (0x0160, 0x03),
            (0x017f, 0x15),
            (0x0151, 0x01),
            (0x0168, 0x03),
            (0x014a, 0x03),
            (0x0161, 0x03),
        ] {
            if !write_reg(t, table, addr_command, addr, value) {
                return None;
            }
        }
        Some(())
    })()
    .is_some();
    let _ = exit_command_mode(t);
    if !ok {
        return false;
    }
    // 9-byte → 8-byte format switch.
    if !t.send_param(CMD_SET_RATE, 0xc8)
        || !t.send_param(CMD_SET_RATE, 0x64)
        || !t.send_param(CMD_SET_RATE, 0x50)
    {
        return false;
    }
    if !t.send(CMD_GET_ID) {
        return false;
    }
    // GETID returns two reply bytes (PSMOUSE_CMD_GETID = 0x02f2).
    if t.recv().is_none() || t.recv().is_none() {
        return false;
    }
    if !t.send_param(CMD_SET_RATE, 0x64) {
        return false;
    }
    t.send(CMD_ENABLE)
}

/// v7 bring-up (Linux `alps_hw_init_v7`): enter command mode,
/// read `0xc2d9`, read the resolution registers at `0xc397`,
/// write `0xc2c9 = 0x64`, set bit 1 of `0xc2c4`, exit command
/// mode, `ENABLE`.
fn enter_absolute_mode_v7<T: AlpsTransport>(t: &mut T) -> bool {
    let (table, addr_command) = match nibble_commands(AlpsVersion::V7) {
        Some(v) => v,
        None => return false,
    };
    if enter_command_mode(t).is_none() {
        let _ = exit_command_mode(t);
        return false;
    }
    let ok = (|| {
        if read_reg(t, table, addr_command, 0xc2d9).is_none() {
            return None;
        }
        let _ = v3_v7_resolution(
            t,
            table,
            addr_command,
            0xc397,
            AlpsVersion::V7.x_max(),
            AlpsVersion::V7.y_max(),
        )?;
        if !write_reg(t, table, addr_command, 0xc2c9, 0x64) {
            return None;
        }
        let reg = read_reg(t, table, addr_command, 0xc2c4)?;
        if !write_current_reg(t, table, reg | 0x02) {
            return None;
        }
        Some(())
    })()
    .is_some();
    let _ = exit_command_mode(t);
    if !ok {
        return false;
    }
    t.send(CMD_ENABLE)
}

// ── Decoded packets ─────────────────────────────────────────────────────────

/// One contact position.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AlpsPoint {
    pub x: i32,
    pub y: i32,
}

/// Decoded form of one ALPS report packet — Linux `struct
/// alps_fields` (`alps.h`), plus the v1/v2 extras Linux reports
/// from the same packet (`gesture` / `finger`, `back` /
/// `forward`, `wheel`, the four direction buttons) and the
/// `BTN_TOUCH` hysteresis state (`touch`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AlpsFields {
    /// Single-touch position.
    pub st: AlpsPoint,
    /// Multi-touch positions (slots 0..`fingers`).
    pub mt: [AlpsPoint; 4],
    /// Number of contacts (`mt` slots live).
    pub fingers: u32,
    /// Finger pressure (0..127).
    pub pressure: i32,
    /// X bitmap for semi-MT (v3/v4/v5).
    pub x_map: u32,
    /// Y bitmap for semi-MT (v3/v4/v5).
    pub y_map: u32,
    /// Packet is the first of a multi-packet report.
    pub first_mp: bool,
    /// Packet is part of a multi-packet report.
    pub is_mp: bool,
    /// Touchpad buttons.
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    /// Trackstick buttons (DualPoint pads).
    pub ts_left: bool,
    pub ts_right: bool,
    pub ts_middle: bool,
    /// v1/v2 gesture bit (`ges`, packet[2] bit 0).
    pub gesture: bool,
    /// v1/v2 finger bit (`fin`, packet[2] bit 1).
    pub finger: bool,
    /// v1/v2 front/back buttons (`ALPS_FW_BK_1` / `_2`).
    pub back: bool,
    pub forward: bool,
    /// v1/v2 hardware wheel delta (`ALPS_WHEEL`).
    pub wheel: i32,
    /// v1/v2 four direction buttons (`ALPS_FOUR_BUTTONS`,
    /// `BTN_0..BTN_3` in bits 0..3).
    pub extra_buttons: u8,
    /// Contact down (`BTN_TOUCH` equivalent): v1/v2/v6 use the
    /// 30/25 pressure hysteresis; the other versions report
    /// pressure > 0 (semi-MT) or fingers > 0 (v7/v8).
    pub touch: bool,
}

/// One decoded ALPS packet, ready for the input layer. `dy`
/// on trackstick / bare-PS/2 events is already in screen-down
/// convention (Linux reports `REL_Y = -y` for the stick).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AlpsEvent {
    /// Touchpad position / semi-MT report.
    Touchpad(AlpsFields),
    /// Relative trackstick motion (DualPoint stick packets,
    /// the v1/v2 `z == 127` stick encoding, v6/v7/v8 stick
    /// packets).
    Trackstick {
        dx: i32,
        dy: i32,
        pressure: i32,
        left: bool,
        right: bool,
        middle: bool,
    },
    /// A bare 3-byte PS/2 packet from a device on the
    /// pass-through port (v2 interleaved frames, or the
    /// `ALPS_PASS` bare-packet path). Buttons are only
    /// populated on the pass-through path — the interleaved
    /// path reports them as released (Linux calls
    /// `alps_report_bare_ps2_packet` with `report_buttons =
    /// false` there; the stick buttons ride the ALPS packet).
    BarePs2 {
        dx: i32,
        dy: i32,
        left: bool,
        right: bool,
        middle: bool,
    },
}

/// Result of one [`AlpsDecoder::decode`] call. At most two
/// events: the v1/v2 tap-and-drag transition emits a synthetic
/// zero-pressure lift before the real packet, so a decode can
/// legitimately produce two touchpad reports for one packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AlpsDecode {
    pub events: [Option<AlpsEvent>; 2],
}

impl AlpsDecode {
    pub const fn none() -> Self {
        AlpsDecode {
            events: [None, None],
        }
    }

    pub const fn one(event: AlpsEvent) -> Self {
        AlpsDecode {
            events: [Some(event), None],
        }
    }

    pub const fn two(first: AlpsEvent, second: AlpsEvent) -> Self {
        AlpsDecode {
            events: [Some(first), Some(second)],
        }
    }

    /// Number of events in this decode.
    pub fn len(self) -> usize {
        self.events.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// Stateful ALPS packet decoder. Holds the per-version decode
/// state Linux keeps in `struct alps_data`: the multi-packet
/// bitmap assembly (`multi_packet` / `multi_data`), the
/// previous finger bit (`prev_fin`, v1/v2 tap-and-drag), the
/// bitmap second-touch corner (`second_touch`), the
/// trackstick-buttons quirk latch, and the `BTN_TOUCH`
/// hysteresis state.
#[derive(Debug)]
pub struct AlpsDecoder {
    /// Negotiated protocol (version, first-byte check, flags).
    pub protocol: AlpsProtocol,
    /// E7 signature of the pad (selects the SS4-Plus v8
    /// multi-finger macros; `[0; 3]` when unknown).
    pub dev_id: [u8; 3],
    /// Largest possible X position (see [`AlpsVersion::x_max`]).
    pub x_max: i32,
    /// Largest possible Y position.
    pub y_max: i32,
    /// X bitmap width (see [`AlpsVersion::x_bits`]).
    pub x_bits: u32,
    /// Y bitmap width.
    pub y_bits: u32,
    multi_packet: u8,
    multi_data: [u8; 6],
    prev_fin: bool,
    second_touch: i32,
    trackstick_buttons: bool,
    touch: bool,
}

impl AlpsDecoder {
    /// Build a decoder for a negotiated protocol (the
    /// `x_max` / `y_max` / `x_bits` / `y_bits` defaults come
    /// from the version, exactly as `alps_set_protocol` sets
    /// them).
    pub const fn new(protocol: AlpsProtocol) -> Self {
        AlpsDecoder {
            protocol,
            dev_id: [0; 3],
            x_max: protocol.version.x_max(),
            y_max: protocol.version.y_max(),
            x_bits: protocol.version.x_bits(),
            y_bits: protocol.version.y_bits(),
            multi_packet: 0,
            multi_data: [0; 6],
            prev_fin: false,
            second_touch: -1,
            trackstick_buttons: false,
            touch: false,
        }
    }

    /// Build a decoder and record the pad's E7 signature (the
    /// v8 SS4-Plus decode depends on it).
    pub fn with_dev_id(protocol: AlpsProtocol, dev_id: [u8; 3]) -> Self {
        let mut d = Self::new(protocol);
        d.dev_id = dev_id;
        d
    }

    pub fn version(&self) -> AlpsVersion {
        self.protocol.version
    }

    pub fn packet_len(&self) -> usize {
        self.protocol.packet_len()
    }

    /// First-byte check for a packet in flight (Linux
    /// `alps_is_valid_first_byte`).
    pub fn is_valid_first_byte(&self, b0: u8) -> bool {
        self.protocol.is_valid_first_byte(b0)
    }

    /// Per-byte validation while a packet is being collected
    /// (Linux `alps_process_byte`): bytes 2..=pktsize must have
    /// a zero high bit for versions below v5, and the v7/v8
    /// packets have their own per-position checks.
    /// `pktcnt` is the 1-based count of bytes collected so far
    /// (the byte just stored is `packet[pktcnt - 1]`).
    /// Returns `false` when the byte invalidates the packet.
    pub fn is_valid_packet_byte(&self, packet: &[u8], pktcnt: usize) -> bool {
        if pktcnt == 0 || pktcnt > packet.len() {
            return false;
        }
        let v = self.version();
        if matches!(
            v,
            AlpsVersion::V1
                | AlpsVersion::V2
                | AlpsVersion::V3
                | AlpsVersion::V3Rushmore
                | AlpsVersion::V4
        ) && pktcnt >= 2
            && pktcnt <= self.packet_len()
            && (packet[pktcnt - 1] & 0x80) != 0
        {
            return false;
        }
        match v {
            AlpsVersion::V7 => match pktcnt {
                3 => (packet[2] & 0x40) == 0x40,
                4 => (packet[3] & 0x48) == 0x48,
                6 => (packet[5] & 0x40) == 0x00,
                _ => true,
            },
            AlpsVersion::V8 => match pktcnt {
                4 => (packet[3] & 0x08) == 0x08,
                6 => (packet[5] & 0x10) == 0x00,
                _ => true,
            },
            _ => true,
        }
    }

    /// The Rushmore smashed-last-byte case (Linux
    /// `alps_process_byte`): a v3-Rushmore packet whose final
    /// byte has its high bit set (commonly `0xff` from a box
    /// with a closed lid) is consumed but not processed, rather
    /// than reported as bad data.
    pub fn is_rushmore_smashed_last_byte(&self, packet: &[u8]) -> bool {
        self.version() == AlpsVersion::V3Rushmore
            && packet.len() == self.packet_len()
            && (packet[packet.len() - 1] & 0x80) != 0
    }

    /// Decode one complete packet. A packet whose first byte
    /// fails the model's check produces no events (a non-ALPS
    /// packet is rejected here, before any field is decoded —
    /// the Linux `alps_process_byte` first-byte refusal, moved
    /// into the decoder so the IRQ path and the tests share
    /// it). Packets consumed by a multi-packet sequence, stray
    /// bitmap packets, the v7 NEW / UNKNOWN ids and the v3
    /// trackstick end-of-stream marker likewise produce no
    /// events.
    pub fn decode(&mut self, packet: &[u8]) -> AlpsDecode {
        if packet.len() != self.packet_len() || packet.is_empty() {
            return AlpsDecode::none();
        }
        if !self.is_valid_first_byte(packet[0]) {
            return AlpsDecode::none();
        }
        match self.version() {
            AlpsVersion::V1 | AlpsVersion::V2 => self.decode_v1_v2(packet),
            AlpsVersion::V3 | AlpsVersion::V3Rushmore => self.decode_v3(packet),
            AlpsVersion::V4 => self.decode_v4(packet),
            AlpsVersion::V5 => self.decode_v5(packet),
            AlpsVersion::V6 => self.decode_v6(packet),
            AlpsVersion::V7 => self.decode_v7(packet),
            AlpsVersion::V8 => self.decode_v8(packet),
        }
    }

    // ── v1 / v2 ─────────────────────────────────────────────────

    /// v1/v2 6-byte packets (Linux
    /// `alps_process_packet_v1_v2`; layouts in `alps.txt`).
    ///
    /// v1: `x = p1 | ((p0 & 0x07) << 7)`,
    /// `y = p4 | ((p3 & 0x07) << 7)`, `z = p5`,
    /// left `p2 & 0x10`, right `p2 & 0x08`;
    /// v2: `x = p1 | ((p2 & 0x78) << 4)`,
    /// `y = p4 | ((p3 & 0x70) << 3)`, `z = p5`,
    /// left `p3 & 1`, right `p3 & 2`, middle `p3 & 4`.
    /// Both share `ges = p2 & 1`, `fin = p2 & 2`, the
    /// front/back buttons, the wheel, the four direction
    /// buttons, and the DualPoint `z == 127` stick encoding.
    fn decode_v1_v2(&mut self, p: &[u8]) -> AlpsDecode {
        let is_v1 = self.version() == AlpsVersion::V1;
        let mut f = AlpsFields::default();
        if is_v1 {
            f.left = p[2] & 0x10 != 0;
            f.right = p[2] & 0x08 != 0;
            f.middle = false;
            f.st.x = (p[1] as i32) | (((p[0] & 0x07) as i32) << 7);
            f.st.y = (p[4] as i32) | (((p[3] & 0x07) as i32) << 7);
            f.pressure = p[5] as i32;
        } else {
            f.left = p[3] & 1 != 0;
            f.right = p[3] & 2 != 0;
            f.middle = p[3] & 4 != 0;
            f.st.x = (p[1] as i32) | (((p[2] & 0x78) as i32) << 4);
            f.st.y = (p[4] as i32) | (((p[3] & 0x70) as i32) << 3);
            f.pressure = p[5] as i32;
        }

        if self.protocol.flags & FLAG_FW_BK_1 != 0 {
            f.back = p[0] & 0x10 != 0;
            f.forward = p[2] & 4 != 0;
        }
        if self.protocol.flags & FLAG_FW_BK_2 != 0 {
            f.back = p[3] & 4 != 0;
            f.forward = p[2] & 4 != 0;
            // `middle = forward && back`; when both are down
            // they collapse into the middle button.
            f.middle = f.forward && f.back;
            if f.middle {
                f.forward = false;
                f.back = false;
            }
        }

        f.gesture = p[2] & 1 != 0;
        f.finger = p[2] & 2 != 0;

        // DualPoint stick: a v1/v2 packet with z == 127 is
        // trackstick motion, not touchpad data (Linux reports
        // it as relative motion on the second device).
        if self.protocol.flags & FLAG_DUALPOINT != 0 && f.pressure == 127 {
            let x = f.st.x;
            let y = f.st.y;
            let dx = if x > 383 { x - 768 } else { x };
            let dy = -(if y > 255 { y - 512 } else { y });
            return AlpsDecode::one(AlpsEvent::Trackstick {
                dx,
                dy,
                pressure: f.pressure,
                left: f.left,
                right: f.right,
                middle: f.middle,
            });
        }

        // Some models have separate stick button bits.
        if self.protocol.flags & FLAG_STICK_BITS != 0 {
            f.left |= p[0] & 1 != 0;
            f.right |= p[0] & 2 != 0;
            f.middle |= p[0] & 4 != 0;
        }

        // Convert a hardware tap to a reasonable Z value.
        if f.gesture && !f.finger {
            f.pressure = 40;
        }

        // Tap-and-drag: the hardware reports the transition
        // from (!fin && ges) to (fin && ges); translate it to
        // the sequence Z>0, Z==0, Z>0 by emitting a synthetic
        // zero-pressure lift first.
        let synthetic = if f.gesture && f.finger && !self.prev_fin {
            let mut lift = f;
            lift.pressure = 0;
            lift.fingers = 0;
            lift.touch = false;
            lift.mt[0] = lift.st;
            Some(AlpsEvent::Touchpad(lift))
        } else {
            None
        };
        self.prev_fin = f.finger;

        // BTN_TOUCH hysteresis: set above 30, clear below 25.
        if f.pressure > 30 {
            self.touch = true;
        }
        if f.pressure < 25 {
            self.touch = false;
        }
        f.touch = self.touch;

        if f.pressure > 0 {
            f.mt[0] = f.st;
            f.fingers = 1;
        } else {
            f.fingers = 0;
        }

        if self.protocol.flags & FLAG_WHEEL != 0 {
            f.wheel = (((p[2] as i32) << 1) & 0x08) - (((p[0] as i32) >> 4) & 0x07);
        }
        if self.protocol.flags & FLAG_FOUR_BUTTONS != 0 {
            let mut extra = 0u8;
            if p[2] & 4 != 0 {
                extra |= 1;
            }
            if p[0] & 0x10 != 0 {
                extra |= 2;
            }
            if p[3] & 4 != 0 {
                extra |= 4;
            }
            if p[0] & 0x20 != 0 {
                extra |= 8;
            }
            f.extra_buttons = extra;
        }

        match synthetic {
            Some(lift) => AlpsDecode::two(lift, AlpsEvent::Touchpad(f)),
            None => AlpsDecode::one(AlpsEvent::Touchpad(f)),
        }
    }

    /// Decode a 9-byte v2 DualPoint interleaved frame (layout
    /// in `alps.txt`): bytes 0–2 are the ALPS packet head,
    /// bytes 3–5 are a bare 3-byte PS/2 packet from the
    /// trackstick, bytes 6–8 are the ALPS packet tail. The
    /// ALPS packet is reassembled as
    /// `[b0, b1, b2, b6 & 0xf7, b7, b8]` (Linux
    /// `alps_handle_interleaved_ps2`); the PS/2 packet is
    /// reported first, with its buttons ignored (Linux passes
    /// `report_buttons = false` — the stick buttons ride the
    /// ALPS packet). Returns `[BarePs2, Touchpad]`.
    pub fn decode_interleaved_v2(&mut self, frame: &[u8; 9]) -> AlpsDecode {
        let bare = AlpsEvent::BarePs2 {
            dx: Self::ps2_dx(frame[3], frame[4]),
            dy: Self::ps2_dy(frame[3], frame[5]),
            left: false,
            right: false,
            middle: false,
        };
        let mut alps = [0u8; 6];
        alps[0] = frame[0];
        alps[1] = frame[1];
        alps[2] = frame[2];
        alps[3] = frame[6] & 0xf7;
        alps[4] = frame[7];
        alps[5] = frame[8];
        match self.decode_v1_v2(&alps) {
            AlpsDecode {
                events: [Some(touch), _],
            } => AlpsDecode::two(bare, touch),
            _ => AlpsDecode::one(bare),
        }
    }

    /// Standard 3-byte PS/2 motion decode (shared by the bare
    /// pass-through path): sign via byte 0, Y negated to the
    /// screen-down convention.
    pub const fn ps2_dx(b0: u8, b1: u8) -> i32 {
        if b0 & 0x10 != 0 {
            b1 as i32 - 256
        } else {
            b1 as i32
        }
    }

    pub const fn ps2_dy(b0: u8, b2: u8) -> i32 {
        if b0 & 0x20 != 0 {
            -(b2 as i32 - 256)
        } else {
            -(b2 as i32)
        }
    }

    /// Decode a bare 3-byte PS/2 packet from the pass-through
    /// port (Linux `alps_report_bare_ps2_packet` with
    /// `report_buttons = true`).
    pub const fn decode_bare_ps2(packet: &[u8; 3]) -> AlpsEvent {
        AlpsEvent::BarePs2 {
            dx: Self::ps2_dx(packet[0], packet[1]),
            dy: Self::ps2_dy(packet[0], packet[2]),
            left: packet[0] & 1 != 0,
            right: packet[0] & 2 != 0,
            middle: packet[0] & 4 != 0,
        }
    }

    // ── v3 / v5 shared machinery ────────────────────────────────────

    /// v3 button decode (Linux `alps_decode_buttons_v3`):
    /// touchpad buttons in the low nibble of byte 3,
    /// trackstick buttons in bits 4–6.
    fn decode_buttons_v3(f: &mut AlpsFields, p: &[u8]) {
        f.left = p[3] & 0x01 != 0;
        f.right = p[3] & 0x02 != 0;
        f.middle = p[3] & 0x04 != 0;
        f.ts_left = p[3] & 0x10 != 0;
        f.ts_right = p[3] & 0x20 != 0;
        f.ts_middle = p[3] & 0x40 != 0;
    }

    /// Pinnacle (plain v3) field decode (Linux
    /// `alps_decode_pinnacle`).
    fn decode_pinnacle(f: &mut AlpsFields, p: &[u8]) {
        f.first_mp = p[4] & 0x40 != 0;
        f.is_mp = p[0] & 0x40 != 0;
        if f.is_mp {
            f.fingers = (p[5] & 0x3) + 1;
            f.x_map = (((p[4] & 0x7e) as u32) << 8)
                | (((p[1] & 0x7f) as u32) << 2)
                | (((p[0] & 0x30) as u32) >> 4);
            f.y_map = (((p[3] & 0x70) as u32) << 4)
                | (((p[2] & 0x7f) as u32) << 1)
                | ((p[4] & 0x01) as u32);
        } else {
            f.st.x = (((p[1] & 0x7f) as i32) << 4)
                | (((p[4] & 0x30) as i32) >> 2)
                | (((p[0] & 0x30) as i32) >> 4);
            f.st.y = (((p[2] & 0x7f) as i32) << 4) | ((p[4] & 0x0f) as i32);
            f.pressure = (p[5] & 0x7f) as i32;
            Self::decode_buttons_v3(f, p);
        }
    }

    /// Rushmore (v3 flavour) field decode (Linux
    /// `alps_decode_rushmore`). Same single-touch layout as
    /// Pinnacle; the bitmap packet is flagged by byte 5 bit 6
    /// instead of byte 0 bit 6, and the maps gain extra high
    /// bits.
    fn decode_rushmore(f: &mut AlpsFields, p: &[u8]) {
        f.first_mp = p[4] & 0x40 != 0;
        f.is_mp = p[5] & 0x40 != 0;
        if f.is_mp {
            f.fingers = core::cmp::max(p[5] & 0x3, (p[5] >> 2) & 0x3) + 1;
            f.x_map = (((p[5] & 0x10) as u32) << 11)
                | (((p[4] & 0x7e) as u32) << 8)
                | (((p[1] & 0x7f) as u32) << 2)
                | (((p[0] & 0x30) as u32) >> 4);
            f.y_map = (((p[5] & 0x20) as u32) << 6)
                | (((p[3] & 0x70) as u32) << 4)
                | (((p[2] & 0x7f) as u32) << 1)
                | ((p[4] & 0x01) as u32);
        } else {
            f.st.x = (((p[1] & 0x7f) as i32) << 4)
                | (((p[4] & 0x30) as i32) >> 2)
                | (((p[0] & 0x30) as i32) >> 4);
            f.st.y = (((p[2] & 0x7f) as i32) << 4) | ((p[4] & 0x0f) as i32);
            f.pressure = (p[5] & 0x7f) as i32;
            Self::decode_buttons_v3(f, p);
        }
    }

    /// Dolphin (v5) field decode (Linux `alps_decode_dolphin`).
    fn decode_dolphin(&self, f: &mut AlpsFields, p: &[u8]) {
        f.first_mp = p[0] & 0x02 != 0;
        f.is_mp = p[0] & 0x20 != 0;
        if !f.is_mp {
            f.st.x = ((p[1] & 0x7f) as i32) | (((p[4] & 0x0f) as i32) << 7);
            f.st.y = ((p[2] & 0x7f) as i32) | (((p[4] & 0xf0) as i32) << 3);
            f.pressure = if p[0] & 4 != 0 {
                0
            } else {
                (p[5] & 0x7f) as i32
            };
            Self::decode_buttons_v3(f, p);
        } else {
            f.fingers = (((p[0] & 0x6) >> 1) | ((p[0] & 0x10) >> 2)) as u32;
            // 35-bit palm profile: Y in the low `y_bits` bits,
            // X above it (`DOLPHIN_COUNT_PER_ELECTRODE` math).
            let palm: u64 = (p[1] & 0x7f) as u64
                | (((p[2] & 0x7f) as u64) << 7)
                | (((p[4] & 0x7f) as u64) << 14)
                | (((p[5] & 0x7f) as u64) << 21)
                | (((p[3] & 0x07) as u64) << 28)
                | (((p[3] & 0x70) as u64) << 27)
                | (((p[0] & 0x01) as u64) << 34);
            let y_mask = (1u64 << self.y_bits) - 1;
            let x_mask = (1u64 << self.x_bits) - 1;
            f.y_map = (palm & y_mask) as u32;
            f.x_map = ((palm >> self.y_bits) & x_mask) as u32;
        }
    }

    /// One run of set bits in a bitmap (Linux `struct
    /// alps_bitmap_point`).
    fn bitmap_points(map: u32) -> ([(i32, i32); 2], u32) {
        let mut low = (0i32, 0i32);
        let mut high = (0i32, 0i32);
        let mut fingers = 0u32;
        let mut point = 0usize; // 0 = low, 1 = high
        let mut prev_bit = false;
        let mut m = map;
        let mut i = 0i32;
        while m != 0 {
            let bit = m & 1 != 0;
            if bit {
                if !prev_bit {
                    if point == 0 {
                        low = (i, 0);
                    } else {
                        high = (i, 0);
                    }
                    fingers += 1;
                }
                if point == 0 {
                    low.1 += 1;
                } else {
                    high.1 += 1;
                }
            } else if prev_bit {
                point = 1;
            }
            prev_bit = bit;
            m >>= 1;
            i += 1;
        }
        ([low, high], fingers)
    }

    /// Bitmap → contact points (Linux `alps_process_bitmap`).
    /// Returns the number of fingers the bitmaps describe (0
    /// when either bitmap is empty). On success `f.mt[0]` is
    /// the single-touch position and `f.mt[1]` the opposite
    /// corner of the contact bounding box, chosen once per
    /// two-finger sequence (`second_touch`) so it does not
    /// jump while the first touch sits in the middle.
    fn process_bitmap(&mut self, f: &mut AlpsFields) -> u32 {
        if f.x_map == 0 || f.y_map == 0 {
            return 0;
        }
        let ([x_low, x_high], fingers_x) = Self::bitmap_points(f.x_map);
        let ([y_low, y_high], fingers_y) = Self::bitmap_points(f.y_map);
        let fingers = core::cmp::max(fingers_x, fingers_y);
        let (mut x_low, mut x_high) = (x_low, x_high);
        let (mut y_low, mut y_high) = (y_low, y_high);
        // A single contact on an axis is split between the two
        // points (overlapping / adjacent fingers).
        if fingers_x == 1 {
            let i = (x_low.1 - 1) / 2;
            x_low.1 -= i;
            x_high = (x_low.0 + i, core::cmp::max(i, 1));
        }
        if fingers_y == 1 {
            let i = (y_low.1 - 1) / 2;
            y_low.1 -= i;
            y_high = (y_low.0 + i, core::cmp::max(i, 1));
        }
        let x_span = 2 * (self.x_bits as i32 - 1);
        let y_span = 2 * (self.y_bits as i32 - 1);
        let mut corner = [AlpsPoint::default(); 4];
        // top-left
        corner[0].x = (self.x_max * (2 * x_low.0 + x_low.1 - 1)) / x_span;
        corner[0].y = (self.y_max * (2 * y_low.0 + y_low.1 - 1)) / y_span;
        // top-right
        corner[1].x = (self.x_max * (2 * x_high.0 + x_high.1 - 1)) / x_span;
        corner[1].y = corner[0].y;
        // bottom-right
        corner[2].x = corner[1].x;
        corner[2].y = (self.y_max * (2 * y_high.0 + y_high.1 - 1)) / y_span;
        // bottom-left
        corner[3].x = corner[0].x;
        corner[3].y = corner[2].y;
        // The X bitmap order is reversed on v5 touchpads, the Y
        // bitmap order on v3 and v4 touchpads.
        if self.version() == AlpsVersion::V5 {
            for c in corner.iter_mut() {
                c.x = self.x_max - c.x;
            }
        }
        if matches!(
            self.version(),
            AlpsVersion::V3 | AlpsVersion::V3Rushmore | AlpsVersion::V4
        ) {
            for c in corner.iter_mut() {
                c.y = self.y_max - c.y;
            }
        }
        if self.second_touch == -1 {
            let mut closest = i32::MAX;
            let mut best = 0i32;
            for (i, c) in corner.iter().enumerate() {
                let dx = f.st.x - c.x;
                let dy = f.st.y - c.y;
                let dist = dx * dx + dy * dy;
                if dist < closest {
                    closest = dist;
                    best = i as i32;
                }
            }
            // Select the corner opposite the closest one.
            self.second_touch = (best + 2) % 4;
        }
        f.mt[0] = f.st;
        f.mt[1] = corner[self.second_touch as usize];
        fingers
    }

    /// Semi-MT report step shared by v3/v4/v5 (Linux
    /// `alps_report_semi_mt_data`): with fewer than two
    /// fingers the single-touch data is used, the finger count
    /// follows pressure, and the second-touch corner resets.
    fn report_semi_mt(&mut self, f: &mut AlpsFields, fingers: u32) {
        let mut n = fingers;
        if n < 2 {
            f.mt[0] = f.st;
            n = if f.pressure > 0 { 1 } else { 0 };
            self.second_touch = -1;
        }
        f.fingers = n;
        f.touch = f.pressure > 0;
    }

    /// v3/v5 touchpad packet state machine (Linux
    /// `alps_process_touchpad_packet_v3_v5`). `decode_one`
    /// selects the Pinnacle / Rushmore / Dolphin field decode.
    fn decode_touchpad_v3_v5(&mut self, p: &[u8]) -> AlpsDecode {
        let mut f = AlpsFields::default();
        match self.version() {
            AlpsVersion::V3 => Self::decode_pinnacle(&mut f, p),
            AlpsVersion::V3Rushmore => Self::decode_rushmore(&mut f, p),
            _ => self.decode_dolphin(&mut f, p),
        }
        let mut fingers = 0u32;
        if self.multi_packet != 0 {
            if f.is_mp {
                fingers = f.fingers;
                // Bitmap processing uses the saved position
                // packet's coordinates: re-decode it over the
                // bitmap fields (only the ST branch fields are
                // overwritten; the maps survive).
                let saved = self.multi_data;
                match self.version() {
                    AlpsVersion::V3 => Self::decode_pinnacle(&mut f, &saved),
                    AlpsVersion::V3Rushmore => Self::decode_rushmore(&mut f, &saved),
                    _ => self.decode_dolphin(&mut f, &saved),
                }
                if self.process_bitmap(&mut f) == 0 {
                    fingers = 0;
                }
            } else {
                self.multi_packet = 0;
            }
        }
        // A bitmap packet without a preceding position packet
        // is dropped; bit 6 of byte 0 is (almost) never set in
        // position packets and marks suspect data.
        if f.is_mp {
            return AlpsDecode::none();
        }
        if self.multi_packet == 0 && f.first_mp {
            self.multi_packet = 1;
            self.multi_data.copy_from_slice(p);
            return AlpsDecode::none();
        }
        self.multi_packet = 0;
        // A lone packet with x, y but z == 0 in the middle of a
        // stream is a fluke; real releases zero all three.
        if f.st.x != 0 && f.st.y != 0 && f.pressure == 0 {
            return AlpsDecode::none();
        }
        self.report_semi_mt(&mut f, fingers);
        AlpsDecode::one(AlpsEvent::Touchpad(f))
    }

    /// v3 trackstick packet (Linux
    /// `alps_process_trackstick_packet_v3`): flagged by
    /// `packet[5] == 0x3f`. The stick buttons are reported
    /// here only once the quirk latches — until a stick packet
    /// carries a button press, the buttons ride the touchpad
    /// packets instead.
    fn decode_trackstick_v3(&mut self, p: &[u8]) -> AlpsDecode {
        if self.protocol.flags & FLAG_DUALPOINT == 0 {
            return AlpsDecode::none();
        }
        if p[0] & 0x40 == 0 {
            return AlpsDecode::none();
        }
        // End-of-stream marker: three 0x7f bytes.
        if p[1] == 0x7f && p[2] == 0x7f && p[4] == 0x7f {
            return AlpsDecode::none();
        }
        let x = ((((p[0] & 0x20) << 2) | (p[1] & 0x7f)) as u8) as i8;
        let y = ((((p[0] & 0x10) << 3) | (p[2] & 0x7f)) as u8) as i8;
        let z = (p[4] & 0x7f) as i32;
        let left = p[3] & 0x01 != 0;
        let right = p[3] & 0x02 != 0;
        let middle = p[3] & 0x04 != 0;
        if !self.trackstick_buttons && (left || right || middle) {
            self.trackstick_buttons = true;
        }
        let (l, r, m) = if self.trackstick_buttons {
            (left, right, middle)
        } else {
            (false, false, false)
        };
        AlpsDecode::one(AlpsEvent::Trackstick {
            dx: (x as i32) / 8,
            dy: -((y as i32) / 8),
            pressure: z,
            left: l,
            right: r,
            middle: m,
        })
    }

    /// v3 packets (Linux `alps_process_packet_v3`): a
    /// trackstick packet is distinguished by `0x3f` in the
    /// last byte — a value never observed in the last byte of
    /// either touchpad packet type.
    fn decode_v3(&mut self, p: &[u8]) -> AlpsDecode {
        if p[5] == 0x3f {
            self.decode_trackstick_v3(p)
        } else {
            self.decode_touchpad_v3_v5(p)
        }
    }

    /// v5 (Dolphin) packets (Linux `alps_hw_init_dolphin_v1`
    /// selects `alps_process_touchpad_packet_v3_v5` directly —
    /// no trackstick packet type).
    fn decode_v5(&mut self, p: &[u8]) -> AlpsDecode {
        self.decode_touchpad_v3_v5(p)
    }

    // ── v4 ──────────────────────────────────────────────────────

    /// v4 8-byte packets (Linux `alps_process_packet_v4`).
    /// Bytes 6–7 of each packet carry two bytes of a 6-byte
    /// bitmap packet; bit 6 of byte 6 syncs the fragment
    /// position. A complete bitmap arrives every third packet.
    fn decode_v4(&mut self, p: &[u8]) -> AlpsDecode {
        if p[6] & 0x40 != 0 {
            self.multi_packet = 0;
        }
        if self.multi_packet > 2 {
            return AlpsDecode::none();
        }
        let offset = (2 * self.multi_packet) as usize;
        self.multi_data[offset] = p[6];
        self.multi_data[offset + 1] = p[7];
        let mut f = AlpsFields::default();
        f.left = p[4] & 0x01 != 0;
        f.right = p[4] & 0x02 != 0;
        f.st.x = (((p[1] & 0x7f) as i32) << 4)
            | (((p[3] & 0x30) as i32) >> 2)
            | (((p[0] & 0x30) as i32) >> 4);
        f.st.y = (((p[2] & 0x7f) as i32) << 4) | ((p[3] & 0x0f) as i32);
        f.pressure = (p[5] & 0x7f) as i32;
        self.multi_packet += 1;
        let mut fingers = 0u32;
        if self.multi_packet > 2 {
            self.multi_packet = 0;
            let md = self.multi_data;
            f.x_map = (((md[2] & 0x1f) as u32) << 10)
                | (((md[3] & 0x60) as u32) << 3)
                | (((md[0] & 0x3f) as u32) << 2)
                | (((md[1] & 0x60) as u32) >> 5);
            f.y_map = (((md[5] & 0x01) as u32) << 10)
                | (((md[3] & 0x1f) as u32) << 5)
                | ((md[1] & 0x1f) as u32);
            fingers = self.process_bitmap(&mut f);
        }
        self.report_semi_mt(&mut f, fingers);
        AlpsDecode::one(AlpsEvent::Touchpad(f))
    }

    // ── v6 ──────────────────────────────────────────────────────

    /// v6 6-byte packets (Linux `alps_process_packet_v6`).
    /// Byte 5 `0x7F` marks a trackpoint packet; anything else
    /// is a touchpad packet. The touchpad has no middle button
    /// (byte 3 bit 2 is masked out before decoding buttons).
    fn decode_v6(&mut self, p: &[u8]) -> AlpsDecode {
        if p[5] == 0x7F {
            if self.protocol.flags & FLAG_DUALPOINT == 0 {
                return AlpsDecode::none();
            }
            let x = (p[1] as i32) | (((p[3] & 0x20) as i32) << 2);
            let y = (p[2] as i32) | (((p[3] & 0x40) as i32) << 1);
            let z = p[4] as i32;
            // A lifted finger reports 0x7F on all three axes;
            // report it as zero motion, not a jump.
            let (x, y, z) = if x == 0x7F && y == 0x7F && z == 0x7F {
                (0, 0, 0)
            } else {
                (x, y, z)
            };
            // The trackpoint is too fast at full scale; Linux
            // divides by 4.
            return AlpsDecode::one(AlpsEvent::Trackstick {
                dx: ((x as u8) as i8 as i32) / 4,
                dy: -(((y as u8) as i8 as i32) / 4),
                pressure: z,
                left: p[3] & 1 != 0,
                right: p[3] & 2 != 0,
                middle: p[3] & 4 != 0,
            });
        }
        let mut f = AlpsFields::default();
        f.st.x = (p[1] as i32) | (((p[3] & 0x78) as i32) << 4);
        f.st.y = (p[2] as i32) | (((p[4] & 0x78) as i32) << 4);
        f.pressure = p[5] as i32;
        if f.pressure > 30 {
            self.touch = true;
        }
        if f.pressure < 25 {
            self.touch = false;
        }
        f.touch = self.touch;
        if f.pressure > 0 {
            f.mt[0] = f.st;
            f.fingers = 1;
        }
        let b3 = p[3] & !0x04;
        f.left = b3 & 1 != 0;
        f.right = b3 & 2 != 0;
        AlpsDecode::one(AlpsEvent::Touchpad(f))
    }

    // ── v7 ──────────────────────────────────────────────────────

    /// v7 packet id (Linux `alps_get_packet_id_v7`).
    fn packet_id_v7(p: &[u8; 6]) -> V7PacketId {
        if p[4] & 0x40 != 0 {
            V7PacketId::Two
        } else if p[4] & 0x01 != 0 {
            V7PacketId::Multi
        } else if (p[0] & 0x10) != 0 && (p[4] & 0x43) == 0 {
            V7PacketId::New
        } else if p[1] == 0x00 && p[4] == 0x00 {
            V7PacketId::Idle
        } else {
            V7PacketId::Unknown
        }
    }

    /// v7 finger coordinates (Linux
    /// `alps_get_finger_coordinate_v7`). Y is inverted
    /// (`0x7FF - y`): the pad reports bottom-to-top.
    fn finger_coords_v7(mt: &mut [AlpsPoint; 4], p: &[u8; 6], id: V7PacketId) {
        mt[0].x = (((p[2] & 0x80) as i32) << 4)
            | (((p[2] & 0x3F) as i32) << 5)
            | (((p[3] & 0x30) as i32) >> 1)
            | ((p[3] & 0x07) as i32);
        mt[0].y = ((p[1] as i32) << 3) | ((p[0] & 0x07) as i32);
        mt[1].x = (((p[3] & 0x80) as i32) << 4)
            | (((p[4] & 0x80) as i32) << 3)
            | (((p[4] & 0x3F) as i32) << 4);
        mt[1].y = (((p[5] & 0x80) as i32) << 3) | (((p[5] & 0x3F) as i32) << 4);
        match id {
            V7PacketId::Two => {
                mt[1].x &= !0x000F;
                mt[1].y |= 0x000F;
                // False-positive touch where x & y report max.
                if mt[1].y == 0x7ff && mt[1].x == 0xff0 {
                    mt[1].x = 0;
                    // y becomes 0 in the inversion below.
                }
            }
            V7PacketId::Multi => {
                mt[1].x &= !0x003F;
                mt[1].y &= !0x0020;
                mt[1].y |= (((p[4] & 0x02) as i32) << 4);
                mt[1].y |= 0x001F;
            }
            V7PacketId::New => {
                mt[1].x &= !0x003F;
                mt[1].x |= (p[0] & 0x20) as i32;
                mt[1].y |= 0x000F;
            }
            _ => {}
        }
        mt[0].y = 0x7FF - mt[0].y;
        mt[1].y = 0x7FF - mt[1].y;
    }

    /// v7 touchpad decode (Linux `alps_decode_packet_v7`).
    /// Returns `None` for IDLE (zeroed fields are reported by
    /// the caller as an empty frame — here as a Touchpad event
    /// with no fingers) and for NEW / UNKNOWN packets, which
    /// Linux drops without reporting.
    fn decode_packet_v7(&self, f: &mut AlpsFields, p: &[u8; 6]) -> Option<()> {
        let id = Self::packet_id_v7(p);
        if id == V7PacketId::Idle {
            return Some(());
        }
        if id == V7PacketId::Unknown {
            return None;
        }
        // NEW packets mark a slot discontinuity; they carry no
        // accurate finger count and inaccurate second-touch X,
        // so Linux ignores them outright.
        if id == V7PacketId::New {
            return None;
        }
        Self::finger_coords_v7(&mut f.mt, p, id);
        if id == V7PacketId::Two {
            let mut n = 0u32;
            for m in f.mt.iter().take(2) {
                if m.x != 0 || m.y != 0 {
                    n += 1;
                }
            }
            f.fingers = n;
        } else {
            // MULTI: at least three fingers.
            f.fingers = 3 + (p[5] & 0x03) as u32;
        }
        f.left = (p[0] & 0x80) >> 7 != 0;
        if self.protocol.flags & FLAG_BUTTONPAD != 0 {
            if p[0] & 0x20 != 0 {
                f.fingers += 1;
            }
            if p[0] & 0x10 != 0 {
                f.fingers += 1;
            }
        } else {
            f.right = (p[0] & 0x20) >> 5 != 0;
            f.middle = (p[0] & 0x10) >> 4 != 0;
        }
        // A single touch is sometimes reported in mt[1].
        if f.fingers == 1 && f.mt[0].x == 0 && f.mt[0].y == 0 {
            f.mt[0] = f.mt[1];
            f.mt[1] = AlpsPoint::default();
        }
        f.st = f.mt[0];
        f.pressure = if f.fingers > 0 { 0x30 } else { 0 };
        f.touch = f.fingers > 0;
        Some(())
    }

    /// v7 trackstick packet (Linux
    /// `alps_process_trackstick_packet_v7`).
    fn decode_trackstick_v7(&self, p: &[u8; 6]) -> AlpsDecode {
        if self.protocol.flags & FLAG_DUALPOINT == 0 {
            return AlpsDecode::none();
        }
        let x = ((p[2] & 0xbf) as i32) | (((p[3] & 0x10) as i32) << 2);
        let y = ((p[3] & 0x07) as i32) | ((p[4] & 0xb8) as i32) | (((p[3] & 0x20) as i32) << 1);
        let z = ((p[5] & 0x3f) as i32) | (((p[3] & 0x80) as i32) >> 1);
        AlpsDecode::one(AlpsEvent::Trackstick {
            dx: (x as u8) as i8 as i32,
            dy: -((y as u8) as i8 as i32),
            pressure: z,
            left: p[1] & 1 != 0,
            right: p[1] & 2 != 0,
            middle: p[1] & 4 != 0,
        })
    }

    /// v7 packets (Linux `alps_process_packet_v7`): a
    /// trackstick packet has `packet[0] == 0x48` and
    /// `(packet[4] & 0x47) == 0x06`.
    fn decode_v7(&mut self, p: &[u8]) -> AlpsDecode {
        let mut pkt = [0u8; 6];
        pkt.copy_from_slice(&p[..6]);
        if pkt[0] == 0x48 && (pkt[4] & 0x47) == 0x06 {
            return self.decode_trackstick_v7(&pkt);
        }
        let mut f = AlpsFields::default();
        match self.decode_packet_v7(&mut f, &pkt) {
            Some(()) => AlpsDecode::one(AlpsEvent::Touchpad(f)),
            None => AlpsDecode::none(),
        }
    }

    // ── v8 (SS4v2) ──────────────────────────────────────────────

    /// v8 packet id (Linux `alps_get_pkt_id_ss4_v2`): the type
    /// is selected by bits 4–5 of byte 3.
    fn packet_id_v8(p: &[u8; 6]) -> Ss4PacketId {
        match p[3] & 0x30 {
            0x00 => {
                if ss4_is_idle(p) {
                    Ss4PacketId::Idle
                } else {
                    Ss4PacketId::One
                }
            }
            0x10 => Ss4PacketId::Two,
            0x20 => Ss4PacketId::Stick,
            _ => Ss4PacketId::Multi,
        }
    }

    /// v8 touchpad/stick decode (Linux `alps_decode_ss4_v2`).
    fn decode_packet_v8(&self, f: &mut AlpsFields, p: &[u8; 6]) {
        let id = Self::packet_id_v8(p);
        let buttonpad = self.protocol.flags & FLAG_BUTTONPAD != 0;
        let plus = is_ss4plus_device(&self.dev_id);
        match id {
            Ss4PacketId::One => {
                f.mt[0].x = ss4_1f_x(p);
                f.mt[0].y = ss4_1f_y(p);
                f.pressure = ((ss4_1f_z(p) * 2) & 0x7f) as i32;
                // A button hold reports x, y and pressure of 0
                // — claim zero contacts so the cursor does not
                // jump when a touch is released under a held
                // button.
                f.fingers = if f.pressure > 0 { 1 } else { 0 };
                f.first_mp = false;
                f.is_mp = false;
            }
            Ss4PacketId::Two => {
                if buttonpad {
                    if plus {
                        f.mt[0].x = ss4_plus_btl_mf_x(p, 0);
                        f.mt[1].x = ss4_plus_btl_mf_x(p, 1);
                    } else {
                        f.mt[0].x = ss4_btl_mf_x(p, 0);
                        f.mt[1].x = ss4_btl_mf_x(p, 1);
                    }
                    f.mt[0].y = ss4_btl_mf_y(p, 0);
                    f.mt[1].y = ss4_btl_mf_y(p, 1);
                } else if plus {
                    f.mt[0].x = ss4_plus_std_mf_x(p, 0);
                    f.mt[1].x = ss4_plus_std_mf_x(p, 1);
                    f.mt[0].y = ss4_std_mf_y(p, 0);
                    f.mt[1].y = ss4_std_mf_y(p, 1);
                } else {
                    f.mt[0].x = ss4_std_mf_x(p, 0);
                    f.mt[1].x = ss4_std_mf_x(p, 1);
                    f.mt[0].y = ss4_std_mf_y(p, 0);
                    f.mt[1].y = ss4_std_mf_y(p, 1);
                }
                f.pressure = if ss4_mf_z(p, 0) != 0 { 0x30 } else { 0 };
                if ss4_is_mf_continue(p) {
                    f.first_mp = true;
                } else {
                    f.fingers = 2;
                    f.first_mp = false;
                }
                f.is_mp = false;
            }
            Ss4PacketId::Multi => {
                let (no_data_x, no_data_y);
                if buttonpad {
                    if plus {
                        f.mt[2].x = ss4_plus_btl_mf_x(p, 0);
                        f.mt[3].x = ss4_plus_btl_mf_x(p, 1);
                        no_data_x = SS4_PLUS_MFPACKET_NO_AX_BL;
                    } else {
                        f.mt[2].x = ss4_btl_mf_x(p, 0);
                        f.mt[3].x = ss4_btl_mf_x(p, 1);
                        no_data_x = SS4_MFPACKET_NO_AX_BL;
                    }
                    no_data_y = SS4_MFPACKET_NO_AY_BL;
                    f.mt[2].y = ss4_btl_mf_y(p, 0);
                    f.mt[3].y = ss4_btl_mf_y(p, 1);
                } else {
                    if plus {
                        f.mt[2].x = ss4_plus_std_mf_x(p, 0);
                        f.mt[3].x = ss4_plus_std_mf_x(p, 1);
                        no_data_x = SS4_PLUS_MFPACKET_NO_AX;
                    } else {
                        f.mt[2].x = ss4_std_mf_x(p, 0);
                        f.mt[3].x = ss4_std_mf_x(p, 1);
                        no_data_x = SS4_MFPACKET_NO_AX;
                    }
                    no_data_y = SS4_MFPACKET_NO_AY;
                    f.mt[2].y = ss4_std_mf_y(p, 0);
                    f.mt[3].y = ss4_std_mf_y(p, 1);
                }
                f.first_mp = false;
                f.is_mp = true;
                if ss4_is_5f_detected(p) {
                    f.fingers = 5;
                } else if f.mt[3].x == no_data_x && f.mt[3].y == no_data_y {
                    f.mt[3].x = 0;
                    f.mt[3].y = 0;
                    f.fingers = 3;
                } else {
                    f.fingers = 4;
                }
            }
            Ss4PacketId::Stick => {
                f.first_mp = false;
                f.is_mp = false;
            }
            Ss4PacketId::Idle => {
                *f = AlpsFields::default();
            }
        }
        // Buttons (Linux: stick packets carry the trackstick
        // buttons; anything else carries the pad buttons, and
        // a buttonpad has no separate right/middle buttons).
        let btn = ss4_btn(p);
        if id == Ss4PacketId::Stick {
            f.ts_left = btn & 0x01 != 0;
            f.ts_right = btn & 0x02 != 0;
            f.ts_middle = btn & 0x04 != 0;
        } else {
            f.left = btn & 0x01 != 0;
            if !buttonpad {
                f.right = btn & 0x02 != 0;
                f.middle = btn & 0x04 != 0;
            }
        }
        if id != Ss4PacketId::Idle {
            f.st = f.mt[0];
            f.touch = f.fingers > 0;
        }
    }

    /// v8 packets (Linux `alps_process_packet_ss4_v2`): the
    /// TWO → MULTI multi-packet merge, then the stick report
    /// or the MT report.
    fn decode_v8(&mut self, p: &[u8]) -> AlpsDecode {
        let mut pkt = [0u8; 6];
        pkt.copy_from_slice(&p[..6]);
        let mut f = AlpsFields::default();
        self.decode_packet_v8(&mut f, &pkt);
        if self.multi_packet != 0 {
            if f.is_mp {
                // Re-decode the saved first packet over the
                // merged fields (only the TWO branch fields are
                // overwritten; the MULTI slots survive).
                let saved = self.multi_data;
                let mut saved_pkt = [0u8; 6];
                saved_pkt.copy_from_slice(&saved);
                self.decode_packet_v8(&mut f, &saved_pkt);
            } else {
                self.multi_packet = 0;
            }
        }
        // A MULTI packet without a preceding TWO is dropped.
        if f.is_mp {
            return AlpsDecode::none();
        }
        if self.multi_packet == 0 && f.first_mp {
            self.multi_packet = 1;
            self.multi_data.copy_from_slice(&pkt);
            return AlpsDecode::none();
        }
        self.multi_packet = 0;
        if Self::packet_id_v8(&pkt) == Ss4PacketId::Stick {
            if self.protocol.flags & FLAG_DUALPOINT == 0 {
                return AlpsDecode::none();
            }
            return AlpsDecode::one(AlpsEvent::Trackstick {
                dx: ss4_ts_x(&pkt),
                dy: ss4_ts_y(&pkt),
                pressure: ss4_ts_z(&pkt),
                left: f.ts_left,
                right: f.ts_right,
                middle: f.ts_middle,
            });
        }
        AlpsDecode::one(AlpsEvent::Touchpad(f))
    }
}

/// v7 packet ids (Linux `enum V7_PACKET_ID`, `alps.h`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum V7PacketId {
    Idle,
    Two,
    Multi,
    New,
    Unknown,
}

/// v8 (SS4v2) packet ids (Linux `enum SS4_PACKET_ID`,
/// `alps.h`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Ss4PacketId {
    Idle,
    One,
    Two,
    Multi,
    Stick,
}

// ── SS4v2 (v8) coordinate macros ────────────────────────────────────────────
//
// Linux `SS4_*_V2` macros from `alps.h`, transcribed with the
// C integer promotions made explicit (every byte is widened to
// `i32` before shifting — the macros rely on `unsigned char`
// promoting to `int`).

/// No-contact sentinel X / Y for a standard multi-finger packet.
pub const SS4_MFPACKET_NO_AX: i32 = 8160;
pub const SS4_MFPACKET_NO_AY: i32 = 4080;
/// No-contact sentinels for a buttonless (buttonpad) packet.
pub const SS4_MFPACKET_NO_AX_BL: i32 = 8176;
pub const SS4_MFPACKET_NO_AY_BL: i32 = 4088;
/// No-contact sentinel X for SS4-Plus packets.
pub const SS4_PLUS_MFPACKET_NO_AX: i32 = 4080;
pub const SS4_PLUS_MFPACKET_NO_AX_BL: i32 = 4088;

fn ss4_is_idle(p: &[u8; 6]) -> bool {
    p[0] == 0x18
        && p[1] == 0x10
        && p[2] == 0x00
        && (p[3] & 0x88) == 0x08
        && p[4] == 0x10
        && p[5] == 0x00
}

fn ss4_1f_x(p: &[u8; 6]) -> i32 {
    ((p[0] & 0x07) as i32)
        | (((p[1] as i32) << 3) & 0x0078)
        | (((p[1] as i32) << 2) & 0x0380)
        | (((p[2] as i32) << 5) & 0x1C00)
}

fn ss4_1f_y(p: &[u8; 6]) -> i32 {
    ((p[2] & 0x0F) as i32)
        | (((p[3] as i32) >> 2) & 0x0030)
        | (((p[4] as i32) << 6) & 0x03C0)
        | (((p[4] as i32) << 5) & 0x0C00)
}

fn ss4_1f_z(p: &[u8; 6]) -> i32 {
    ((p[5] & 0x0F) as i32) | (((p[5] as i32) >> 1) & 0x70) | ((p[4] & 0x80) as i32)
}

fn ss4_btn(p: &[u8; 6]) -> u8 {
    (p[0] >> 5) & 0x07
}

fn ss4_std_mf_x(p: &[u8; 6], i: usize) -> i32 {
    (((p[i * 3] as i32) << 5) & 0x00E0) | (((p[1 + i * 3] as i32) << 5) & 0x1F00)
}

fn ss4_plus_std_mf_x(p: &[u8; 6], i: usize) -> i32 {
    (((p[i * 3] as i32) << 4) & 0x0070) | (((p[1 + i * 3] as i32) << 4) & 0x0F80)
}

fn ss4_std_mf_y(p: &[u8; 6], i: usize) -> i32 {
    (((p[1 + i * 3] as i32) << 3) & 0x0010)
        | (((p[2 + i * 3] as i32) << 5) & 0x01E0)
        | (((p[2 + i * 3] as i32) << 4) & 0x0E00)
}

fn ss4_btl_mf_x(p: &[u8; 6], i: usize) -> i32 {
    ss4_std_mf_x(p, i) | (((p[i * 3] as i32) >> 3) & 0x0010)
}

fn ss4_plus_btl_mf_x(p: &[u8; 6], i: usize) -> i32 {
    ss4_plus_std_mf_x(p, i) | (((p[i * 3] as i32) >> 4) & 0x0008)
}

fn ss4_btl_mf_y(p: &[u8; 6], i: usize) -> i32 {
    ss4_std_mf_y(p, i) | (((p[i * 3] as i32) >> 3) & 0x0008)
}

fn ss4_mf_z(p: &[u8; 6], i: usize) -> i32 {
    ((p[1 + i * 3] & 0x01) as i32) | (((p[1 + i * 3] as i32) >> 1) & 0x0002)
}

fn ss4_is_mf_continue(p: &[u8; 6]) -> bool {
    (p[2] & 0x10) == 0x10
}

fn ss4_is_5f_detected(p: &[u8; 6]) -> bool {
    (p[2] & 0x10) == 0x10
}

fn ss4_ts_x(p: &[u8; 6]) -> i32 {
    ((((p[0] & 0x01) << 7) | (p[1] & 0x7F)) as u8) as i8 as i32
}

fn ss4_ts_y(p: &[u8; 6]) -> i32 {
    -(((((p[3] & 0x01) << 7) | (p[2] & 0x7F)) as u8) as i8 as i32)
}

fn ss4_ts_z(p: &[u8; 6]) -> i32 {
    (p[4] & 0x7F) as i8 as i32
}
