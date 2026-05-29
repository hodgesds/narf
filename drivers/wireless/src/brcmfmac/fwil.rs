//! `brcmfmac` Firmware Interface Layer (FWIL) — IOCTL / IOVAR encoder.
//!
//! FWIL is Linux's name for the layer that translates a high-level
//! "set this knob on the firmware" call into a (cmd, data) IOCTL or a
//! ("name\0data", data) IOVAR shipped over the msgbuf control ring.
//!
//! - **IOCTL** — a direct command code from the `BRCMF_C_*` table,
//!   e.g. `BRCMF_C_UP` (2) to bring the radio up, `BRCMF_C_SET_SSID`
//!   (26) to start an association attempt. Payload semantics are
//!   per-command.
//! - **IOVAR** — a wrapper that bundles a NUL-terminated variable name
//!   followed by an opaque blob into the payload of `BRCMF_C_GET_VAR`
//!   (262) or `BRCMF_C_SET_VAR` (263). Used for the much larger surface
//!   of firmware-tunable variables (`chanspec`, `country`, `bss`, etc.).
//!
//! ## Reference (Linux v6.6)
//!
//! - `drivers/net/wireless/broadcom/brcm80211/brcmfmac/fwil.h` —
//!   the `BRCMF_C_*` enumeration (lines 14..83 verbatim).
//! - `drivers/net/wireless/broadcom/brcm80211/brcmfmac/fwil.c` —
//!   `brcmf_create_iovar` (~L166..L184) builds the
//!   "name\0data" buffer that ships as the IOCTL payload.

#![allow(dead_code)]

// ── BRCMF_C_* IOCTL command codes ───────────────────────────────────
//
// Per Linux `fwil.h` (lines 14..83). Mechanically copied — these are
// wire codes the firmware interprets, not driver-internal values, so
// they must match Linux exactly for an unmodified Broadcom firmware
// blob to respond.

pub const BRCMF_C_GET_VERSION: u32 = 1;
pub const BRCMF_C_UP: u32 = 2;
pub const BRCMF_C_DOWN: u32 = 3;
pub const BRCMF_C_SET_PROMISC: u32 = 10;
pub const BRCMF_C_GET_RATE: u32 = 12;
pub const BRCMF_C_GET_INFRA: u32 = 19;
pub const BRCMF_C_SET_INFRA: u32 = 20;
pub const BRCMF_C_GET_AUTH: u32 = 21;
pub const BRCMF_C_SET_AUTH: u32 = 22;
pub const BRCMF_C_GET_BSSID: u32 = 23;
pub const BRCMF_C_GET_SSID: u32 = 25;
pub const BRCMF_C_SET_SSID: u32 = 26;
pub const BRCMF_C_TERMINATED: u32 = 28;
pub const BRCMF_C_GET_CHANNEL: u32 = 29;
pub const BRCMF_C_SET_CHANNEL: u32 = 30;
pub const BRCMF_C_GET_SRL: u32 = 31;
pub const BRCMF_C_SET_SRL: u32 = 32;
pub const BRCMF_C_GET_LRL: u32 = 33;
pub const BRCMF_C_SET_LRL: u32 = 34;
pub const BRCMF_C_GET_RADIO: u32 = 37;
pub const BRCMF_C_SET_RADIO: u32 = 38;
pub const BRCMF_C_GET_PHYTYPE: u32 = 39;
pub const BRCMF_C_SET_KEY: u32 = 45;
pub const BRCMF_C_GET_REGULATORY: u32 = 46;
pub const BRCMF_C_SET_REGULATORY: u32 = 47;
pub const BRCMF_C_SET_PASSIVE_SCAN: u32 = 49;
pub const BRCMF_C_SCAN: u32 = 50;
pub const BRCMF_C_SCAN_RESULTS: u32 = 51;
pub const BRCMF_C_DISASSOC: u32 = 52;
pub const BRCMF_C_REASSOC: u32 = 53;
pub const BRCMF_C_SET_ROAM_TRIGGER: u32 = 55;
pub const BRCMF_C_SET_ROAM_DELTA: u32 = 57;
pub const BRCMF_C_GET_BCNPRD: u32 = 75;
pub const BRCMF_C_SET_BCNPRD: u32 = 76;
pub const BRCMF_C_GET_DTIMPRD: u32 = 77;
pub const BRCMF_C_SET_DTIMPRD: u32 = 78;
pub const BRCMF_C_SET_COUNTRY: u32 = 84;
pub const BRCMF_C_GET_PM: u32 = 85;
pub const BRCMF_C_SET_PM: u32 = 86;
pub const BRCMF_C_GET_REVINFO: u32 = 98;
pub const BRCMF_C_GET_MONITOR: u32 = 107;
pub const BRCMF_C_SET_MONITOR: u32 = 108;
pub const BRCMF_C_GET_CURR_RATESET: u32 = 114;
pub const BRCMF_C_GET_AP: u32 = 117;
pub const BRCMF_C_SET_AP: u32 = 118;
pub const BRCMF_C_SET_SCB_AUTHORIZE: u32 = 121;
pub const BRCMF_C_SET_SCB_DEAUTHORIZE: u32 = 122;
pub const BRCMF_C_GET_RSSI: u32 = 127;
pub const BRCMF_C_GET_WSEC: u32 = 133;
pub const BRCMF_C_SET_WSEC: u32 = 134;
pub const BRCMF_C_GET_PHY_NOISE: u32 = 135;
pub const BRCMF_C_GET_BSS_INFO: u32 = 136;
pub const BRCMF_C_GET_BANDLIST: u32 = 140;
pub const BRCMF_C_SET_SCB_TIMEOUT: u32 = 158;
pub const BRCMF_C_GET_ASSOCLIST: u32 = 159;
pub const BRCMF_C_GET_PHYLIST: u32 = 180;
pub const BRCMF_C_SET_SCAN_CHANNEL_TIME: u32 = 185;
pub const BRCMF_C_SET_SCAN_UNASSOC_TIME: u32 = 187;
pub const BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON: u32 = 201;
pub const BRCMF_C_SET_ASSOC_PREFER: u32 = 205;
pub const BRCMF_C_GET_VALID_CHANNELS: u32 = 217;
pub const BRCMF_C_SET_FAKEFRAG: u32 = 219;
pub const BRCMF_C_GET_KEY_PRIMARY: u32 = 235;
pub const BRCMF_C_SET_KEY_PRIMARY: u32 = 236;
pub const BRCMF_C_SET_SCAN_PASSIVE_TIME: u32 = 258;
pub const BRCMF_C_GET_VAR: u32 = 262;
pub const BRCMF_C_SET_VAR: u32 = 263;
pub const BRCMF_C_SET_WSEC_PMK: u32 = 268;

// ── Firmware error codes (BCME_*) ───────────────────────────────────
//
// Per `fwil.c::brcmf_fil_errstr` (lines 26..80). The firmware returns
// these as **negative** integers in the IOCTL completion's `status`
// field, so `-2` is `BCME_BADARG`. Callers interpret the magnitude.

pub const BCME_OK: i32 = 0;
pub const BCME_ERROR: i32 = -1;
pub const BCME_BADARG: i32 = -2;
pub const BCME_BADOPTION: i32 = -3;
pub const BCME_NOTUP: i32 = -4;
pub const BCME_NOTDOWN: i32 = -5;
pub const BCME_NOTAP: i32 = -6;
pub const BCME_NOTSTA: i32 = -7;
pub const BCME_BADKEYIDX: i32 = -8;
pub const BCME_BUSY: i32 = -16;
pub const BCME_NOTASSOCIATED: i32 = -17;
pub const BCME_BUFTOOSHORT: i32 = -14;
pub const BCME_BUFTOOLONG: i32 = -15;
pub const BCME_UNSUPPORTED: i32 = -23;
pub const BCME_NOTREADY: i32 = -25;
pub const BCME_NOMEM: i32 = -27;
pub const BCME_RANGE: i32 = -29;
pub const BCME_NOTFOUND: i32 = -30;
pub const BCME_VERSION: i32 = -36;
pub const BCME_NODEVICE: i32 = -39;
pub const BCME_DISABLED: i32 = -46;

// ── IOVAR builder ──────────────────────────────────────────────────
//
// `brcmf_create_iovar` builds a payload of the form:
//
//     NAME\0DATA...
//
// where NAME is a printable C string for the firmware variable
// ("chanspec", "country", "bss", etc.) and DATA is the
// command-specific blob. The whole payload then goes through
// `BRCMF_C_SET_VAR` (set) or `BRCMF_C_GET_VAR` (get) over the msgbuf
// control ring.
//
// Reference: Linux `fwil.c::brcmf_create_iovar` (~L166..L184).

/// Maximum IOVAR variable-name length the firmware accepts. Matches the
/// implicit bound in `brcmf_create_iovar` (the `name` argument is a
/// kernel `const char*` with no explicit cap, but every caller passes a
/// constant string ≤ 31 bytes long). 32 bytes leaves room for the NUL.
pub const IOVAR_NAME_MAX: usize = 32;

/// IOCTL payload upper bound. Matches `BRCMF_DCMD_MAXLEN` (Linux
/// `fwil.c::brcmf_fil_cmd_data` ~L108).
pub const BRCMF_DCMD_MAXLEN: usize = 8192;

/// Build the "name\0data" payload bytes-into `out`. Returns the number
/// of bytes written, or `None` if `out` is too small or the name is
/// not NUL-free / too long.
///
/// Direct port of `brcmf_create_iovar`. `name` must be a printable C
/// string (no embedded NUL); the encoder appends the trailing NUL and
/// then the `data` payload.
pub fn build_iovar_payload(name: &str, data: &[u8], out: &mut [u8]) -> Option<usize> {
    if name.len() >= IOVAR_NAME_MAX {
        return None;
    }
    if name.as_bytes().contains(&0) {
        return None;
    }
    let total = name.len() + 1 + data.len();
    if out.len() < total {
        return None;
    }
    out[..name.len()].copy_from_slice(name.as_bytes());
    out[name.len()] = 0;
    out[name.len() + 1..total].copy_from_slice(data);
    Some(total)
}

/// Decode an IOVAR payload back into `(name, data)`. Returns `None` if
/// no NUL is present in the buffer.
pub fn parse_iovar_payload(payload: &[u8]) -> Option<(&str, &[u8])> {
    let nul = payload.iter().position(|&b| b == 0)?;
    let name = core::str::from_utf8(&payload[..nul]).ok()?;
    Some((name, &payload[nul + 1..]))
}

// ── SSID struct (`brcmf_ssid_le`) ──────────────────────────────────
//
// Wire payload for `BRCMF_C_SET_SSID` and `BRCMF_C_GET_SSID`. The
// firmware expects a 4-byte LE `SSID_len` followed by exactly 32 bytes
// of SSID buffer, zero-padded.
//
// Reference: Linux `fwil_types.h::brcmf_ssid_le` (~L357).

/// Maximum SSID length per IEEE 802.11. The firmware's struct holds a
/// fixed 32-byte buffer regardless of actual length.
pub const IEEE80211_MAX_SSID_LEN: usize = 32;

/// Wire size of `brcmf_ssid_le`: 4-byte length + 32-byte buffer.
pub const SSID_LE_SIZE: usize = 4 + IEEE80211_MAX_SSID_LEN;

/// Encode an SSID into the 36-byte `brcmf_ssid_le` wire form.
/// Returns `None` if `ssid` is longer than `IEEE80211_MAX_SSID_LEN` or
/// `out` is too small.
pub fn encode_ssid_le(ssid: &[u8], out: &mut [u8]) -> Option<()> {
    if ssid.len() > IEEE80211_MAX_SSID_LEN {
        return None;
    }
    if out.len() < SSID_LE_SIZE {
        return None;
    }
    let len = ssid.len() as u32;
    out[0..4].copy_from_slice(&len.to_le_bytes());
    out[4..4 + ssid.len()].copy_from_slice(ssid);
    // Zero-pad remainder.
    for byte in &mut out[4 + ssid.len()..SSID_LE_SIZE] {
        *byte = 0;
    }
    Some(())
}

/// Decode a `brcmf_ssid_le` from `bytes`. Returns `(len, ssid_buf)` —
/// `ssid_buf` is always the full 32-byte buffer; the caller may want
/// `&ssid_buf[..len as usize]` for the live portion.
pub fn decode_ssid_le(bytes: &[u8]) -> Option<(u32, &[u8])> {
    if bytes.len() < SSID_LE_SIZE {
        return None;
    }
    let len = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if len as usize > IEEE80211_MAX_SSID_LEN {
        return None;
    }
    Some((len, &bytes[4..4 + IEEE80211_MAX_SSID_LEN]))
}

// ── join_params encoder (`BRCMF_C_SET_SSID` payload) ───────────────
//
// `brcmf_join_params` = `brcmf_ssid_le` + `brcmf_assoc_params_le`. The
// assoc-params block is BSSID + chanspec-count + chanspec-list. For a
// blind SSID association (no BSSID lock, channels-any), the assoc
// params are 6 bytes of zero BSSID, 4 bytes of zero chanspec-num, and
// a single 2-byte chanspec entry. Total = 36 + 6 + 4 + 2 = 48 bytes
// for one chanspec, or 36 + 6 + 4 for chanspec-num = 0.
//
// Reference: Linux `fwil_types.h::brcmf_join_params` (~L509),
//            `brcmf_assoc_params_le` (~L482).

/// MAC address length (ETH_ALEN).
pub const ETH_ALEN: usize = 6;

/// Base size of `brcmf_assoc_params_le` (BSSID 6 + chanspec_num 4 +
/// chanspec_list[0] 2 = 12). When chanspec_num is 0 the chanspec_list
/// is still required (Linux declares it as `[1]`), so the firmware
/// reads a 2-byte placeholder regardless.
pub const ASSOC_PARAMS_BASE_SIZE: usize = ETH_ALEN + 4 + 2;

/// Full size of `brcmf_join_params` when used with a single
/// (placeholder) chanspec entry. Used by SSID-only / blind join.
pub const JOIN_PARAMS_BLIND_SIZE: usize = SSID_LE_SIZE + ASSOC_PARAMS_BASE_SIZE;

/// Encode a blind-SSID join into `out`.
///
/// `ssid`   — the SSID bytes (≤ 32).
/// `bssid`  — optional 6-byte BSSID; if `None`, the BSSID field is left
///            zeroed (firmware interprets all-zero BSSID as "any AP").
/// `chanspec` — optional 16-bit chanspec (see
///            [`super::msgbuf::chanspec_20mhz`]) to bias the join
///            attempt onto a specific channel. `0` for no preference.
///
/// Returns the number of bytes written (= [`JOIN_PARAMS_BLIND_SIZE`])
/// or `None` if the inputs are invalid.
///
/// Reference: Linux `cfg80211.c::brcmf_set_join_pref` builds this in
/// the `WL_JOIN_PREF` IOVAR; the actual `SET_SSID` payload is built in
/// `brcmf_link_set_ssid` (~L2245, v6.6) which calls into the same
/// `brcmf_join_params` encoder shape.
pub fn encode_join_params(
    ssid: &[u8],
    bssid: Option<&[u8; ETH_ALEN]>,
    chanspec: u16,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < JOIN_PARAMS_BLIND_SIZE {
        return None;
    }
    encode_ssid_le(ssid, &mut out[..SSID_LE_SIZE])?;
    let bssid_off = SSID_LE_SIZE;
    if let Some(b) = bssid {
        out[bssid_off..bssid_off + ETH_ALEN].copy_from_slice(b);
    } else {
        for byte in &mut out[bssid_off..bssid_off + ETH_ALEN] {
            *byte = 0;
        }
    }
    // chanspec_num: 1 if a chanspec is supplied, 0 otherwise. Use 1
    // when biasing onto a known channel — firmware otherwise scans
    // every channel which is much slower.
    let chanspec_num: u32 = if chanspec != 0 { 1 } else { 0 };
    let cn_off = bssid_off + ETH_ALEN;
    out[cn_off..cn_off + 4].copy_from_slice(&chanspec_num.to_le_bytes());
    let cl_off = cn_off + 4;
    out[cl_off..cl_off + 2].copy_from_slice(&chanspec.to_le_bytes());
    Some(JOIN_PARAMS_BLIND_SIZE)
}
