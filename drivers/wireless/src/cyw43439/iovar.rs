//! IOVAR — string-keyed variant of IOCTL on the CYW43439.
//!
//! Most chip configuration that doesn't have a dedicated `WLC_*`
//! command is reached through *IOVARs* — string-named "variables"
//! the firmware exposes. The wire format is just an IOCTL with
//! command [`super::ioctl::WLC_GET_VAR`] / [`super::ioctl::WLC_SET_VAR`]
//! whose payload begins with the NUL-terminated variable name and
//! is followed by the value bytes.
//!
//! IOVAR names are documented in **AN232689 Wi-Fi Software User
//! Guide** and reproduced (with cross-checked usage examples) in
//! `soypat/cyw43439` (MIT) and Embassy `cyw43` (Apache-2.0 / MIT).
//! **No GPL `brcmfmac` / `bcmdhd` source consulted.**

use alloc::vec::Vec;

use super::ioctl::{build_request, Direction, WLC_GET_VAR, WLC_SET_VAR};

// ── Common IOVAR names (AN232689) ──────────────────────────────────

/// `clmload` — push the CLM (country-locale matrix) blob into the
/// firmware after boot. The value is the raw CLM bytes; the host
/// segments the upload across multiple `clmload` SET_VARs.
pub const VAR_CLMLOAD: &str = "clmload";
/// `country` — set/read the operating country code. Value layout:
/// 4 bytes country code + 4-byte struct (`ccode_rev`, `ccode`).
pub const VAR_COUNTRY: &str = "country";
/// `cur_etheraddr` — current Ethernet (MAC) address.
pub const VAR_CUR_ETHERADDR: &str = "cur_etheraddr";
/// `bsscfg:event_msgs` — event-mask vector for which async events
/// the firmware should deliver to the host.
pub const VAR_EVENT_MSGS: &str = "bsscfg:event_msgs";
/// `escan` / `escanresults` — extended (non-blocking) scan IOVAR
/// pair used by `narf-wireless` for STA scan offload.
pub const VAR_ESCAN: &str = "escan";
pub const VAR_ESCAN_RESULTS: &str = "escanresults";
/// `bus:txglom` — enable TX aggregation ("GLOM") on the F2 path.
pub const VAR_BUS_TXGLOM: &str = "bus:txglom";
/// `bus:txglomalign` / `bus:rxglom` — alignment / RX-side controls.
pub const VAR_BUS_TXGLOM_ALIGN: &str = "bus:txglomalign";
pub const VAR_BUS_RXGLOM: &str = "bus:rxglom";
/// `pm` / `pm2_sleep_ret` — power-management knobs.
pub const VAR_PM: &str = "pm";
pub const VAR_PM2_SLEEP_RET: &str = "pm2_sleep_ret";
/// `cur_etheraddr` synonym used in some firmware revisions; kept
/// here as a separate constant so callers can pick either spelling.
pub const VAR_CURRENT_MAC: &str = "cur_etheraddr";

// ── Encoders ──────────────────────────────────────────────────────

/// Build the IOCTL payload for an IOVAR access.
///
/// Layout:
///
/// ```text
///   [name bytes] 0x00 [value bytes]
/// ```
///
/// The chip enforces NUL termination on the name; the value is then
/// either zero-padded out-buffer space (GET) or the actual data
/// being written (SET).
pub fn build_payload(name: &str, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(name.len() + 1 + value.len());
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(value);
    buf
}

/// Compose a complete IOVAR SET request frame.
pub fn build_set_request(
    seq: u8,
    xact_id: u16,
    if_idx: u8,
    name: &str,
    value: &[u8],
) -> Vec<u8> {
    let payload = build_payload(name, value);
    build_request(seq, xact_id, if_idx, Direction::Set, WLC_SET_VAR, &payload)
}

/// Compose a complete IOVAR GET request frame. `out_len` is the
/// number of bytes the host has reserved in the buffer for the
/// chip's response value (the chip writes its response in-place).
pub fn build_get_request(
    seq: u8,
    xact_id: u16,
    if_idx: u8,
    name: &str,
    out_len: usize,
) -> Vec<u8> {
    let zero = alloc::vec![0u8; out_len];
    let payload = build_payload(name, &zero);
    build_request(seq, xact_id, if_idx, Direction::Get, WLC_GET_VAR, &payload)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_payload_layout() -> TestResult {
        let p = build_payload(VAR_COUNTRY, b"US\x00\x00");
        // Expect "country" + 0x00 + value
        if &p[..VAR_COUNTRY.len()] != VAR_COUNTRY.as_bytes() {
            return TestResult::Fail("name not at start");
        }
        if p[VAR_COUNTRY.len()] != 0 {
            return TestResult::Fail("name not NUL-terminated");
        }
        if &p[VAR_COUNTRY.len() + 1..] != b"US\x00\x00" {
            return TestResult::Fail("value bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/iovar", smoke_payload_layout);

    fn smoke_set_request_uses_set_var() -> TestResult {
        let frame = build_set_request(1, 0, 0, VAR_PM, &[1, 0, 0, 0]);
        // BCDC starts at offset 12 (HW 4 + SW 8); cmd is the first u32.
        let bcdc_start = 12;
        let cmd = u32::from_le_bytes([
            frame[bcdc_start],
            frame[bcdc_start + 1],
            frame[bcdc_start + 2],
            frame[bcdc_start + 3],
        ]);
        if cmd != WLC_SET_VAR {
            return TestResult::Fail("SET request not encoded as WLC_SET_VAR");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/iovar",
        smoke_set_request_uses_set_var
    );

    fn smoke_get_request_reserves_outbuf() -> TestResult {
        let frame = build_get_request(1, 0, 0, VAR_CUR_ETHERADDR, 6);
        // Payload length encoded in BCDC.len = name + NUL + 6.
        let bcdc_start = 12;
        let len = u32::from_le_bytes([
            frame[bcdc_start + 4],
            frame[bcdc_start + 5],
            frame[bcdc_start + 6],
            frame[bcdc_start + 7],
        ]) as usize;
        if len != VAR_CUR_ETHERADDR.len() + 1 + 6 {
            return TestResult::Fail("GET payload length wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/iovar",
        smoke_get_request_reserves_outbuf
    );
}
