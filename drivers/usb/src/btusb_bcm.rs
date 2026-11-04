//! Broadcom USB Bluetooth firmware setup (BCM4377/4378).
//!
//! Broadcom controllers boot a ROM patcher: the host downloads a
//! `.hcd` patch file — a stream of HCI commands — into patch RAM
//! and the controller reboots into the patched firmware. Only
//! after the upload does the controller answer normal HCI.
//!
//! Reference: Linux `drivers/bluetooth/btbcm.c`
//! (`btbcm_patchram`, `btbcm_setup_patchram`, GPL-2.0-or-later),
//! consulted under NARF's GPL-2.0-or-later licensing, plus the
//! in-tree quirk table (`bluetooth/src/btusb_quirks.rs`, whose
//! Broadcom names come from the same file's naming scheme).
//!
//! Wire sequence:
//! 1. HCI_Reset, mirroring the reset `btbcm_initialize` issues
//!    before patchram (the generic bring-up resets again after
//!    vendor setup; the duplicate is harmless).
//! 2. Download Minidriver, HCI vendor opcode 0xFC2E, no
//!    parameters, awaiting Command Complete.
//! 3. 50 ms cooperative delay.
//! 4. The `.hcd` records in file order: each record is
//!    `[opcode LE16, plen, params[plen]]` sent as one HCI
//!    command awaiting Command Complete. The final record is the
//!    Launch RAM command; no opcode is special-cased, exactly as
//!    in Linux.
//! 5. 250 ms cooperative delay after the last record.
//! 6. Pending vendor events are drained so the generic bring-up
//!    sees a clean event stream.
//!
//! Deliberate strictness deltas vs Linux, all fail-closed:
//! - A `.hcd` with 1-2 trailing bytes (a partial record header)
//!   fails the parse; Linux silently ignores the tail.
//! - A missing patch file fails the bind; Linux logs "firmware
//!   Patch file not found" and continues with the unpatched ROM.
//!   NARF's issue scope is fail-closed: a part whose quirk entry
//!   names a patch must not silently run unpatched.
//!
//! The pure helper (`parse_hcd`) carries the conversation
//! fixtures; the async glue is a thin loop over it.

use alloc::format;
use alloc::vec::Vec;

use narf_bluetooth::btusb_quirks::{self, Quirk};
use narf_bluetooth::opcode as op;

use crate::btusb::{self, BtUsbError};
use crate::xhci::Xhci;

/// HCI vendor opcode: download minidriver.
const OP_DOWNLOAD_MINIDRIVER: u16 = 0xFC2E;
/// Delay after the minidriver download completes.
const MINIDRIVER_DELAY_MS: u64 = 50;
/// Delay after the Launch RAM record completes.
const LAUNCH_RAM_DELAY_MS: u64 = 250;
/// `.hcd` record header: opcode LE16 + parameter length.
const HCD_RECORD_HDR_SIZE: usize = 3;

/// Registry prefix for Broadcom firmware names.
const BRCM_PREFIX: &str = "brcm";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BcmError {
    /// A vendor command failed at the HCI layer.
    Transport(BtUsbError),
    /// No provisioned `.hcd` patch file for this controller.
    FirmwareUnavailable,
    /// The `.hcd` file failed structural validation.
    FirmwareInvalid,
}

impl From<BtUsbError> for BcmError {
    fn from(e: BtUsbError) -> Self {
        BcmError::Transport(e)
    }
}

/// One `.hcd` record: an HCI command to send verbatim.
#[derive(Debug, PartialEq, Eq)]
struct HcdCommand<'a> {
    opcode: u16,
    params: &'a [u8],
}

/// Parse a `.hcd` patch file into its command records. A record
/// header or parameter block overrunning the file fails, as does
/// a trailing 1-2 byte partial header (strict vs Linux, which
/// ignores the tail).
fn parse_hcd(bytes: &[u8]) -> Result<Vec<HcdCommand<'_>>, BcmError> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let hdr = bytes
            .get(pos..pos + HCD_RECORD_HDR_SIZE)
            .ok_or(BcmError::FirmwareInvalid)?;
        let opcode = u16::from_le_bytes([hdr[0], hdr[1]]);
        let plen = hdr[2] as usize;
        pos += HCD_RECORD_HDR_SIZE;
        let params = bytes
            .get(pos..pos + plen)
            .ok_or(BcmError::FirmwareInvalid)?;
        pos += plen;
        records.push(HcdCommand { opcode, params });
    }
    Ok(records)
}

/// Cooperative delay: yield until the deadline, mirroring the
/// MediaTek loader's helper.
async fn cooperative_delay_ms(ms: u64) {
    let deadline = narf_time::Deadline::after_ms(ms);
    while !deadline.expired() {
        narf_scheduler::yield_now().await;
    }
}

/// Run the Broadcom firmware setup for a just-configured USB
/// Bluetooth controller. On success the controller is running
/// patched firmware and the generic bring-up may proceed.
pub(crate) async fn setup_broadcom(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
) -> Result<(), BcmError> {
    let mut patch_cap = None;
    for (name, _) in btusb_quirks::firmware_paths(Quirk::Broadcom) {
        if let Some(cap) = btusb::firmware_cap(&format!("{BRCM_PREFIX}/{name}")) {
            patch_cap = Some(cap);
            break;
        }
    }
    let patch_cap = patch_cap.ok_or(BcmError::FirmwareUnavailable)?;
    let patch_view =
        narf_firmware::view_of(&patch_cap).map_err(|_| BcmError::FirmwareUnavailable)?;
    let records = parse_hcd(patch_view.bytes)?;
    btusb::send_command_and_await_complete(xhci, slot_id, interface, event_dci, op::HCI_RESET, &[])
        .await?;
    btusb::send_command_and_await_complete(
        xhci,
        slot_id,
        interface,
        event_dci,
        OP_DOWNLOAD_MINIDRIVER,
        &[],
    )
    .await?;
    cooperative_delay_ms(MINIDRIVER_DELAY_MS).await;
    for record in &records {
        btusb::send_command_and_await_complete(
            xhci,
            slot_id,
            interface,
            event_dci,
            record.opcode,
            record.params,
        )
        .await?;
    }
    cooperative_delay_ms(LAUNCH_RAM_DELAY_MS).await;
    btusb::drain_pending_events(xhci, slot_id, event_dci, 500).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn record(opcode: u16, params: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&opcode.to_le_bytes());
        out.push(params.len() as u8);
        out.extend_from_slice(params);
        out
    }

    #[test]
    fn parses_record_stream_byte_for_byte() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&record(0xFC2E, &[]));
        bytes.extend_from_slice(&record(0x0C03, &[0x01, 0x02, 0x03]));
        bytes.extend_from_slice(&record(0xFC4C, &[0xAA]));
        let records = parse_hcd(&bytes).unwrap();
        assert_eq!(
            records,
            vec![
                HcdCommand {
                    opcode: 0xFC2E,
                    params: &[]
                },
                HcdCommand {
                    opcode: 0x0C03,
                    params: &[0x01, 0x02, 0x03]
                },
                HcdCommand {
                    opcode: 0xFC4C,
                    params: &[0xAA]
                },
            ]
        );
    }

    #[test]
    fn rejects_truncated_record() {
        // Header claims 4 params, file carries 2.
        let mut bytes = record(0x0C03, &[0x01, 0x02]);
        bytes[2] = 4;
        assert_eq!(parse_hcd(&bytes), Err(BcmError::FirmwareInvalid));
    }

    #[test]
    fn rejects_trailing_partial_header() {
        let mut bytes = record(0x0C03, &[0x01]);
        bytes.extend_from_slice(&[0x4C, 0xFC]);
        assert_eq!(parse_hcd(&bytes), Err(BcmError::FirmwareInvalid));
    }

    #[test]
    fn empty_file_is_empty_stream() {
        assert_eq!(parse_hcd(&[]), Ok(Vec::new()));
    }
}
