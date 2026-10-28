//! USB Mass Storage Class — Bulk-Only Transport (BOT) — clean-room.
//!
//! ## Reference
//!
//! - "Universal Serial Bus Mass Storage Class Bulk-Only Transport"
//!   Revision 1.0, 31 September 1999. Public document, usb.org.
//!   Section numbers below (`§3.x`) refer to this spec.
//!   <https://www.usb.org/document-library/mass-storage-bulk-only-10>
//! - "SCSI Block Commands - 3 (SBC-3)" — for the embedded SCSI
//!   command opcodes (`READ(10)` / `WRITE(10)` / `INQUIRY` /
//!   `READ CAPACITY(10)`).
//!   <https://www.t10.org/drafts.htm#SCSI3_SBC>
//!
//! ## Protocol shape (§3 BOT)
//!
//! Three-phase per command:
//!   1. **CBW** (Command Block Wrapper, 31 bytes, `bulk-OUT`).
//!   2. **Data**: caller's payload, on `bulk-IN` for reads, on
//!      `bulk-OUT` for writes. Optional (some commands have no
//!      data stage — TEST UNIT READY, etc.).
//!   3. **CSW** (Command Status Wrapper, 13 bytes, `bulk-IN`).
//!
//! ## Implemented command set
//!
//! - TEST UNIT READY (0x00) — probe readiness
//! - REQUEST SENSE (0x03) — 18-byte fixed-format sense on error
//! - INQUIRY (0x12) — vendor / product / revision
//! - START STOP UNIT (0x1B) — spin up / down / eject
//! - READ CAPACITY(10) (0x25) — last LBA + block size
//! - READ CAPACITY(16) (0x9E) — issued at attach when the
//!   10-byte form reports `0xFFFF_FFFF`; its 64-bit last LBA
//!   decides the capacity of > 2 TiB media (#832)
//! - READ(10) (0x28) / WRITE(10) (0x2A) — single and multi-block;
//!   WRITE(10) also in its FUA form (byte 1 bit 3) for
//!   [`UsbMscBlockDevice`]'s native `write_fua`
//! - READ(16) (0x88) / WRITE(16) (0x8A) — the 16-byte forms,
//!   selected per LUN when its capacity crossed the 32-bit
//!   boundary (#832)
//! - SYNCHRONIZE CACHE(10) (0x35) — whole-medium cache flush
//!   backing [`UsbMscBlockDevice`]'s `flush()`; without it the
//!   block layer's Flush/FUA advertisement was a durability lie
//!   (#829)
//!
//! Multi-LUN devices bind one [`MscDevice`] per LUN after a
//! GET MAX LUN probe at attach (#831).
//!
//! ## Error recovery (#830)
//!
//! A failed command is not the end of the conversation. Within
//! an exchange, a stalled bulk pipe is cleared (host Reset
//! Endpoint + device CLEAR_FEATURE) and the status phase still
//! runs. At the command level, a Command Failed status drains
//! REQUEST SENSE and retries once for the transient conditions
//! (UNIT ATTENTION, spin-up), a Phase Error or an unparseable
//! CSW triggers Reset Recovery (§5.3) and one retry, and a
//! durable failure surfaces with its sense data attached
//! ([`MscError::Sense`]). UAS (USB Attached SCSI) remains
//! deferred — no issue in the MSC family covers it.

use alloc::vec::Vec;

use core::future::Future;

use crate::xhci::{self, EndpointConfig, EndpointKind, Xhci};
use narf_lib::sync::IrqSafeSpinLock;

/// Maximum payload (in target blocks) we'll cram into a single
/// BOT command. Larger requests are chunked into a sequence of
/// commands by the read/write paths (#828); the bound itself
/// comes from the bulk transfer scratch (see
/// `MSC_DMA_PAGE_BYTES`).
pub const MSC_MAX_BLOCKS_PER_XFER: u16 = 8;

/// Size of the xHCI endpoint DMA buffer a single bulk transfer
/// moves. A BOT data stage larger than this cannot complete, so
/// chunk sizes are the smaller of `MSC_MAX_BLOCKS_PER_XFER`
/// blocks and however many whole blocks fit in one page.
const MSC_DMA_PAGE_BYTES: u32 = 4096;

// USB class triple identifying a Mass Storage device with the SCSI
// transparent command set + Bulk-Only Transport (§4.0 of the BOT
// spec; §3.1 of the parent MSC spec). These show up in the
// Interface Descriptor's bInterfaceClass / SubClass / Protocol.
pub const MSC_INTERFACE_CLASS: u8 = 0x08;
pub const MSC_INTERFACE_SUBCLASS: u8 = 0x06; // SCSI Transparent
pub const MSC_INTERFACE_PROTOCOL: u8 = 0x50; // Bulk-Only Transport

/// CBW signature (§5.1 Table 5.1) — `b'USBC'` little-endian.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// CSW signature (§5.2 Table 5.2) — `b'USBS'` little-endian.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;

/// CBW direction bit (bmCBWFlags bit 7): 1 = data IN (device to host).
const CBW_FLAG_IN: u8 = 0x80;

/// SCSI opcodes we issue.
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_REQUEST_SENSE: u8 = 0x03;
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_START_STOP_UNIT: u8 = 0x1B;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2A;
const SCSI_READ_16: u8 = 0x88;
const SCSI_WRITE_16: u8 = 0x8A;
const SCSI_SYNCHRONIZE_CACHE_10: u8 = 0x35;

/// WRITE(10) CDB byte 1 bit 3: Force Unit Access — the device must
/// write the data to the medium (not merely to its volatile cache)
/// before reporting completion (SBC-3 §5.30, Table 92).
const WRITE10_FUA: u8 = 0x08;

/// Decoded standard INQUIRY response (SPC-4 §6.5 Table 82).
/// Vendor (8 bytes), product (16 bytes), and revision (4 bytes)
/// are space-padded ASCII in the wire format; we trim trailing
/// whitespace before storing them here.
#[derive(Clone, Debug)]
pub struct InquiryData {
    /// Peripheral Device Type (bits[4:0] of byte 0; 0 = Direct Access).
    pub peripheral_type: u8,
    /// Removable Medium Bit (bit 7 of byte 1).
    pub removable: bool,
    /// Vendor identification string (at most 8 printable ASCII chars).
    pub vendor: alloc::string::String,
    /// Product identification string (at most 16 printable ASCII chars).
    pub product: alloc::string::String,
    /// Product revision level (at most 4 printable ASCII chars).
    pub revision: alloc::string::String,
}

impl InquiryData {
    /// Decode a 36-byte standard INQUIRY response buffer. Returns
    /// `None` if the buffer is shorter than 36 bytes.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 36 {
            return None;
        }
        let peripheral_type = buf[0] & 0x1F;
        let removable = buf[1] & 0x80 != 0;
        let vendor =
            alloc::string::String::from(core::str::from_utf8(&buf[8..16]).unwrap_or("").trim_end());
        let product = alloc::string::String::from(
            core::str::from_utf8(&buf[16..32]).unwrap_or("").trim_end(),
        );
        let revision = alloc::string::String::from(
            core::str::from_utf8(&buf[32..36]).unwrap_or("").trim_end(),
        );
        Some(InquiryData {
            peripheral_type,
            removable,
            vendor,
            product,
            revision,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MscError {
    /// Device's `bInterfaceClass:SubClass:Protocol` didn't match BOT.
    NotMsc,
    /// Couldn't enumerate enough endpoints (need bulk IN + bulk OUT).
    EndpointsMissing,
    /// CSW signature didn't match `b'USBS'`.
    BadCsw,
    /// CSW reported a non-success status (1 = Failed, 2 = Phase Error).
    CswStatus(u8),
    /// The command failed with CHECK CONDITION and the follow-up
    /// REQUEST SENSE returned this fixed-format sense data
    /// (SPC-4 §4.5) — the device's own account of why: sense key,
    /// additional sense code, and qualifier. Surfaced instead of
    /// a bare status byte so a medium error, a write-protect, or
    /// an absent medium is distinguishable upstream (#830).
    Sense(narf_block::scsi::FixedSense),
    /// Underlying xHCI error.
    Xhci(xhci::XhciError),
    /// Caller-supplied buffer is the wrong size.
    BadLength,
}

impl From<xhci::XhciError> for MscError {
    fn from(e: xhci::XhciError) -> Self {
        MscError::Xhci(e)
    }
}

/// GET MAX LUN — class-specific request 0xFE (BOT §3.3):
/// `bmRequestType` 0xA1 (device-to-host, class, interface),
/// `wValue` 0, `wIndex` = interface number, one data byte: the
/// largest LUN the device supports (total LUNs − 1).
pub const BOT_GET_MAX_LUN: u8 = 0xFE;

/// Mass Storage Reset — class-specific request 0xFF (BOT §5.3):
/// `bmRequestType` 0x21 (host-to-device, class, interface),
/// `wValue` 0, `wIndex` = interface number, no data stage. The
/// first step of Reset Recovery (#830).
pub const BOT_MASS_STORAGE_RESET: u8 = 0xFF;

/// Defensive bound on the LUN index probed at bind. The BOT spec
/// puts no bound on the GET MAX LUN response byte, but a family
/// of buggy bridges answers 0xFF to an unsupported request; each
/// probed LUN costs a READ CAPACITY conversation, so an unbounded
/// byte could stall bind for minutes. Real multi-LUN devices
/// (card readers) expose a handful of LUNs; 15 is far above any
/// shipping reader and far below a hang.
const MAX_LUN_PROBE: u8 = 15;

/// Transport seam for the BOT conversation: the wire operations
/// [`MscDevice`] drives, abstracted so kernel-test fixtures can
/// play the device side of the conversation end to end without an
/// xHCI controller — the pattern `ccid`'s `CcidTransport`
/// established in this crate. The production implementation is
/// [`Xhci`], whose bulk / control methods already have exactly
/// these shapes; fixtures implement the device side of BOT + the
/// embedded SCSI conversation independently, from the specs.
pub trait BotTransport {
    /// One bulk-IN transfer (CBW data stage or CSW) on `dci`.
    fn bulk_in(
        &self,
        slot_id: u8,
        dci: u8,
        out: &mut [u8],
    ) -> impl Future<Output = Result<usize, MscError>>;
    /// One bulk-OUT transfer (CBW or data stage) on `dci`.
    fn bulk_out(
        &self,
        slot_id: u8,
        dci: u8,
        data: &[u8],
    ) -> impl Future<Output = Result<usize, MscError>>;
    /// Control read on EP0 (GET MAX LUN rides this).
    fn control_in(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &mut [u8],
    ) -> impl Future<Output = Result<usize, MscError>>;
    /// Control write / no-data control request on EP0
    /// (SET_CONFIGURATION, CLEAR_FEATURE, Mass Storage Reset).
    fn control_out(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> impl Future<Output = Result<usize, MscError>>;
    /// Host half of halted-endpoint recovery: Reset Endpoint +
    /// Set TR Dequeue Pointer on the controller side (the
    /// device-side half is CLEAR_FEATURE(ENDPOINT_HALT), issued by
    /// the caller over [`Self::control_out`]). See
    /// `Xhci::reset_endpoint` for the hardware sequence.
    fn reset_halted_endpoint(
        &self,
        slot_id: u8,
        dci: u8,
    ) -> impl Future<Output = Result<(), MscError>>;
    /// Resume this device's hub port if the supervisor has
    /// idle-suspended it (#840). Production delegates to
    /// `attach::resume_port`; fixtures have no hub topology and
    /// take the no-op default.
    fn resume_hub_port(&self, _hub_port: Option<(usize, u8)>) -> impl Future<Output = ()> {
        async {}
    }
    /// Feed the hub idle-suspend activity timer after a completed
    /// transfer (#840). No-op by default, as above.
    fn note_hub_activity(&self, _hub_port: Option<(usize, u8)>) {}
}

impl BotTransport for Xhci {
    async fn bulk_in(&self, slot_id: u8, dci: u8, out: &mut [u8]) -> Result<usize, MscError> {
        self.bulk_in(slot_id, dci, out)
            .await
            .map_err(MscError::Xhci)
    }

    async fn bulk_out(&self, slot_id: u8, dci: u8, data: &[u8]) -> Result<usize, MscError> {
        self.bulk_out(slot_id, dci, data)
            .await
            .map_err(MscError::Xhci)
    }

    async fn control_in(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        out: &mut [u8],
    ) -> Result<usize, MscError> {
        self.control_in(slot_id, bm_request_type, b_request, w_value, w_index, out)
            .await
            .map_err(MscError::Xhci)
    }

    async fn control_out(
        &self,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: &[u8],
    ) -> Result<usize, MscError> {
        self.control_out(slot_id, bm_request_type, b_request, w_value, w_index, data)
            .await
            .map_err(MscError::Xhci)
    }

    async fn reset_halted_endpoint(&self, slot_id: u8, dci: u8) -> Result<(), MscError> {
        // `Xhci::reset_endpoint` (the inherent method) additionally
        // wants the slot's current device generation; resolve it
        // here so BOT callers only name the endpoint.
        let generation = self
            .device_generation(slot_id)
            .ok_or(MscError::Xhci(xhci::XhciError::CmdFailed(0xFD)))?;
        self.reset_endpoint(slot_id, generation, dci)
            .await
            .map_err(MscError::Xhci)
    }

    async fn resume_hub_port(&self, hub_port: Option<(usize, u8)>) {
        if let Some((hub_idx, port)) = hub_port {
            crate::attach::resume_port(self, hub_idx, port).await;
        }
    }

    fn note_hub_activity(&self, hub_port: Option<(usize, u8)>) {
        if let Some((hub_idx, port)) = hub_port {
            crate::attach::mark_port_activity(hub_idx, port);
        }
    }
}

/// One bulk-only-transport mass storage device. Ties a previously
/// addressed + configured xHCI slot to its bulk-IN / bulk-OUT
/// endpoint DCIs.
#[derive(Debug)]
pub struct MscDevice {
    pub slot_id: u8,
    pub bulk_in: u8,  // DCI of the bulk-IN endpoint
    pub bulk_out: u8, // DCI of the bulk-OUT endpoint
    /// Logical unit number this instance speaks for — the
    /// `bCBWLUN` byte of every CBW it issues (BOT §5.1). One
    /// `MscDevice` exists per LUN: a multi-LUN device (a card
    /// reader) binds one instance per LUN, all sharing the slot
    /// and the bulk endpoint pair (#831).
    pub lun: u8,
    /// `bInterfaceNumber` of the MSC interface — the `wIndex` of
    /// the class-specific requests (GET MAX LUN, Mass Storage
    /// Reset).
    pub interface: u8,
    /// Block size reported by READ CAPACITY(10), or by
    /// READ CAPACITY(16) when the 10-byte form overflows.
    pub lba_bytes: u32,
    /// Last LBA reported by READ CAPACITY. This is a `u64`
    /// because a device over 2 TiB reports it through
    /// READ CAPACITY(16) (#832).
    pub last_lba: u64,
    /// Whether this LUN needs the 16-byte READ/WRITE CDBs:
    /// selected at attach when READ CAPACITY(16) reports a last
    /// LBA above the 32-bit range. Devices at or below 2 TiB keep
    /// the 10-byte forms.
    pub cmd16: bool,
    /// Bind generation, stamped by [`insert_device`] from a
    /// process-wide monotonic counter. Zero means "not yet
    /// inserted" (a freshly attached or test-constructed device);
    /// every live registry entry carries a unique non-zero value,
    /// and an adapter's transfer snapshot copies its entry's. [`UsbMscBlockDevice`] captures the
    /// generation at construction and refuses to operate when the
    /// entry at its index carries a different one, so a held
    /// adapter can never be silently retargeted at the next disk
    /// to reuse its index after a replug.
    pub generation: u64,
    /// Sequence counter for `dCBWTag` (matched by the device in CSW).
    tag: IrqSafeSpinLock<u32>,
    /// Hub context when this device sits behind a USB hub:
    /// (index into `crate::attach::HUBS`, downstream port).
    /// `None` for root-hub-attached devices (root ports are never
    /// idle-suspended) and for the legacy root enumerate path.
    /// The BOT funnels resume the port before a transfer and feed
    /// `crate::attach::mark_port_activity` on completion when this
    /// is `Some` — without it a hub-attached device wedges ~30 s
    /// after bind: the supervisor idle-suspends its port and
    /// nothing ever resumes it (#840).
    pub hub_port: Option<(usize, u8)>,
}

/// Walk a Configuration Descriptor (§9.6.3) tree looking for the
/// first interface whose `bInterfaceClass:SubClass:Protocol` matches
/// MSC BOT, plus its bulk-IN + bulk-OUT endpoints. Returns the
/// `EndpointConfig` for each direction so a caller can hand them
/// to `xhci::configure_endpoints`, plus the matching interface's
/// `bInterfaceNumber` (the `wIndex` of the class-specific BOT
/// requests).
///
/// `cfg` is the descriptor blob fetched via
/// `Xhci::get_config_descriptor`.
pub fn find_bot_endpoints(cfg: &[u8]) -> Result<(EndpointConfig, EndpointConfig, u8), MscError> {
    let mut i = 0usize;
    let mut in_match = false;
    let mut matched_interface = 0u8;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor (§9.6.5) — bLength 9, dtype 4.
            //   +2 bInterfaceNumber
            //   +5 bInterfaceClass
            //   +6 bInterfaceSubClass
            //   +7 bInterfaceProtocol
            4 if len >= 9 => {
                in_match = cfg[i + 5] == MSC_INTERFACE_CLASS
                    && cfg[i + 6] == MSC_INTERFACE_SUBCLASS
                    && cfg[i + 7] == MSC_INTERFACE_PROTOCOL;
                if in_match {
                    matched_interface = cfg[i + 2];
                }
            }
            // Endpoint Descriptor (§9.6.6) — bLength 7, dtype 5.
            //   +2 bEndpointAddress (bit 7 = IN)
            //   +3 bmAttributes (bits[1:0] = transfer type; 2 = bulk)
            //   +4..=5 wMaxPacketSize
            5 if len >= 7 && in_match => {
                let ep_addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                let xfer_t = attr & 0x03;
                let is_in = ep_addr & 0x80 != 0;
                if xfer_t == 2 {
                    let kind = if is_in {
                        EndpointKind::BulkIn
                    } else {
                        EndpointKind::BulkOut
                    };
                    let cfg_ep = EndpointConfig {
                        ep_addr,
                        max_packet: mps,
                        kind,
                        interval: 0,
                    };
                    if is_in {
                        bulk_in = Some(cfg_ep);
                    } else {
                        bulk_out = Some(cfg_ep);
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    match (bulk_in, bulk_out) {
        (Some(i), Some(o)) => Ok((i, o, matched_interface)),
        _ => Err(MscError::EndpointsMissing),
    }
}

/// GET MAX LUN for the interface at `slot_id` (BOT §3.3). A
/// device that does not implement the request stalls it (or
/// otherwise errors), which the spec reads as "LUN 0 only" — the
/// overwhelmingly common single-LUN stick. Any transport error
/// likewise degrades to LUN 0 rather than failing the bind: a
/// device with real extra LUNs answers this request.
async fn get_max_lun<T: BotTransport>(t: &T, slot_id: u8, interface: u8) -> u8 {
    let mut buf = [0u8; 1];
    match t
        .control_in(
            slot_id,
            0xA1,
            BOT_GET_MAX_LUN,
            0,
            u16::from(interface),
            &mut buf,
        )
        .await
    {
        Ok(n) if n >= 1 => buf[0].min(MAX_LUN_PROBE),
        _ => 0,
    }
}

/// Bind every LUN of an already addressed + configured MSC
/// interface: GET MAX LUN, then one [`MscDevice`] per LUN
/// (#831). A LUN whose READ CAPACITY fails on a multi-LUN device
/// is an empty card-reader slot and is skipped — its failure
/// must not take the populated slots down with it. On a
/// single-LUN device (or when *every* LUN fails) the error
/// propagates, preserving the historic bind contract. Caller
/// must have already run `xhci.configure_endpoints` for the bulk
/// pair returned by `find_bot_endpoints`.
pub async fn attach_all_luns<T: BotTransport>(
    t: &T,
    slot_id: u8,
    bulk_in: u8,
    bulk_out: u8,
    interface: u8,
) -> Result<Vec<MscDevice>, MscError> {
    let max_lun = get_max_lun(t, slot_id, interface).await;
    let mut devs = Vec::new();
    let mut last_err: Option<MscError> = None;
    for lun in 0..=max_lun {
        match MscDevice::attach_lun(t, slot_id, bulk_in, bulk_out, interface, lun).await {
            Ok(dev) => devs.push(dev),
            Err(e) => {
                if max_lun == 0 {
                    return Err(e);
                }
                last_err = Some(e);
            }
        }
    }
    if devs.is_empty() {
        return Err(last_err.unwrap_or(MscError::EndpointsMissing));
    }
    Ok(devs)
}

/// Which of the two bulk pipes a recovery step addresses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BotPipe {
    In,
    Out,
}

/// xHCI completion code 6 — Stall Error (xHCI §6.4.5, the
/// completion-code table): the device answered a bulk transfer
/// with a STALL handshake and halted the endpoint. Bulk
/// completions reach this driver as `XhciError::CmdFailed(code)`.
const XHCI_CC_STALL: u8 = 6;

/// Did this error come from a bulk endpoint STALL? That single
/// fact drives the whole recovery shape (#830): a stall is
/// cleared in-exchange and the conversation continues, where
/// other transport errors end the command.
fn is_stall(err: &MscError) -> bool {
    matches!(
        err,
        MscError::Xhci(xhci::XhciError::CmdFailed(XHCI_CC_STALL))
    )
}

/// Is this sense a transient condition the command should be
/// retried after, having drained it by reading the sense?
/// Exactly two cases (SPC-4 sense keys / ASC table):
///
/// - UNIT ATTENTION (key 0x6) — a power-on, reset, or
///   media-change event; the sense read that reported it clears
///   it, and the retried command runs against a settled unit.
/// - NOT READY (key 0x2) with ASC 0x04 — "logical unit in
///   process of becoming ready", i.e. a disk still spinning up.
///
/// Everything else — MEDIUM ERROR, DATA PROTECT, NOT READY with
/// ASC 0x3A "medium not present" — is a durable answer about the
/// medium, and retrying would just ask the same question again.
fn sense_is_retryable(sense: &narf_block::scsi::FixedSense) -> bool {
    sense.response_code == narf_block::scsi::FixedSense::RESPONSE_CODE_CURRENT
        && (sense.sense_key == narf_block::scsi::SENSE_KEY_UNIT_ATTENTION
            || (sense.sense_key == narf_block::scsi::SENSE_KEY_NOT_READY
                && sense.additional_sense_code == 0x04))
}

impl MscDevice {
    /// Bind one LUN of an already addressed + configured slot.
    /// Issues READ CAPACITY(10) — escalating to READ CAPACITY(16)
    /// when the 10-byte form overflows — so `lba_bytes`,
    /// `last_lba`, and the 10/16-byte command form are populated.
    /// Caller must have already run `xhci.configure_endpoints`
    /// for the bulk pair returned by `find_bot_endpoints`.
    pub async fn attach_lun<T: BotTransport>(
        t: &T,
        slot_id: u8,
        bulk_in: u8,
        bulk_out: u8,
        interface: u8,
        lun: u8,
    ) -> Result<Self, MscError> {
        let mut dev = MscDevice {
            slot_id,
            bulk_in,
            bulk_out,
            lun,
            interface,
            lba_bytes: 0,
            last_lba: 0,
            cmd16: false,
            generation: 0,
            tag: IrqSafeSpinLock::new(1),
            hub_port: None,
        };
        let (block_bytes, last_lba10) = dev.read_capacity_10(t).await?;
        dev.lba_bytes = block_bytes;
        dev.last_lba = u64::from(last_lba10);
        if last_lba10 == u32::MAX {
            // SBC-3 READ CAPACITY(10): a returned last LBA of
            // 0xFFFF_FFFF means the capacity does not fit the
            // 10-byte response (or ends exactly there). Ask again
            // with READ CAPACITY(16) and let its 64-bit last LBA
            // decide both the capacity and the command form.
            let (block_bytes16, last_lba16) = dev.read_capacity_16(t).await?;
            dev.lba_bytes = block_bytes16;
            dev.last_lba = last_lba16;
            dev.cmd16 = last_lba16 > u64::from(u32::MAX);
        }
        Ok(dev)
    }

    /// Allocate a fresh CBW tag.
    fn next_tag(&self) -> u32 {
        let mut g = self.tag.lock();
        let t = *g;
        *g = g.wrapping_add(1);
        t
    }

    /// Build a 31-byte CBW (§5.1 Table 5.1) addressed to this
    /// device's LUN.
    fn build_cbw(&self, tag: u32, data_len: u32, is_in: bool, cb: &[u8]) -> [u8; 31] {
        encode_cbw(tag, data_len, is_in, self.lun, cb)
    }

    /// Receive + parse a 13-byte CSW (§5.2 Table 5.2). Verifies the
    /// `b'USBS'` signature and returns the bCSWStatus byte (0=ok,
    /// 1=fail, 2=phase err) and the residue.
    async fn read_csw<T: BotTransport>(
        &self,
        t: &T,
        expect_tag: u32,
    ) -> Result<(u8, u32), MscError> {
        let mut buf = [0u8; 13];
        let n = t.bulk_in(self.slot_id, self.bulk_in, &mut buf).await?;
        if n < 13 {
            return Err(MscError::BadCsw);
        }
        let sig = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let tag = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let resid = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let status = buf[12];
        if sig != CSW_SIGNATURE || tag != expect_tag {
            return Err(MscError::BadCsw);
        }
        Ok((status, resid))
    }

    /// [`Self::read_csw`] with the status phase's own stall
    /// recovery: a device that has no CSW to give yet stalls
    /// bulk-IN instead; clearing the pipe (the full host + device
    /// halt clear) is what makes it produce the CSW, so clear and
    /// read once more before giving up on the status phase.
    async fn read_csw_resilient<T: BotTransport>(
        &self,
        t: &T,
        expect_tag: u32,
    ) -> Result<(u8, u32), MscError> {
        match self.read_csw(t, expect_tag).await {
            Ok(v) => Ok(v),
            Err(e) if is_stall(&e) => {
                self.clear_endpoint_halt(t, BotPipe::In).await;
                self.read_csw(t, expect_tag).await
            }
            Err(e) => Err(e),
        }
    }

    /// Clear a halted bulk endpoint end to end, the pairing
    /// `USBDevice::clear_endpoint_halt` established in this
    /// crate: host side first (Reset Endpoint + Set TR Dequeue,
    /// via the transport), then CLEAR_FEATURE(ENDPOINT_HALT) to
    /// clear the device-side halt and reset its data toggle, so
    /// host and device toggles restart together. Both steps are
    /// best-effort — recovery code runs when the device is
    /// already misbehaving, and the transfer that follows is the
    /// verdict on whether the pipe is usable again.
    async fn clear_endpoint_halt<T: BotTransport>(&self, t: &T, pipe: BotPipe) {
        let (dci, ep_addr) = match pipe {
            // DCI of IN endpoint n is 2n+1; of OUT endpoint n, 2n.
            BotPipe::In => (self.bulk_in, 0x80 | ((self.bulk_in - 1) / 2)),
            BotPipe::Out => (self.bulk_out, self.bulk_out / 2),
        };
        let _ = t.reset_halted_endpoint(self.slot_id, dci).await;
        let _ = t
            .control_out(
                self.slot_id,
                crate::control::RT_RECIP_ENDPOINT,
                crate::control::REQ_CLEAR_FEATURE,
                crate::control::FEATURE_ENDPOINT_HALT,
                u16::from(ep_addr),
                &[],
            )
            .await;
    }

    /// Reset Recovery (§5.3): the Mass Storage Reset class
    /// request, then a halt clear on both bulk endpoints. The
    /// spec's prescribed answer to a Phase Error — and to a CSW
    /// so desynchronised it cannot be parsed, which is a phase
    /// desync by another name. Best-effort throughout, like
    /// [`Self::clear_endpoint_halt`].
    async fn reset_recovery<T: BotTransport>(&self, t: &T) {
        let _ = t
            .control_out(
                self.slot_id,
                crate::control::RT_TYPE_CLASS | crate::control::RT_RECIP_INTERFACE,
                BOT_MASS_STORAGE_RESET,
                0,
                u16::from(self.interface),
                &[],
            )
            .await;
        self.clear_endpoint_halt(t, BotPipe::In).await;
        self.clear_endpoint_halt(t, BotPipe::Out).await;
    }

    /// One raw BOT exchange with no data stage: CBW, then CSW.
    /// Stall recovery *within* the exchange (a stalled phase is
    /// cleared and the status phase still runs) lives here;
    /// command-level recovery (sense drain, Reset Recovery,
    /// retry) lives in the `cmd_*` wrappers (#830).
    async fn bot_no_data<T: BotTransport>(&self, t: &T, cb: &[u8]) -> Result<(), MscError> {
        t.resume_hub_port(self.hub_port).await;
        let tag = self.next_tag();
        let cbw = self.build_cbw(tag, 0, false, cb);
        match t.bulk_out(self.slot_id, self.bulk_out, &cbw).await {
            Ok(_) => {}
            Err(e) if is_stall(&e) => {
                // The device stalled the CBW itself. Clear the
                // OUT pipe and still run the status phase: a
                // device that refuses a wrapper this way owes a
                // CSW saying so.
                self.clear_endpoint_halt(t, BotPipe::Out).await;
            }
            Err(e) => return Err(e),
        }
        let (status, _) = self.read_csw_resilient(t, tag).await?;
        check_csw_status(status)?;
        t.note_hub_activity(self.hub_port);
        Ok(())
    }

    /// One raw BOT exchange with a host-bound (IN) data stage:
    /// CBW, data, CSW. See [`Self::bot_no_data`] for the layering.
    async fn bot_data_in<T: BotTransport>(
        &self,
        t: &T,
        cb: &[u8],
        out: &mut [u8],
    ) -> Result<usize, MscError> {
        t.resume_hub_port(self.hub_port).await;
        let tag = self.next_tag();
        let cbw = self.build_cbw(tag, out.len() as u32, true, cb);
        let cbw_stalled = match t.bulk_out(self.slot_id, self.bulk_out, &cbw).await {
            Ok(_) => false,
            Err(e) if is_stall(&e) => {
                self.clear_endpoint_halt(t, BotPipe::Out).await;
                true
            }
            Err(e) => return Err(e),
        };
        let mut n = 0usize;
        if !cbw_stalled {
            match t.bulk_in(self.slot_id, self.bulk_in, out).await {
                Ok(m) => n = m,
                Err(e) if is_stall(&e) => {
                    // The classic BOT failure: the device stalls
                    // the data pipe instead of moving data. Clear
                    // the pipe; the status phase then reports the
                    // command's real outcome (and its sense).
                    self.clear_endpoint_halt(t, BotPipe::In).await;
                }
                Err(e) => return Err(e),
            }
        }
        let (status, _) = self.read_csw_resilient(t, tag).await?;
        check_csw_status(status)?;
        t.note_hub_activity(self.hub_port);
        Ok(n)
    }

    /// One raw BOT exchange with a device-bound (OUT) data
    /// stage: CBW, data, CSW. See [`Self::bot_no_data`].
    async fn bot_data_out<T: BotTransport>(
        &self,
        t: &T,
        cb: &[u8],
        data: &[u8],
    ) -> Result<usize, MscError> {
        t.resume_hub_port(self.hub_port).await;
        let tag = self.next_tag();
        let cbw = self.build_cbw(tag, data.len() as u32, false, cb);
        let cbw_stalled = match t.bulk_out(self.slot_id, self.bulk_out, &cbw).await {
            Ok(_) => false,
            Err(e) if is_stall(&e) => {
                self.clear_endpoint_halt(t, BotPipe::Out).await;
                true
            }
            Err(e) => return Err(e),
        };
        let mut n = 0usize;
        if !cbw_stalled {
            match t.bulk_out(self.slot_id, self.bulk_out, data).await {
                Ok(m) => n = m,
                Err(e) if is_stall(&e) => {
                    self.clear_endpoint_halt(t, BotPipe::Out).await;
                }
                Err(e) => return Err(e),
            }
        }
        let (status, _) = self.read_csw_resilient(t, tag).await?;
        check_csw_status(status)?;
        t.note_hub_activity(self.hub_port);
        Ok(n)
    }

    /// REQUEST SENSE as the recovery path uses it: one raw
    /// exchange (no recursive recovery), parsed into fixed-format
    /// sense. Reading the sense is itself the drain — a reported
    /// UNIT ATTENTION condition is cleared by the device once
    /// its sense data has been delivered.
    async fn request_sense_raw<T: BotTransport>(
        &self,
        t: &T,
    ) -> Result<narf_block::scsi::FixedSense, MscError> {
        // ALLOCATION LENGTH = 18 (fixed-format sense, SPC-4 Table 26).
        let cb = [SCSI_REQUEST_SENSE, 0, 0, 0, 18, 0];
        let mut out = [0u8; 18];
        let n = self.bot_data_in(t, &cb, &mut out).await?;
        if n < 18 {
            return Err(MscError::BadLength);
        }
        narf_block::scsi::FixedSense::parse(&out).map_err(|_| MscError::BadLength)
    }

    /// Command-level recovery for one failed BOT attempt (#830).
    /// `Ok(())` means "recovery performed — retry the attempt
    /// once"; `Err` is the final error to surface. The policy,
    /// per failure class:
    ///
    /// - **CSW status 1 (Command Failed):** fetch REQUEST SENSE.
    ///   UNIT ATTENTION (the power-on / reset / media-change
    ///   event every cheap bridge raises on first access) and
    ///   NOT READY / "becoming ready" (a disk still spinning up)
    ///   are transient by definition — the sense read drained
    ///   the condition, so retry. Anything else (medium error,
    ///   write-protect, absent medium, …) is the answer, not a
    ///   retry cue: surface it as [`MscError::Sense`].
    /// - **CSW status 2 (Phase Error) or an unparseable CSW:**
    ///   Reset Recovery (§5.3), then retry.
    /// - **Transport errors** (timeout, controller failure): no
    ///   spec recovery exists; surface as-is.
    ///
    /// If the sense fetch itself fails, the *original* command
    /// failure is surfaced — the recovery's failure must not
    /// mask why the command died.
    async fn recover_from_failure<T: BotTransport>(
        &self,
        t: &T,
        err: MscError,
    ) -> Result<(), MscError> {
        match err {
            MscError::CswStatus(1) => match self.request_sense_raw(t).await {
                Ok(sense) => {
                    if sense_is_retryable(&sense) {
                        Ok(())
                    } else {
                        Err(MscError::Sense(sense))
                    }
                }
                Err(_) => Err(err),
            },
            MscError::CswStatus(2) | MscError::BadCsw => {
                self.reset_recovery(t).await;
                Ok(())
            }
            other => Err(other),
        }
    }

    /// Run a SCSI command with no data stage, with command-level
    /// recovery (#830): one raw attempt, recovery, at most one
    /// retry. Used by TEST UNIT READY and SYNCHRONIZE CACHE(10).
    async fn cmd_no_data<T: BotTransport>(&self, t: &T, cb: &[u8]) -> Result<(), MscError> {
        match self.bot_no_data(t, cb).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.recover_from_failure(t, e).await?;
                self.bot_no_data(t, cb).await
            }
        }
    }

    /// Run a SCSI command with a host-bound (IN) data stage,
    /// with recovery as in [`Self::cmd_no_data`].
    async fn cmd_data_in<T: BotTransport>(
        &self,
        t: &T,
        cb: &[u8],
        out: &mut [u8],
    ) -> Result<usize, MscError> {
        match self.bot_data_in(t, cb, out).await {
            Ok(n) => Ok(n),
            Err(e) => {
                self.recover_from_failure(t, e).await?;
                self.bot_data_in(t, cb, out).await
            }
        }
    }

    /// Run a SCSI command with a device-bound (OUT) data stage,
    /// with recovery as in [`Self::cmd_no_data`].
    async fn cmd_data_out<T: BotTransport>(
        &self,
        t: &T,
        cb: &[u8],
        data: &[u8],
    ) -> Result<usize, MscError> {
        match self.bot_data_out(t, cb, data).await {
            Ok(n) => Ok(n),
            Err(e) => {
                self.recover_from_failure(t, e).await?;
                self.bot_data_out(t, cb, data).await
            }
        }
    }

    /// `TEST UNIT READY` (SBC-3 §5.34). 6-byte command, no data.
    /// Returns `Ok(())` if the device is ready to handle media
    /// access; a CSW status of 1 means the device wants the host
    /// to call REQUEST SENSE.
    pub async fn test_unit_ready<T: BotTransport>(&self, t: &T) -> Result<(), MscError> {
        self.cmd_no_data(t, &[SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0])
            .await
    }

    /// `REQUEST SENSE` (SPC-4 §6.28). Returns a fixed-format sense
    /// buffer (18 bytes). Use when TEST UNIT READY / any SCSI command
    /// returns CSW status 1 (Failed) — the sense data carries the
    /// SENSE KEY, ASC, and ASCQ that describe the error. Callers
    /// interested in CHECK CONDITION detail should call this next.
    /// This runs as one raw exchange: REQUEST SENSE *is* the
    /// recovery tool, so it does not itself re-enter the
    /// sense-drain recovery in the `cmd_*` funnels.
    pub async fn request_sense<T: BotTransport>(&self, t: &T) -> Result<[u8; 18], MscError> {
        // ALLOCATION LENGTH = 18 (fixed-format sense, SPC-4 Table 26).
        let cb = [SCSI_REQUEST_SENSE, 0, 0, 0, 18, 0];
        let mut out = [0u8; 18];
        let n = self.bot_data_in(t, &cb, &mut out).await?;
        if n < 18 {
            return Err(MscError::BadLength);
        }
        Ok(out)
    }

    /// `START STOP UNIT` (SBC-3 §5.25). `start=true` spins the medium
    /// up; `start=false` spins it down / ejects (LOEJ=1 in the CDB)
    /// when `eject=true`. Typical USB-stick eject: `start=false,
    /// eject=true`.
    pub async fn start_stop_unit<T: BotTransport>(
        &self,
        t: &T,
        start: bool,
        eject: bool,
    ) -> Result<(), MscError> {
        // CDB byte 4: LOEJ bit (bit 1) + START bit (bit 0).
        let flags: u8 = if eject { 0x02 } else { 0x00 } | if start { 0x01 } else { 0x00 };
        self.cmd_no_data(t, &[SCSI_START_STOP_UNIT, 0, 0, 0, flags, 0])
            .await
    }

    /// `SYNCHRONIZE CACHE(10)` (SBC-3) over the whole medium: ask
    /// the device to write every block sitting in its volatile
    /// write cache to the medium. Encoded with LBA = 0 and
    /// NUMBER OF BLOCKS = 0, which SBC-3 defines as "all blocks
    /// from the LBA to the end of the medium" — a whole-device
    /// flush. The IMD bit is clear, so the CSW only reports
    /// completion once the flush has actually finished; a
    /// non-zero CSW status surfaces as [`MscError::CswStatus`]
    /// (a failed flush must never read as success — #829).
    pub async fn synchronize_cache<T: BotTransport>(&self, t: &T) -> Result<(), MscError> {
        self.cmd_no_data(t, &encode_synchronize_cache10()).await
    }

    /// `INQUIRY` (SPC-4 §6.5). Returns the standard 36-byte INQUIRY
    /// response (vendor / product / revision / etc.).
    pub async fn inquiry<T: BotTransport>(&self, t: &T) -> Result<[u8; 36], MscError> {
        let cb = [SCSI_INQUIRY, 0, 0, 0, 36, 0];
        let mut out = [0u8; 36];
        let n = self.cmd_data_in(t, &cb, &mut out).await?;
        if n < 36 {
            return Err(MscError::BadLength);
        }
        Ok(out)
    }

    /// `READ CAPACITY(10)` (SBC-3 §5.16). Returns
    /// `(block_bytes, last_lba)` — the device's reported block size
    /// and the index of the last addressable LBA.
    pub async fn read_capacity_10<T: BotTransport>(&self, t: &T) -> Result<(u32, u32), MscError> {
        let cb = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut out = [0u8; 8];
        let n = self.cmd_data_in(t, &cb, &mut out).await?;
        if n < 8 {
            return Err(MscError::BadLength);
        }
        // Big-endian fields per SBC-3 Table 56.
        let last_lba = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
        let blocksz = u32::from_be_bytes([out[4], out[5], out[6], out[7]]);
        Ok((blocksz, last_lba))
    }

    /// `READ CAPACITY(16)` (SBC-3 §5.16.2). Returns
    /// `(block_bytes, last_lba)` with a 64-bit last LBA. Issued
    /// at attach only when READ CAPACITY(10) reports
    /// `0xFFFF_FFFF`, the standard's signal that the capacity
    /// does not fit the 10-byte response (#832). The CDB and
    /// response parser are the shared T10 codecs in
    /// `narf_block::scsi`.
    pub async fn read_capacity_16<T: BotTransport>(&self, t: &T) -> Result<(u32, u64), MscError> {
        let cb = narf_block::scsi::read_capacity_16(32);
        let mut out = [0u8; 32];
        let n = self.cmd_data_in(t, &cb, &mut out).await?;
        if n < 12 {
            return Err(MscError::BadLength);
        }
        let (last_lba, blocksz, _prot) =
            narf_block::scsi::parse_read_capacity_16(&out[..n]).map_err(|_| MscError::BadLength)?;
        Ok((blocksz, last_lba))
    }

    /// Build the READ CDB this LUN uses: READ(16) when the
    /// device crossed the 32-bit capacity boundary at attach,
    /// READ(10) otherwise. Returns the CDB bytes and their
    /// length (the backing array is sized for the 16-byte form).
    fn read_cdb(&self, lba: u64, nblocks: u32) -> Result<([u8; 16], usize), MscError> {
        if self.cmd16 {
            let cb = encode_read16(lba, nblocks);
            Ok((cb, cb.len()))
        } else {
            if lba > u64::from(u32::MAX) || nblocks > u32::from(u16::MAX) {
                return Err(MscError::BadLength);
            }
            let cb10 = encode_read10(lba as u32, nblocks as u16);
            let mut cb = [0u8; 16];
            cb[..10].copy_from_slice(&cb10);
            Ok((cb, 10))
        }
    }

    /// WRITE counterpart of [`Self::read_cdb`], with the FUA bit
    /// carried in byte 1 of either form.
    fn write_cdb(&self, lba: u64, nblocks: u32, fua: bool) -> Result<([u8; 16], usize), MscError> {
        if self.cmd16 {
            let cb = if fua {
                encode_write16_fua(lba, nblocks)
            } else {
                encode_write16(lba, nblocks)
            };
            Ok((cb, cb.len()))
        } else {
            if lba > u64::from(u32::MAX) || nblocks > u32::from(u16::MAX) {
                return Err(MscError::BadLength);
            }
            let cb10 = if fua {
                encode_write10_fua(lba as u32, nblocks as u16)
            } else {
                encode_write10(lba as u32, nblocks as u16)
            };
            let mut cb = [0u8; 16];
            cb[..10].copy_from_slice(&cb10);
            Ok((cb, 10))
        }
    }

    /// `READ(10)` or `READ(16)` for a single block, selected by
    /// the LUN's attach-time capacity form. Returns the
    /// `lba_bytes`-sized data buffer. (SBC-3 READ(10) / READ(16).)
    pub async fn read_block<T: BotTransport>(&self, t: &T, lba: u64) -> Result<Vec<u8>, MscError> {
        if self.lba_bytes == 0 || self.lba_bytes as usize > 4096 {
            return Err(MscError::BadLength);
        }
        let (cb, cb_len) = self.read_cdb(lba, 1)?;
        let mut out = alloc::vec![0u8; self.lba_bytes as usize];
        let n = self.cmd_data_in(t, &cb[..cb_len], &mut out[..]).await?;
        if n != self.lba_bytes as usize {
            return Err(MscError::BadLength);
        }
        Ok(out)
    }

    /// `WRITE(10)` or `WRITE(16)` for a single block, selected
    /// like [`Self::read_block`]. (SBC-3 WRITE(10) / WRITE(16).)
    pub async fn write_block<T: BotTransport>(
        &self,
        t: &T,
        lba: u64,
        data: &[u8],
    ) -> Result<(), MscError> {
        if data.len() != self.lba_bytes as usize {
            return Err(MscError::BadLength);
        }
        let (cb, cb_len) = self.write_cdb(lba, 1, false)?;
        let n = self.cmd_data_out(t, &cb[..cb_len], data).await?;
        if n != data.len() {
            return Err(MscError::BadLength);
        }
        Ok(())
    }

    /// How many blocks one BOT command may carry for this LUN:
    /// the per-command cap, further bounded so the data stage
    /// fits the xHCI endpoint's single-page DMA buffer.
    fn bot_chunk_blocks(&self) -> u32 {
        (MSC_DMA_PAGE_BYTES / self.lba_bytes.max(1)).min(u32::from(MSC_MAX_BLOCKS_PER_XFER))
    }

    /// Multi-block READ. Reads `nblocks` consecutive blocks
    /// starting at `lba`, in the LUN's 10- or 16-byte command
    /// form. Requests of any size are chunked internally into
    /// per-command pieces of at most `bot_chunk_blocks()` blocks
    /// (#828) — the 8-block shape of one BOT command is a wire
    /// detail, not a caller-visible limit. Returns the
    /// concatenated payload.
    pub async fn read_blocks<T: BotTransport>(
        &self,
        t: &T,
        lba: u64,
        nblocks: u32,
    ) -> Result<Vec<u8>, MscError> {
        if self.lba_bytes == 0 || nblocks == 0 {
            return Err(MscError::BadLength);
        }
        let total = (self.lba_bytes as usize)
            .checked_mul(nblocks as usize)
            .ok_or(MscError::BadLength)?;
        let mut out: Vec<u8> = alloc::vec![0u8; total];
        self.read_blocks_into(t, lba, &mut out).await?;
        Ok(out)
    }

    /// Buffer-filling form of [`Self::read_blocks`]: reads whole
    /// blocks into `out` (whose length must be a non-zero multiple
    /// of the block size), chunking as described there. The block
    /// adapter uses this form so a large filesystem request never
    /// materialises a second full-size buffer.
    pub async fn read_blocks_into<T: BotTransport>(
        &self,
        t: &T,
        lba: u64,
        out: &mut [u8],
    ) -> Result<(), MscError> {
        if self.lba_bytes == 0 || out.is_empty() || out.len() % self.lba_bytes as usize != 0 {
            return Err(MscError::BadLength);
        }
        let chunk = self.bot_chunk_blocks();
        let mut done_blocks: u64 = 0;
        let mut offset = 0usize;
        while offset < out.len() {
            let remaining = ((out.len() - offset) / self.lba_bytes as usize) as u64;
            let count = remaining.min(u64::from(chunk));
            let chunk_lba = lba.checked_add(done_blocks).ok_or(MscError::BadLength)?;
            let (cb, cb_len) = self.read_cdb(chunk_lba, count as u32)?;
            let bytes = (count as usize) * self.lba_bytes as usize;
            let n = self
                .cmd_data_in(t, &cb[..cb_len], &mut out[offset..offset + bytes])
                .await?;
            if n != bytes {
                return Err(MscError::BadLength);
            }
            done_blocks += count;
            offset += bytes;
        }
        Ok(())
    }

    /// Multi-block WRITE. Writes `nblocks` blocks starting at
    /// `lba`, in the LUN's 10- or 16-byte command form, chunked
    /// internally exactly like [`Self::read_blocks`](#828).
    /// `data.len()` must equal `nblocks * lba_bytes`.
    pub async fn write_blocks<T: BotTransport>(
        &self,
        t: &T,
        lba: u64,
        nblocks: u32,
        data: &[u8],
    ) -> Result<(), MscError> {
        self.write_blocks_inner(t, lba, nblocks, data, false).await
    }

    /// Multi-block WRITE with Force Unit Access: identical to
    /// [`Self::write_blocks`] except every chunk's CDB carries
    /// the FUA bit, so the device must commit the data to the
    /// medium (not merely to its volatile write cache) before
    /// each CSW reports completion. FUA orders nothing written
    /// earlier — callers that need a barrier issue
    /// [`Self::synchronize_cache`] first (the block layer's
    /// `write_fua` contract, #829).
    pub async fn write_blocks_fua<T: BotTransport>(
        &self,
        t: &T,
        lba: u64,
        nblocks: u32,
        data: &[u8],
    ) -> Result<(), MscError> {
        self.write_blocks_inner(t, lba, nblocks, data, true).await
    }

    async fn write_blocks_inner<T: BotTransport>(
        &self,
        t: &T,
        lba: u64,
        nblocks: u32,
        data: &[u8],
        fua: bool,
    ) -> Result<(), MscError> {
        if self.lba_bytes == 0 || nblocks == 0 {
            return Err(MscError::BadLength);
        }
        let total = (self.lba_bytes as usize)
            .checked_mul(nblocks as usize)
            .ok_or(MscError::BadLength)?;
        if data.len() != total {
            return Err(MscError::BadLength);
        }
        let chunk = self.bot_chunk_blocks();
        let mut done_blocks: u64 = 0;
        let mut offset = 0usize;
        while offset < data.len() {
            let remaining = ((data.len() - offset) / self.lba_bytes as usize) as u64;
            let count = remaining.min(u64::from(chunk));
            let chunk_lba = lba.checked_add(done_blocks).ok_or(MscError::BadLength)?;
            let (cb, cb_len) = self.write_cdb(chunk_lba, count as u32, fua)?;
            let bytes = (count as usize) * self.lba_bytes as usize;
            let n = self
                .cmd_data_out(t, &cb[..cb_len], &data[offset..offset + bytes])
                .await?;
            if n != bytes {
                return Err(MscError::BadLength);
            }
            done_blocks += count;
            offset += bytes;
        }
        Ok(())
    }
}

// ── Hot-plug enumeration ──────────────────────────────────────────

/// System-wide registry of attached USB Mass Storage devices.
/// Populated by `enumerate_and_attach_msc` and
/// `try_bind_msc_already_addressed`; consumed by the
/// `block::BlockDeviceSync` adapter once one is wired up.
///
/// Entries are tombstoned (`None`) by [`detach_msc`], never shifted:
/// a [`UsbMscBlockDevice`] adapter and its block-layer name
/// (`usb-msc{idx}`) hold the index for the device's whole lifetime,
/// so a removal must not renumber the survivors. A later bind
/// reuses the first tombstone (see [`insert_device`]), which keeps
/// the published name stable across an unplug/replug cycle. Index
/// reuse is safe for held adapters only because each entry carries
/// a bind generation (see [`MscDevice::generation`]): an adapter
/// captured from a previous occupant of the index fails
/// `DeviceRemoved` instead of being retargeted at the new disk.
pub static MSC_DEVICES: IrqSafeSpinLock<Vec<Option<MscDevice>>> = IrqSafeSpinLock::new(Vec::new());

/// Monotonic bind-generation source for [`MscDevice::generation`].
/// Incremented once per [`insert_device`] and never reused, so a
/// generation identifies one *bind*, not one disk: even the same
/// physical device detached and rebound gets a fresh generation,
/// and adapters held from its earlier bind stay stale.
static MSC_BIND_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Insert a freshly bound device, reusing the first tombstoned
/// slot when one exists so indices (and therefore `usb-msc{idx}`
/// names) stay bounded and stable across replug. Stamps the device
/// with the next bind generation before publishing it. Returns
/// the index.
fn insert_device(mut dev: MscDevice) -> usize {
    dev.generation = MSC_BIND_GENERATION.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
    let mut g = MSC_DEVICES.lock();
    if let Some((idx, slot)) = g.iter_mut().enumerate().find(|(_, s)| s.is_none()) {
        *slot = Some(dev);
        idx
    } else {
        g.push(Some(dev));
        g.len() - 1
    }
}

/// Bind to an already-addressed device using its full configuration
/// descriptor `cfg`. Returns the new device's index in
/// [`MSC_DEVICES`] on success; the caller can then look it up to
/// register block / partition entries. On failure the slot is
/// disabled by the caller (`dispatch_after_address` handles that).
///
/// Caller's responsibility: the device is post-`address_device`
/// and `cfg` is the full GET_DESCRIPTOR(CONFIG) blob (so we don't
/// re-issue the control transfer).
///
/// `hub_port` is the device's hub context — (index into
/// `crate::attach::HUBS`, downstream port) — when it sits behind
/// a hub, `None` on a root port. Recorded on the device so its
/// BOT transfers can resume / feed its port (#840).
pub async fn try_bind_msc_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    cfg: &[u8],
    hub_port: Option<(usize, u8)>,
) -> Result<usize, MscError> {
    let (ep_in, ep_out, interface) = find_bot_endpoints(cfg)?;
    // SET_CONFIGURATION before any class-specific request (USB 2.0
    // §9.4.7). Use cfg value 1 — every MSC device the bring-up arc
    // targets ships a single config at value 1.
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };
    if xhci_dev
        .control_out(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .is_err()
    {
        return Err(MscError::EndpointsMissing);
    }
    xhci_dev
        .configure_endpoints(slot_id, &[ep_in, ep_out])
        .await
        .map_err(MscError::Xhci)?;
    let bulk_in_dci = ((ep_in.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (ep_out.ep_addr & 0x0F) * 2; // xHCI OUT DCI: ep_num * 2
                                                    // One device instance per LUN (#831): GET MAX LUN, then a
                                                    // READ CAPACITY conversation per LUN inside attach_all_luns.
    let devs = attach_all_luns(xhci_dev, slot_id, bulk_in_dci, bulk_out_dci, interface).await?;
    let mut first_idx = None;
    for mut dev in devs {
        // Record the hub context *after* attach: the READ
        // CAPACITY(10) inside attach runs before the supervisor
        // marks the port bound, and idle-suspend only ever targets
        // bound ports — the port cannot be suspended yet, so that
        // first transaction needs no resume.
        dev.hub_port = hub_port;
        let idx = insert_device(dev);
        // Register against the block layer + scan partitions. Done
        // inline so the post-bind state (block device visible +
        // per-partition sub-devices registered) is established
        // before the caller's supervisor cycle moves on. Failure
        // here doesn't unbind the MSC device — the raw bulk path
        // still works through `with_device`; the block-layer view
        // is best-effort. Each LUN registers under its own index,
        // so a multi-slot reader publishes one `usb-msc{idx}` per
        // populated slot.
        register_msc_block_device(idx);
        if first_idx.is_none() {
            first_idx = Some(idx);
        }
    }
    // attach_all_luns only succeeds with at least one LUN bound.
    Ok(first_idx.unwrap_or(0))
}

/// Per-index cache of the leaked `usb-msc{idx}` block names. The
/// block registry's `&'static str` interface forces a leak per
/// distinct name; caching by index means an unplug/replug cycle
/// re-registers the identical string instead of leaking a fresh
/// copy of the same text every time.
static MSC_BLOCK_NAMES: IrqSafeSpinLock<Vec<&'static str>> = IrqSafeSpinLock::new(Vec::new());

/// The block-layer name for MSC_DEVICES[idx], leaked once and then
/// reused for every (re)registration of that index.
fn msc_block_name(idx: usize) -> &'static str {
    let mut g = MSC_BLOCK_NAMES.lock();
    while g.len() <= idx {
        let n = g.len();
        g.push(alloc::boxed::Box::leak(
            alloc::format!("usb-msc{}", n).into_boxed_str(),
        ));
    }
    g[idx]
}

/// Register MSC_DEVICES[idx] as a block-layer device under
/// `usb-msc{idx}` and run the partition scanner so child entries
/// like `usb-msc0p1` appear.
pub fn register_msc_block_device(idx: usize) {
    let dev = match UsbMscBlockDevice::from_index(idx) {
        Some(d) => d,
        None => return,
    };
    let static_name = msc_block_name(idx);
    let arc: alloc::sync::Arc<dyn narf_block::BlockDeviceSync> = alloc::sync::Arc::new(dev);
    narf_block::register_block_device(static_name, arc.clone());
    let _ = narf_block::partition::scan_and_register_partitions(arc, static_name);
}

/// Withdraw MSC_DEVICES[idx]'s block-layer publication: unregister
/// the partition children first, then the disk itself.
/// `narf_block::unregister_block_device` removes a single entry and
/// has no cascade, so the children are snapshotted from the
/// registry (entries whose `parent` is this disk) before the disk
/// entry goes. Safe to call for an index that was never registered.
pub fn unregister_msc_block_device(idx: usize) {
    let name = msc_block_name(idx);
    let children: Vec<&'static str> = narf_block::block_devices()
        .iter()
        .filter(|e| e.parent == Some(name))
        .map(|e| e.name)
        .collect();
    for child in children {
        narf_block::unregister_block_device(child);
    }
    narf_block::unregister_block_device(name);
}

/// Detach every MSC device bound to xHCI `slot_id`: tombstone its
/// [`MSC_DEVICES`] entry and withdraw its block-layer publication.
///
/// This is the per-class publication teardown for MSC, invoked on
/// the supervisor's detach path via the class registry's unbind
/// dispatch (`attach::detach_slot` →
/// `class_registry::dispatch_unbind`, registered by
/// [`register_initcalls`]). Tombstoning happens before the block
/// unregister and the registry lock is released in between, so an
/// in-flight `UsbMscBlockDevice` read/write that still holds the
/// (about-to-be-unregistered) adapter fails cleanly with
/// `BlockIoError::DeviceRemoved` instead of driving a dead slot.
/// The tombstone is only a liveness check, though — it covers the
/// window until the next bind, and [`insert_device`] deliberately
/// reuses the first tombstone, so a replugged disk lands on the
/// same index. The identity check for that window is the bind
/// generation ([`MscDevice::generation`]): the adapter compares
/// its captured generation against the live entry on every op
/// and fails `DeviceRemoved` on mismatch, so a filesystem that
/// keeps its adapter across an unplug/replug is never silently
/// served by the new disk. Idempotent: detaching an unbound slot
/// is a no-op.
pub fn detach_msc(slot_id: u8) {
    let mut indices = Vec::new();
    {
        let mut g = MSC_DEVICES.lock();
        for (idx, slot) in g.iter_mut().enumerate() {
            if slot.as_ref().is_some_and(|d| d.slot_id == slot_id) {
                *slot = None;
                indices.push(idx);
            }
        }
    }
    for idx in indices {
        unregister_msc_block_device(idx);
    }
}

/// Wholesale variant of [`detach_msc`]: tombstone and unpublish
/// every bound MSC device regardless of slot. This is the MSC half
/// of controller-recovery teardown; the supervisor's epoch path
/// (`attach::detach_all_bindings`) should call it alongside the
/// pumped classes it already clears.
pub fn unbind_all_msc() {
    let mut indices = Vec::new();
    {
        let mut g = MSC_DEVICES.lock();
        for (idx, slot) in g.iter_mut().enumerate() {
            if slot.is_some() {
                *slot = None;
                indices.push(idx);
            }
        }
    }
    for idx in indices {
        unregister_msc_block_device(idx);
    }
}

// ── Class-registry unbind registration ────────────────────────────

/// Class-registry match for MSC Bulk-Only Transport (the
/// `MSC_INTERFACE_*` triple). Binding itself is owned by the attach
/// cascade in `attach::dispatch_after_address`, which runs before
/// `class_registry::dispatch_probe`; this entry exists so the
/// registry's unbind dispatch can reach [`detach_msc`].
const MSC_CLASS_MATCH: [crate::class_registry::UsbClassMatch; 1] =
    [crate::class_registry::UsbClassMatch {
        vendor_id: 0,
        product_id: 0,
        class: Some(MSC_INTERFACE_CLASS),
        subclass: Some(MSC_INTERFACE_SUBCLASS),
        protocol: Some(MSC_INTERFACE_PROTOCOL),
    }];

/// Registry probe for MSC. A device only reaches `dispatch_probe`
/// when the attach cascade's real (async) bind already declined or
/// failed — the registry probe is synchronous and cannot run the
/// BOT bring-up — so it reports `BindFailed` and the dispatcher
/// falls through to the same terminal-mismatch handling the device
/// would have seen before this entry existed.
fn msc_registry_probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    Err(crate::class_registry::UsbProbeError::BindFailed)
}

/// Register MSC's unbind hook with the class registry. Called from
/// the crate's Stage::Subsys initcalls (`lib.rs`).
pub fn register_initcalls() {
    let _ = crate::class_registry::register_class_driver_with_unbind(
        "usb-msc",
        &MSC_CLASS_MATCH,
        msc_registry_probe,
        detach_msc,
    );
}

/// Walk every connected port on the supplied xHCI controller and
/// try to bring up an MSC BOT device on each one. Per-port flow
/// mirrors the HID keyboard path: port_reset → enable_slot →
/// address_device → fetch CONFIG → `find_bot_endpoints` →
/// configure_endpoints → `MscDevice::attach` (which also issues
/// READ CAPACITY(10)).
///
/// Returns the count of devices successfully attached. Per-port
/// failures are skipped silently.
pub async fn enumerate_and_attach_msc(xhci_dev: &Xhci) -> usize {
    let mut attached = 0usize;
    for (port, _portsc) in xhci_dev.connected_ports() {
        if try_attach_msc_port(xhci_dev, port).await.is_ok() {
            attached += 1;
        }
    }
    attached
}

async fn try_attach_msc_port(xhci_dev: &Xhci, port: u8) -> Result<(), MscError> {
    xhci_dev.port_reset(port).await.map_err(MscError::Xhci)?;
    let speed = xhci_dev
        .port_speed(port)
        .ok_or(MscError::EndpointsMissing)?;
    let slot_id = xhci_dev.enable_slot().await.map_err(MscError::Xhci)?;
    // Wrap the post-enable_slot enumeration so we always free the
    // controller-allocated slot if anything fails (was a leak that
    // bound port→slot until the next HCRST and tripped a later
    // Address Device on the same port with TRB Error "port already
    // assigned"). Best-effort disable_slot — the real failure code
    // is what matters.
    let result = async {
        xhci_dev
            .address_device(slot_id, port, speed)
            .await
            .map_err(MscError::Xhci)?;

        // Read 9-byte cfg header for wTotalLength.
        let mut head = [0u8; 9];
        let n = xhci_dev
            .get_config_descriptor(slot_id, 0, &mut head)
            .await?;
        if n < 9 {
            return Err(MscError::NotMsc);
        }
        let total = u16::from_le_bytes([head[2], head[3]]) as usize;
        if !(9..=4096).contains(&total) {
            return Err(MscError::NotMsc);
        }

        // Pull the full descriptor tree.
        let mut full = alloc::vec![0u8; total];
        let n2 = xhci_dev
            .get_config_descriptor(slot_id, 0, &mut full)
            .await?;
        if n2 < total {
            full.truncate(n2);
        }

        let (ep_in, ep_out, interface) = find_bot_endpoints(&full)?;
        xhci_dev
            .configure_endpoints(slot_id, &[ep_in, ep_out])
            .await
            .map_err(MscError::Xhci)?;

        let bulk_in_dci = ((ep_in.ep_addr & 0x0F) * 2) + 1;
        let bulk_out_dci = (ep_out.ep_addr & 0x0F) * 2; // xHCI OUT DCI: ep_num * 2
        attach_all_luns(xhci_dev, slot_id, bulk_in_dci, bulk_out_dci, interface).await
    }
    .await;
    match result {
        Ok(devs) => {
            for dev in devs {
                insert_device(dev);
            }
            Ok(())
        }
        Err(e) => {
            let _ = xhci_dev.disable_slot(slot_id).await;
            Err(e)
        }
    }
}

/// Number of MSC devices currently bound (tombstones excluded).
pub fn attached_msc_count() -> usize {
    MSC_DEVICES.lock().iter().filter(|s| s.is_some()).count()
}

/// Run a closure against an attached MSC device by index; returns
/// `None` if `idx` is out of range or the entry was detached. The
/// closure runs while the global registry is locked, so don't
/// perform xHCI traffic that re-enters MSC bookkeeping.
pub fn with_device<R>(idx: usize, f: impl FnOnce(&MscDevice) -> R) -> Option<R> {
    let g = MSC_DEVICES.lock();
    g.get(idx).and_then(|slot| slot.as_ref()).map(f)
}

#[doc(hidden)]
pub fn __reset_msc_for_test() {
    MSC_DEVICES.lock().clear();
}

/// Test-only: insert a synthetic device for `slot_id` through the
/// real index-allocation path and publish its block device, without
/// any xHCI traffic. The fabricated capacity (2048 × 512 B) is never
/// read back by the fixture — the partition scan inside
/// [`register_msc_block_device`] fails harmlessly when no live
/// controller answers for the slot — so fixtures can exercise
/// bind → detach → replug publication state on any test kernel.
#[doc(hidden)]
pub fn __insert_msc_for_test(slot_id: u8) -> usize {
    let dev = MscDevice {
        slot_id,
        bulk_in: 3,
        bulk_out: 2,
        lun: 0,
        interface: 0,
        lba_bytes: 512,
        last_lba: 2047,
        cmd16: false,
        generation: 0,
        tag: IrqSafeSpinLock::new(1),
        hub_port: None,
    };
    let idx = insert_device(dev);
    register_msc_block_device(idx);
    idx
}

// ── Protocol codec helpers (pub for unit tests) ────────────────────

/// Encode a 31-byte CBW (§5.1 Table 5.1).
///
/// `tag` identifies this transaction and is echoed back in the CSW.
/// `data_len` is the expected transfer length in bytes.  `is_in` sets
/// bit 7 of `bmCBWFlags` (1 = data flows from device to host).
/// `lun` is the target logical unit (`bCBWLUN`, §5.1) — 0 for the
/// single-LUN devices that dominate, the slot index for a
/// multi-LUN card reader (#831).
/// `cb` is the SCSI command descriptor block; at most 16 bytes are
/// copied into `CBWCB[16]`.
pub fn encode_cbw(tag: u32, data_len: u32, is_in: bool, lun: u8, cb: &[u8]) -> [u8; 31] {
    let mut out = [0u8; 31];
    out[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    out[4..8].copy_from_slice(&tag.to_le_bytes());
    out[8..12].copy_from_slice(&data_len.to_le_bytes());
    out[12] = if is_in { CBW_FLAG_IN } else { 0 };
    out[13] = lun; // bCBWLUN
    out[14] = (cb.len() as u8) & 0x1F; // bCBWCBLength (low 5 bits)
    let n = cb.len().min(16);
    out[15..15 + n].copy_from_slice(&cb[..n]);
    out
}

/// Decoded fields of a 13-byte CSW (§5.2 Table 5.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CswFields {
    /// Echo of the CBW `dCBWTag`.
    pub tag: u32,
    /// Difference between `dCBWDataTransferLength` and the actual
    /// bytes transferred.
    pub residue: u32,
    /// 0 = Command Passed, 1 = Command Failed, 2 = Phase Error.
    pub status: u8,
}

/// Decode a 13-byte CSW buffer. Returns `None` if the buffer is
/// shorter than 13 bytes or the `dCSWSignature` (`b'USBS'`) doesn't
/// match. The caller still needs to verify `tag` echoes the CBW tag.
pub fn decode_csw(buf: &[u8]) -> Option<CswFields> {
    if buf.len() < 13 {
        return None;
    }
    let sig = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if sig != CSW_SIGNATURE {
        return None;
    }
    let tag = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let residue = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let status = buf[12];
    Some(CswFields {
        tag,
        residue,
        status,
    })
}

/// Map a CSW `bCSWStatus` byte to the transport result: 0
/// (Command Passed) is `Ok`; 1 (Command Failed) and 2 (Phase
/// Error) become [`MscError::CswStatus`]. Every BOT exchange in
/// this module funnels through here, so a device that refuses a
/// command — a SYNCHRONIZE CACHE it cannot honour, say — can
/// never be mistaken for success by a caller (#829).
pub fn check_csw_status(status: u8) -> Result<(), MscError> {
    if status != 0 {
        return Err(MscError::CswStatus(status));
    }
    Ok(())
}

/// Encode a READ(10) CDB (SBC-3 §5.10). Returns the 10-byte
/// command descriptor block. `lba` and `nblocks` are big-endian
/// in the wire format.
pub fn encode_read10(lba: u32, nblocks: u16) -> [u8; 10] {
    let lba_be = lba.to_be_bytes();
    let nb = nblocks.to_be_bytes();
    [
        SCSI_READ_10,
        0,
        lba_be[0],
        lba_be[1],
        lba_be[2],
        lba_be[3],
        0,
        nb[0],
        nb[1],
        0,
    ]
}

/// Encode a WRITE(10) CDB (SBC-3 §5.27). Returns the 10-byte
/// command descriptor block. `lba` and `nblocks` are big-endian.
pub fn encode_write10(lba: u32, nblocks: u16) -> [u8; 10] {
    let lba_be = lba.to_be_bytes();
    let nb = nblocks.to_be_bytes();
    [
        SCSI_WRITE_10,
        0,
        lba_be[0],
        lba_be[1],
        lba_be[2],
        lba_be[3],
        0,
        nb[0],
        nb[1],
        0,
    ]
}

/// Encode a WRITE(10) CDB with Force Unit Access set (byte 1
/// bit 3): the device must commit the data to the medium before
/// completing the command. Otherwise identical to
/// [`encode_write10`].
pub fn encode_write10_fua(lba: u32, nblocks: u16) -> [u8; 10] {
    let mut cb = encode_write10(lba, nblocks);
    cb[1] = WRITE10_FUA;
    cb
}

/// Encode a READ(16) CDB (SBC-3 READ(16)): opcode 0x88, the
/// 64-bit LBA big-endian at bytes 2..10, and the 32-bit transfer
/// length (in blocks) big-endian at bytes 10..14. Used for LUNs
/// whose capacity crossed the 32-bit boundary (#832).
pub fn encode_read16(lba: u64, nblocks: u32) -> [u8; 16] {
    let mut cb = [0u8; 16];
    cb[0] = SCSI_READ_16;
    cb[2..10].copy_from_slice(&lba.to_be_bytes());
    cb[10..14].copy_from_slice(&nblocks.to_be_bytes());
    cb
}

/// Encode a WRITE(16) CDB (SBC-3 WRITE(16)): opcode 0x8A, with
/// the same LBA / transfer-length layout as [`encode_read16`].
pub fn encode_write16(lba: u64, nblocks: u32) -> [u8; 16] {
    let mut cb = encode_read16(lba, nblocks);
    cb[0] = SCSI_WRITE_16;
    cb
}

/// Encode a WRITE(16) CDB with Force Unit Access set (byte 1
/// bit 3), the 16-byte counterpart of [`encode_write10_fua`].
pub fn encode_write16_fua(lba: u64, nblocks: u32) -> [u8; 16] {
    let mut cb = encode_write16(lba, nblocks);
    cb[1] = WRITE10_FUA;
    cb
}

/// Encode a SYNCHRONIZE CACHE(10) CDB (SBC-3) for a whole-medium
/// flush: LBA = 0 and NUMBER OF BLOCKS = 0, which the standard
/// defines as "all blocks from the LBA to the end of the medium".
/// Byte 1 is zero — in particular IMD is clear, so the device
/// reports completion only after the flush has finished.
pub fn encode_synchronize_cache10() -> [u8; 10] {
    [SCSI_SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// Decode a READ CAPACITY(10) response buffer (SBC-3 Table 56).
/// Returns `(block_size_bytes, last_lba)`.  Both fields are
/// big-endian on the wire. Returns `None` if `buf` is shorter
/// than 8 bytes.
pub fn decode_read_capacity10(buf: &[u8]) -> Option<(u32, u32)> {
    if buf.len() < 8 {
        return None;
    }
    let last_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Some((block_size, last_lba))
}

// ── BlockDeviceSync adapter ────────────────────────────────────────
//
// Wraps an index into MSC_DEVICES + a cached (lba_size, capacity)
// so the BlockDeviceSync interface — which doesn't take &Xhci —
// can still drive the per-block READ/WRITE 10 transactions. Each
// read/write reaches back through xhci::with_controller and
// msc::with_device for the actual transfer.

/// Block-layer adapter for a bound USB MSC device. Constructed from
/// an MSC_DEVICES index by the supervisor / boot path; registered
/// against narf_block::register_block_device as `"usb-msc{idx}"`.
pub struct UsbMscBlockDevice {
    /// Index into MSC_DEVICES at registration time. Entries are
    /// tombstoned on detach, never shifted, so this stays stable
    /// for the device's lifetime; once the entry is tombstoned,
    /// reads/writes through a stale adapter fail with
    /// `BlockIoError::DeviceRemoved`.
    idx: usize,
    /// Bind generation of the entry this adapter was built from,
    /// captured at construction. Filesystems retain this adapter
    /// for the mount's whole life, across detach and replug; since
    /// a replug reuses the tombstoned index, the bare index cannot
    /// distinguish "my disk" from "the next disk". Every op
    /// compares this against the live entry's generation before
    /// issuing anything and fails `DeviceRemoved` on mismatch, so
    /// a stale adapter is never silently served by a different
    /// disk (or by a rebind of the same disk — a rebind is a new
    /// bind, with a new generation).
    generation: u64,
    /// Cached lba_size_bytes — read from MscDevice::lba_bytes once
    /// at construction so we don't re-enter the registry on every
    /// `lba_size()` call.
    lba_size: u32,
    /// Cached capacity in LBAs.
    capacity: u64,
    /// Cached command form of the bound LUN: true when its
    /// capacity crossed the 32-bit boundary and BOT commands use
    /// the 16-byte CDBs (#832). Captured at construction like
    /// `lba_size` / `capacity`; the request range preflight uses
    /// it to judge which LBA space a request must fit.
    cmd16: bool,
}

impl core::fmt::Debug for UsbMscBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UsbMscBlockDevice")
            .field("idx", &self.idx)
            .field("generation", &self.generation)
            .field("lba_size", &self.lba_size)
            .field("capacity", &self.capacity)
            .field("cmd16", &self.cmd16)
            .finish()
    }
}

impl UsbMscBlockDevice {
    /// Wrap MSC_DEVICES[idx] as a BlockDeviceSync. Returns None if
    /// the index isn't bound, or the device hasn't completed
    /// READ CAPACITY(10) (lba_size == 0).
    pub fn from_index(idx: usize) -> Option<Self> {
        let g = MSC_DEVICES.lock();
        let dev = g.get(idx).and_then(|slot| slot.as_ref())?;
        if dev.lba_bytes == 0 {
            return None;
        }
        Some(Self {
            idx,
            generation: dev.generation,
            lba_size: dev.lba_bytes,
            capacity: dev.last_lba + 1,
            cmd16: dev.cmd16,
        })
    }

    /// Snapshot the (controller, device-fields) pair a BOT exchange
    /// needs, without holding any registry lock across the transfer
    /// (`flush` and `write_fua` share this helper; `read`/`write`
    /// build the same snapshot inline). The snapshot is the
    /// identity gate, identical to `read`/`write`: the registry is
    /// consulted before the controller lookup and before the caller
    /// takes the I/O claim — the entry must be live *and* still the
    /// bind this adapter was built from (generation match), so a
    /// flush or FUA write through a stale adapter fails
    /// `DeviceRemoved` instead of draining or forcing a write on
    /// the disk that reused its index after a replug. The hub
    /// context rides along so the snapshot's transfer funnels can
    /// resume / feed the port (#840). The
    /// snapshot's tag counter restarts at 1 — safe because
    /// `MscIoClaim` serialises exchanges per device, so the tag
    /// only has to match the CSW of the exchange in flight.
    fn transport_snapshot(
        &self,
    ) -> Result<(alloc::sync::Arc<Xhci>, MscDevice), narf_block::BlockIoError> {
        let (
            slot_id,
            bulk_in_dci,
            bulk_out_dci,
            lun,
            interface,
            lba_bytes,
            cmd16,
            generation,
            hub_port,
        ) = {
            let g = MSC_DEVICES.lock();
            let dev = match g.get(self.idx).and_then(|slot| slot.as_ref()) {
                Some(d) => d,
                None => return Err(narf_block::BlockIoError::DeviceRemoved),
            };
            if dev.generation != self.generation {
                return Err(narf_block::BlockIoError::DeviceRemoved);
            }
            (
                dev.slot_id,
                dev.bulk_in,
                dev.bulk_out,
                dev.lun,
                dev.interface,
                dev.lba_bytes,
                dev.cmd16,
                dev.generation,
                dev.hub_port,
            )
        };
        let c = match xhci::controller() {
            Some(c) => c,
            None => return Err(narf_block::BlockIoError::DeviceRemoved),
        };
        Ok((
            c,
            MscDevice {
                slot_id,
                bulk_in: bulk_in_dci,
                bulk_out: bulk_out_dci,
                lun,
                interface,
                lba_bytes,
                last_lba: 0,
                cmd16,
                generation,
                tag: IrqSafeSpinLock::new(1),
                hub_port,
            },
        ))
    }
}

/// Drive one bulk-only transport exchange from a synchronous
/// `BlockDeviceSync` caller.
///
/// Callers include contexts inside an executor poll: the HID supervisor
/// task scans partitions inline right after binding (`register_msc_block_device`),
/// and a FAT volume on the stick is driven from kernel tasks and syscalls.
/// `block_on` panics there by design, so those use `block_on_spin`. That is
/// safe for this future: every xHCI wait (`await_event`) drains the event
/// ring itself, self-wakes through `yield_now` and is bounded at 250 ms, so
/// it needs neither the executor nor an interrupt to make progress. Outside
/// a poll the cooperative `block_on` keeps its idle behaviour.
fn sync_bridge<F: core::future::Future>(fut: F) -> F::Output {
    if narf_scheduler::current_task_id() != narf_scheduler::TaskId::NONE {
        narf_scheduler::block_on_spin(fut)
    } else {
        narf_scheduler::block_on(fut)
    }
}

/// Per-interface exclusion for one CBW → data → CSW exchange. Two
/// sync callers on different tasks (the supervisor's partition
/// scan and a FAT volume on the same stick, say) would otherwise
/// interleave bulk-only-transport phases on the shared endpoints.
/// The claim is keyed by xHCI **slot**, not by registry index:
/// BOT is a one-command-at-a-time protocol per *interface*, and
/// since #831 a multi-LUN device holds several registry entries
/// (one per LUN) over the same slot and endpoint pair — keyed by
/// index, two LUNs of one reader could interleave phases on the
/// wire. Slots past the table are left unserialised.
const MSC_IO_SLOTS: usize = 256;
static MSC_IO_BUSY: [core::sync::atomic::AtomicBool; MSC_IO_SLOTS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MSC_IO_SLOTS];
/// A holder can be preempted mid-exchange; each of its xHCI waits is bounded
/// at 250 ms, so a claim that takes longer than this is a dead holder.
const MSC_IO_CLAIM_MS: u64 = 2_000;

struct MscIoClaim(Option<usize>);

impl MscIoClaim {
    fn acquire(slot_id: u8) -> Option<Self> {
        use core::sync::atomic::Ordering;
        let idx = slot_id as usize;
        let Some(busy) = MSC_IO_BUSY.get(idx) else {
            return Some(Self(None));
        };
        let deadline = narf_time::Deadline::after_ms(MSC_IO_CLAIM_MS);
        loop {
            if busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self(Some(idx)));
            }
            if deadline.expired() {
                return None;
            }
            core::hint::spin_loop();
        }
    }
}

impl Drop for MscIoClaim {
    fn drop(&mut self) {
        if let Some(idx) = self.0 {
            MSC_IO_BUSY[idx].store(false, core::sync::atomic::Ordering::Release);
        }
    }
}

/// Keep each BOT command within the xHCI endpoint's single-page DMA buffer.
/// Filesystem requests (notably 16 KiB btrfs nodes) can span many commands.
fn block_chunks(
    lba: u64,
    n_blocks: u16,
    lba_bytes: u32,
    cmd16: bool,
) -> Result<impl Iterator<Item = (u64, u16, core::ops::Range<usize>)>, narf_block::BlockIoError> {
    if !lba_bytes.is_power_of_two() || !(512..=4096).contains(&lba_bytes) {
        return Err(narf_block::BlockIoError::DriverError);
    }
    let end = lba
        .checked_add(n_blocks as u64)
        .ok_or(narf_block::BlockIoError::OutOfRange)?;
    // The request must fit the LUN's command form: a 10-byte-CDB
    // device addresses at most 2^32 blocks, while a 16-byte-CDB
    // device (#832) spans the full u64 LBA space.
    let max_end = if cmd16 {
        u64::MAX
    } else {
        u64::from(u32::MAX) + 1
    };
    if end > max_end {
        return Err(narf_block::BlockIoError::OutOfRange);
    }
    let max_blocks = (4096 / lba_bytes).min(MSC_MAX_BLOCKS_PER_XFER as u32) as usize;
    Ok((0..n_blocks as usize)
        .step_by(max_blocks)
        .map(move |offset| {
            let count = (n_blocks as usize - offset).min(max_blocks);
            let start = offset * lba_bytes as usize;
            (
                lba + offset as u64,
                count as u16,
                start..start + count * lba_bytes as usize,
            )
        }))
}

impl narf_block::BlockDeviceSync for UsbMscBlockDevice {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        self.capacity
    }
    /// USB enclosures and bridges carry volatile write caches, and
    /// this device now performs both advertised operations for
    /// real: `flush` issues SYNCHRONIZE CACHE(10) and `write_fua`
    /// sets the WRITE(10) FUA bit (#829). `volatile_cache` is the
    /// conservative assumption — no caching mode page is probed at
    /// attach; on a genuinely write-through device SYNCHRONIZE
    /// CACHE simply completes with nothing to drain, so the cost
    /// of assuming a cache is one extra command per flush, never
    /// a correctness risk.
    fn capabilities(&self) -> narf_block::BlockCaps {
        narf_block::BlockCaps {
            volatile_cache: true,
            fua: true,
        }
    }
    /// Drain the device's volatile write cache with
    /// SYNCHRONIZE CACHE(10) over BOT. Returns only once the CSW
    /// reports completion; a failed or phase-error CSW maps to
    /// `DriverError` — a flush that did not happen must surface
    /// as an error, never as success (#829).
    fn flush(&self) -> Result<(), narf_block::BlockIoError> {
        let (c, dev_snapshot) = self.transport_snapshot()?;
        let Some(_claim) = MscIoClaim::acquire(dev_snapshot.slot_id) else {
            return Err(narf_block::BlockIoError::DriverError);
        };
        let result = sync_bridge(async { dev_snapshot.synchronize_cache(&*c).await });
        match result {
            Ok(()) => Ok(()),
            Err(_) => Err(narf_block::BlockIoError::DriverError),
        }
    }
    /// Native FUA write: WRITE(10) with the FUA bit set, so the
    /// data is on the medium when the CSW completes — not the
    /// trait default's write + flush emulation. Same range and
    /// buffer contract as `write`.
    fn write_fua(
        &self,
        lba: u64,
        n_blocks: u16,
        data: &[u8],
    ) -> Result<(), narf_block::BlockIoError> {
        if lba
            .checked_add(n_blocks as u64)
            .is_none_or(|end| end > self.capacity)
        {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        let chunks = block_chunks(lba, n_blocks, self.lba_size, self.cmd16)?;
        let expected = n_blocks as usize * self.lba_size as usize;
        if data.len() < expected {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        let (c, dev_snapshot) = self.transport_snapshot()?;
        let Some(_claim) = MscIoClaim::acquire(dev_snapshot.slot_id) else {
            return Err(narf_block::BlockIoError::DriverError);
        };
        sync_bridge(async {
            for (start, count, bytes) in chunks {
                dev_snapshot
                    .write_blocks_fua(&*c, start, u32::from(count), &data[bytes])
                    .await
                    .map_err(|_| narf_block::BlockIoError::DriverError)?;
            }
            Ok(())
        })
    }
    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::BlockIoError> {
        if lba
            .checked_add(n_blocks as u64)
            .is_none_or(|end| end > self.capacity)
        {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        let chunks = block_chunks(lba, n_blocks, self.lba_size, self.cmd16)?;
        let expected = n_blocks as usize * self.lba_size as usize;
        if out.len() < expected {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        // Snapshot the device handle outside the registry locks so
        // we can drive the async read_blocks via `sync_bridge`
        // without holding any IrqSafeSpinLock across the .await
        // (see `sync_bridge` for the in-poll callers). The snapshot
        // is the identity gate, and it runs before the I/O claim is
        // taken: the entry must be live *and* still the bind this
        // adapter was built from (generation match). A tombstone
        // or a generation mismatch — the index was reused by a
        // replugged disk — fails DeviceRemoved without issuing
        // anything against the current occupant. The hub context
        // rides along so the snapshot's transfer funnels can
        // resume / feed the port (#840).
        let (
            slot_id,
            bulk_in_dci,
            bulk_out_dci,
            lun,
            interface,
            lba_bytes,
            cmd16,
            generation,
            hub_port,
        ) = {
            let g = MSC_DEVICES.lock();
            let dev = match g.get(self.idx).and_then(|slot| slot.as_ref()) {
                Some(d) => d,
                None => return Err(narf_block::BlockIoError::DeviceRemoved),
            };
            if dev.generation != self.generation {
                return Err(narf_block::BlockIoError::DeviceRemoved);
            }
            (
                dev.slot_id,
                dev.bulk_in,
                dev.bulk_out,
                dev.lun,
                dev.interface,
                dev.lba_bytes,
                dev.cmd16,
                dev.generation,
                dev.hub_port,
            )
        };
        let c = match xhci::controller() {
            Some(c) => c,
            None => return Err(narf_block::BlockIoError::DeviceRemoved),
        };
        let dev_snapshot = MscDevice {
            slot_id,
            bulk_in: bulk_in_dci,
            bulk_out: bulk_out_dci,
            lun,
            interface,
            lba_bytes,
            last_lba: 0,
            cmd16,
            generation,
            tag: IrqSafeSpinLock::new(1),
            hub_port,
        };
        let Some(_claim) = MscIoClaim::acquire(slot_id) else {
            return Err(narf_block::BlockIoError::DriverError);
        };
        sync_bridge(async {
            for (start, count, bytes) in chunks {
                let data = dev_snapshot
                    .read_blocks(&*c, start, u32::from(count))
                    .await
                    .map_err(|_| narf_block::BlockIoError::DriverError)?;
                out[bytes].copy_from_slice(&data);
            }
            Ok(())
        })
    }
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        if lba
            .checked_add(n_blocks as u64)
            .is_none_or(|end| end > self.capacity)
        {
            return Err(narf_block::BlockIoError::OutOfRange);
        }
        let chunks = block_chunks(lba, n_blocks, self.lba_size, self.cmd16)?;
        let expected = n_blocks as usize * self.lba_size as usize;
        if data.len() < expected {
            return Err(narf_block::BlockIoError::BufferTooSmall);
        }
        // Identity gate, identical to `read`: snapshot the live
        // entry and compare bind generations before the I/O claim
        // is taken, so a stale adapter never issues a write against
        // the disk that reused its index after a replug. The hub
        // context rides along so the snapshot's transfer funnels
        // can resume / feed the port (#840).
        let (
            slot_id,
            bulk_in_dci,
            bulk_out_dci,
            lun,
            interface,
            lba_bytes,
            cmd16,
            generation,
            hub_port,
        ) = {
            let g = MSC_DEVICES.lock();
            let dev = match g.get(self.idx).and_then(|slot| slot.as_ref()) {
                Some(d) => d,
                None => return Err(narf_block::BlockIoError::DeviceRemoved),
            };
            if dev.generation != self.generation {
                return Err(narf_block::BlockIoError::DeviceRemoved);
            }
            (
                dev.slot_id,
                dev.bulk_in,
                dev.bulk_out,
                dev.lun,
                dev.interface,
                dev.lba_bytes,
                dev.cmd16,
                dev.generation,
                dev.hub_port,
            )
        };
        let c = match xhci::controller() {
            Some(c) => c,
            None => return Err(narf_block::BlockIoError::DeviceRemoved),
        };
        let dev_snapshot = MscDevice {
            slot_id,
            bulk_in: bulk_in_dci,
            bulk_out: bulk_out_dci,
            lun,
            interface,
            lba_bytes,
            last_lba: 0,
            cmd16,
            generation,
            tag: IrqSafeSpinLock::new(1),
            hub_port,
        };
        let Some(_claim) = MscIoClaim::acquire(slot_id) else {
            return Err(narf_block::BlockIoError::DriverError);
        };
        sync_bridge(async {
            for (start, count, bytes) in chunks {
                dev_snapshot
                    .write_blocks(&*c, start, u32::from(count), &data[bytes])
                    .await
                    .map_err(|_| narf_block::BlockIoError::DriverError)?;
            }
            Ok(())
        })
    }
}

#[cfg(all(feature = "kernel-test", target_arch = "x86_64"))]
mod block_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_msc_filesystem_request_chunks() -> TestResult {
        // A btrfs node on a 512-byte disk, including a partial final chunk.
        let chunks: Vec<_> = block_chunks(100, 33, 512, false).unwrap().collect();
        if chunks
            != [
                (100, 8, 0..4096),
                (108, 8, 4096..8192),
                (116, 8, 8192..12288),
                (124, 8, 12288..16384),
                (132, 1, 16384..16896),
            ]
        {
            return TestResult::Fail("filesystem request lost or overlapped blocks");
        }
        let chunks: Vec<_> = block_chunks(u32::MAX as u64 - 1, 2, 4096, false)
            .unwrap()
            .collect();
        if chunks
            != [
                (u32::MAX as u64 - 1, 1, 0..4096),
                (u32::MAX as u64, 1, 4096..8192),
            ]
        {
            return TestResult::Fail("4K logical blocks exceeded the DMA buffer");
        }
        if block_chunks(u32::MAX as u64, 2, 512, false).is_ok()
            || block_chunks(0, 1, 8192, false).is_ok()
            || block_chunks(0, 1, 0, false).is_ok()
        {
            return TestResult::Fail("invalid BOT geometry or READ(10) range accepted");
        }
        // The same range that overflows a 10-byte CDB is ordinary
        // on a 16-byte-CDB device (#832): chunking must accept it
        // and carry the full 64-bit LBA into every chunk.
        let wide: Vec<_> = match block_chunks(u32::MAX as u64, 2, 512, true) {
            Ok(it) => it.collect(),
            Err(_) => return TestResult::Fail("READ(16) range refused by chunking"),
        };
        if wide != [(u32::MAX as u64, 2, 0..1024)] {
            return TestResult::Fail("READ(16) chunks lost the high LBA bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/msc", smoke_msc_filesystem_request_chunks);

    fn smoke_msc_fua_preflights_whole_request() -> TestResult {
        use narf_block::{BlockDeviceSync, BlockIoError};
        let device = UsbMscBlockDevice {
            idx: usize::MAX,
            generation: 0,
            lba_size: 512,
            capacity: u64::MAX,
            cmd16: false,
        };
        // The first LBA fits WRITE(10), but the final one does not. Refuse
        // the whole request before looking up transport or taking a claim.
        if device.write_fua(u32::MAX as u64, 2, &[0; 1024]) != Err(BlockIoError::OutOfRange) {
            return TestResult::Fail("FUA did not validate the complete WRITE(10) range");
        }
        // An exactly representable request passes preflight and reaches
        // the normal stale/missing-device gate, without touching a controller.
        if device.write_fua(u32::MAX as u64 - 1, 2, &[0; 1024]) != Err(BlockIoError::DeviceRemoved)
        {
            return TestResult::Fail("FUA refused a valid boundary request before identity lookup");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/msc", smoke_msc_fua_preflights_whole_request);
}
