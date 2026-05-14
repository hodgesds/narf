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
//! ## Stage-5 cut
//!
//! - INQUIRY (5 bytes) → INQUIRY data (36 bytes)
//! - READ CAPACITY(10) → 8 bytes (last LBA + block size)
//! - READ(10) / WRITE(10) for a single 512-byte block
//!
//! Multi-block transfers, error recovery (Reset Recovery, §5.3),
//! and the LUN > 0 path are still follow-ups.

use alloc::vec::Vec;

use crate::xhci::{self, EndpointConfig, EndpointKind, Xhci};
use narf_lib::sync::IrqSafeSpinLock;

/// Maximum payload (in target blocks) we'll cram into a single
/// READ(10) / WRITE(10). Bounded by the bulk transfer scratch.
pub const MSC_MAX_BLOCKS_PER_XFER: u16 = 8;

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
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2A;

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

/// One bulk-only-transport mass storage device. Ties a previously
/// addressed + configured xHCI slot to its bulk-IN / bulk-OUT
/// endpoint DCIs.
#[derive(Debug)]
pub struct MscDevice {
    pub slot_id: u8,
    pub bulk_in: u8,  // DCI of the bulk-IN endpoint
    pub bulk_out: u8, // DCI of the bulk-OUT endpoint
    /// Block size reported by READ CAPACITY(10).
    pub lba_bytes: u32,
    /// Last LBA reported by READ CAPACITY(10).
    pub last_lba: u32,
    /// Sequence counter for `dCBWTag` (matched by the device in CSW).
    tag: IrqSafeSpinLock<u32>,
}

/// Walk a Configuration Descriptor (§9.6.3) tree looking for the
/// first interface whose `bInterfaceClass:SubClass:Protocol` matches
/// MSC BOT, plus its bulk-IN + bulk-OUT endpoints. Returns the
/// `EndpointConfig` for each direction so a caller can hand them
/// to `xhci::configure_endpoints`.
///
/// `cfg` is the descriptor blob fetched via
/// `Xhci::get_config_descriptor`.
pub fn find_bot_endpoints(cfg: &[u8]) -> Result<(EndpointConfig, EndpointConfig), MscError> {
    let mut i = 0usize;
    let mut in_match = false;
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
            //   +5 bInterfaceClass
            //   +6 bInterfaceSubClass
            //   +7 bInterfaceProtocol
            4 if len >= 9 => {
                in_match = cfg[i + 5] == MSC_INTERFACE_CLASS
                    && cfg[i + 6] == MSC_INTERFACE_SUBCLASS
                    && cfg[i + 7] == MSC_INTERFACE_PROTOCOL;
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
        (Some(i), Some(o)) => Ok((i, o)),
        _ => Err(MscError::EndpointsMissing),
    }
}

impl MscDevice {
    /// Bind to an already addressed + configured slot. Issues
    /// READ CAPACITY(10) so `lba_bytes` and `last_lba` are
    /// populated. Caller must have already run
    /// `xhci.configure_endpoints` for the bulk pair returned by
    /// `find_bot_endpoints`.
    pub fn attach(xhci: &Xhci, slot_id: u8, bulk_in: u8, bulk_out: u8) -> Result<Self, MscError> {
        let dev = MscDevice {
            slot_id,
            bulk_in,
            bulk_out,
            lba_bytes: 0,
            last_lba: 0,
            tag: IrqSafeSpinLock::new(1),
        };
        let cap = dev.read_capacity_10(xhci)?;
        Ok(MscDevice {
            slot_id,
            bulk_in,
            bulk_out,
            lba_bytes: cap.0,
            last_lba: cap.1,
            tag: IrqSafeSpinLock::new(2),
        })
    }

    /// Allocate a fresh CBW tag.
    fn next_tag(&self) -> u32 {
        let mut g = self.tag.lock();
        let t = *g;
        *g = g.wrapping_add(1);
        t
    }

    /// Build a 31-byte CBW (§5.1 Table 5.1).
    fn build_cbw(&self, tag: u32, data_len: u32, is_in: bool, cb: &[u8]) -> [u8; 31] {
        let mut out = [0u8; 31];
        out[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        out[4..8].copy_from_slice(&tag.to_le_bytes());
        out[8..12].copy_from_slice(&data_len.to_le_bytes());
        out[12] = if is_in { CBW_FLAG_IN } else { 0 };
        out[13] = 0; // bCBWLUN
        out[14] = (cb.len() as u8) & 0x1F; // bCBWCBLength (low 5)
        let n = cb.len().min(16);
        out[15..15 + n].copy_from_slice(&cb[..n]);
        out
    }

    /// Receive + parse a 13-byte CSW (§5.2 Table 5.2). Verifies the
    /// `b'USBS'` signature and returns the bCSWStatus byte (0=ok,
    /// 1=fail, 2=phase err) and the residue.
    fn read_csw(&self, xhci: &Xhci, expect_tag: u32) -> Result<(u8, u32), MscError> {
        let mut buf = [0u8; 13];
        let n = xhci.bulk_in(self.slot_id, self.bulk_in, &mut buf)?;
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

    /// Run a SCSI command with no data stage. Used by TEST UNIT READY.
    fn cmd_no_data(&self, xhci: &Xhci, cb: &[u8]) -> Result<(), MscError> {
        let tag = self.next_tag();
        let cbw = self.build_cbw(tag, 0, false, cb);
        xhci.bulk_out(self.slot_id, self.bulk_out, &cbw)?;
        let (status, _) = self.read_csw(xhci, tag)?;
        if status != 0 {
            return Err(MscError::CswStatus(status));
        }
        Ok(())
    }

    /// Run a SCSI command with a host-bound (IN) data stage.
    fn cmd_data_in(&self, xhci: &Xhci, cb: &[u8], out: &mut [u8]) -> Result<usize, MscError> {
        let tag = self.next_tag();
        let cbw = self.build_cbw(tag, out.len() as u32, true, cb);
        xhci.bulk_out(self.slot_id, self.bulk_out, &cbw)?;
        let n = xhci.bulk_in(self.slot_id, self.bulk_in, out)?;
        let (status, _) = self.read_csw(xhci, tag)?;
        if status != 0 {
            return Err(MscError::CswStatus(status));
        }
        Ok(n)
    }

    /// Run a SCSI command with a device-bound (OUT) data stage.
    fn cmd_data_out(&self, xhci: &Xhci, cb: &[u8], data: &[u8]) -> Result<usize, MscError> {
        let tag = self.next_tag();
        let cbw = self.build_cbw(tag, data.len() as u32, false, cb);
        xhci.bulk_out(self.slot_id, self.bulk_out, &cbw)?;
        let n = xhci.bulk_out(self.slot_id, self.bulk_out, data)?;
        let (status, _) = self.read_csw(xhci, tag)?;
        if status != 0 {
            return Err(MscError::CswStatus(status));
        }
        Ok(n)
    }

    /// `TEST UNIT READY` (SBC-3 §5.34). 6-byte command, no data.
    /// Returns `Ok(())` if the device is ready to handle media
    /// access; a CSW status of 1 means the device wants the host
    /// to call REQUEST SENSE (not implemented here — Stage-5 cut).
    pub fn test_unit_ready(&self, xhci: &Xhci) -> Result<(), MscError> {
        self.cmd_no_data(xhci, &[SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0])
    }

    /// `INQUIRY` (SPC-4 §6.5). Returns the standard 36-byte INQUIRY
    /// response (vendor / product / revision / etc.).
    pub fn inquiry(&self, xhci: &Xhci) -> Result<[u8; 36], MscError> {
        let cb = [SCSI_INQUIRY, 0, 0, 0, 36, 0];
        let mut out = [0u8; 36];
        let n = self.cmd_data_in(xhci, &cb, &mut out)?;
        if n < 36 {
            return Err(MscError::BadLength);
        }
        Ok(out)
    }

    /// `READ CAPACITY(10)` (SBC-3 §5.16). Returns
    /// `(block_bytes, last_lba)` — the device's reported block size
    /// and the index of the last addressable LBA.
    pub fn read_capacity_10(&self, xhci: &Xhci) -> Result<(u32, u32), MscError> {
        let cb = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut out = [0u8; 8];
        let n = self.cmd_data_in(xhci, &cb, &mut out)?;
        if n < 8 {
            return Err(MscError::BadLength);
        }
        // Big-endian fields per SBC-3 Table 56.
        let last_lba = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
        let blocksz = u32::from_be_bytes([out[4], out[5], out[6], out[7]]);
        Ok((blocksz, last_lba))
    }

    /// `READ(10)` for a single block. Returns the `lba_bytes`-sized
    /// data buffer. SBC-3 §5.10.
    pub fn read_block(&self, xhci: &Xhci, lba: u32) -> Result<Vec<u8>, MscError> {
        if self.lba_bytes == 0 || self.lba_bytes as usize > 4096 {
            return Err(MscError::BadLength);
        }
        let lba_be = lba.to_be_bytes();
        // CDB layout: opcode | flags | LBA[3..0] | group | xferlen[1..0] | ctrl
        let cb = [
            SCSI_READ_10,
            0,
            lba_be[0],
            lba_be[1],
            lba_be[2],
            lba_be[3],
            0,
            0,
            1,
            0,
        ];
        let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(self.lba_bytes as usize);
        out.resize(self.lba_bytes as usize, 0);
        let n = self.cmd_data_in(xhci, &cb, &mut out[..])?;
        if n != self.lba_bytes as usize {
            return Err(MscError::BadLength);
        }
        Ok(out)
    }

    /// `WRITE(10)` for a single block. SBC-3 §5.27.
    pub fn write_block(&self, xhci: &Xhci, lba: u32, data: &[u8]) -> Result<(), MscError> {
        if data.len() != self.lba_bytes as usize {
            return Err(MscError::BadLength);
        }
        let lba_be = lba.to_be_bytes();
        let cb = [
            SCSI_WRITE_10,
            0,
            lba_be[0],
            lba_be[1],
            lba_be[2],
            lba_be[3],
            0,
            0,
            1,
            0,
        ];
        let n = self.cmd_data_out(xhci, &cb, data)?;
        if n != data.len() {
            return Err(MscError::BadLength);
        }
        Ok(())
    }

    /// Multi-block `READ(10)`. Reads `nblocks` consecutive blocks
    /// starting at `lba`. Bounded to `MSC_MAX_BLOCKS_PER_XFER` per
    /// call. Returns the concatenated payload.
    pub fn read_blocks(&self, xhci: &Xhci, lba: u32, nblocks: u16) -> Result<Vec<u8>, MscError> {
        if self.lba_bytes == 0 || nblocks == 0 || nblocks > MSC_MAX_BLOCKS_PER_XFER {
            return Err(MscError::BadLength);
        }
        let total = self.lba_bytes as usize * nblocks as usize;
        let lba_be = lba.to_be_bytes();
        let nb = nblocks.to_be_bytes();
        let cb = [
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
        ];
        let mut out: Vec<u8> = alloc::vec![0u8; total];
        let n = self.cmd_data_in(xhci, &cb, &mut out[..])?;
        if n != total {
            return Err(MscError::BadLength);
        }
        Ok(out)
    }

    /// Multi-block `WRITE(10)`. Writes `nblocks` blocks starting at
    /// `lba`. `data.len()` must equal `nblocks * lba_bytes`.
    pub fn write_blocks(
        &self,
        xhci: &Xhci,
        lba: u32,
        nblocks: u16,
        data: &[u8],
    ) -> Result<(), MscError> {
        if self.lba_bytes == 0
            || nblocks == 0
            || nblocks > MSC_MAX_BLOCKS_PER_XFER
            || data.len() != self.lba_bytes as usize * nblocks as usize
        {
            return Err(MscError::BadLength);
        }
        let lba_be = lba.to_be_bytes();
        let nb = nblocks.to_be_bytes();
        let cb = [
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
        ];
        let n = self.cmd_data_out(xhci, &cb, data)?;
        if n != data.len() {
            return Err(MscError::BadLength);
        }
        Ok(())
    }
}

// ── Hot-plug enumeration ──────────────────────────────────────────

/// System-wide registry of attached USB Mass Storage devices.
/// Populated by `enumerate_and_attach_msc`; consumed by the
/// `block::BlockDeviceSync` adapter once one is wired up.
static MSC_DEVICES: IrqSafeSpinLock<Vec<MscDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Walk every connected port on the supplied xHCI controller and
/// try to bring up an MSC BOT device on each one. Per-port flow
/// mirrors the HID keyboard path: port_reset → enable_slot →
/// address_device → fetch CONFIG → `find_bot_endpoints` →
/// configure_endpoints → `MscDevice::attach` (which also issues
/// READ CAPACITY(10)).
///
/// Returns the count of devices successfully attached. Per-port
/// failures are skipped silently.
pub fn enumerate_and_attach_msc(xhci_dev: &Xhci) -> usize {
    let mut attached = 0usize;
    for (port, _portsc) in xhci_dev.connected_ports() {
        if try_attach_msc_port(xhci_dev, port).is_ok() {
            attached += 1;
        }
    }
    attached
}

fn try_attach_msc_port(xhci_dev: &Xhci, port: u8) -> Result<(), MscError> {
    xhci_dev.port_reset(port).map_err(MscError::Xhci)?;
    let speed = xhci_dev
        .port_speed(port)
        .ok_or(MscError::EndpointsMissing)?;
    let slot_id = xhci_dev.enable_slot().map_err(MscError::Xhci)?;
    // Wrap the post-enable_slot enumeration so we always free the
    // controller-allocated slot if anything fails (was a leak that
    // bound port→slot until the next HCRST and tripped a later
    // Address Device on the same port with TRB Error "port already
    // assigned"). Best-effort disable_slot — the real failure code
    // is what matters.
    let result = (|| -> Result<MscDevice, MscError> {
        xhci_dev
            .address_device(slot_id, port, speed)
            .map_err(MscError::Xhci)?;

        // Read 9-byte cfg header for wTotalLength.
        let mut head = [0u8; 9];
        let n = xhci_dev.get_config_descriptor(slot_id, 0, &mut head)?;
        if n < 9 {
            return Err(MscError::NotMsc);
        }
        let total = u16::from_le_bytes([head[2], head[3]]) as usize;
        if total < 9 || total > 4096 {
            return Err(MscError::NotMsc);
        }

        // Pull the full descriptor tree.
        let mut full = alloc::vec![0u8; total];
        let n2 = xhci_dev.get_config_descriptor(slot_id, 0, &mut full)?;
        if n2 < total {
            full.truncate(n2);
        }

        let (ep_in, ep_out) = find_bot_endpoints(&full)?;
        xhci_dev
            .configure_endpoints(slot_id, &[ep_in, ep_out])
            .map_err(MscError::Xhci)?;

        let bulk_in_dci = ((ep_in.ep_addr & 0x0F) * 2) + 1;
        let bulk_out_dci = ((ep_out.ep_addr & 0x0F) * 2) + 0;
        MscDevice::attach(xhci_dev, slot_id, bulk_in_dci, bulk_out_dci)
    })();
    match result {
        Ok(dev) => {
            MSC_DEVICES.lock().push(dev);
            Ok(())
        }
        Err(e) => {
            let _ = xhci_dev.disable_slot(slot_id);
            Err(e)
        }
    }
}

/// Number of MSC devices currently bound.
pub fn attached_msc_count() -> usize {
    MSC_DEVICES.lock().len()
}

/// Run a closure against an attached MSC device by index; returns
/// `None` if `idx` is out of range. The closure runs while the
/// global registry is locked, so don't perform xHCI traffic that
/// re-enters MSC bookkeeping.
pub fn with_device<R>(idx: usize, f: impl FnOnce(&MscDevice) -> R) -> Option<R> {
    let g = MSC_DEVICES.lock();
    g.get(idx).map(f)
}

#[doc(hidden)]
pub fn __reset_msc_for_test() {
    MSC_DEVICES.lock().clear();
}
