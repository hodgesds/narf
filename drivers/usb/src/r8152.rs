//! Realtek RTL8152/RTL8153 USB Ethernet driver — register-level.
//!
//! Full driver for the RTL8152 (USB 2.0, 10/100) and RTL8153 /
//! RTL8155 / RTL8156 / RTL8157 (USB 3.x, GbE / 2.5 GbE) family —
//! the chip inside most USB-C docks and USB Ethernet dongles.
//!
//! ## Register / wire model
//!
//! Register facts (addresses, bit definitions, descriptor formats)
//! are the chip's publicly documented programming model, as
//! mirrored by the public references for this family:
//! - Linux `drivers/net/usb/r8152.c` (cited by the original stub).
//! - FreeBSD `sys/dev/usb/net/if_ure.c` register header.
//!
//! The MAC's register file is reached through the **OCP vendor
//! control protocol**: a vendor device request (`bRequest = 0x05`
//! for both directions; `bmRequestType` 0xC0 read / 0x40 write)
//! where `wValue` is the register address and `wIndex` packs the
//! MCU window (`0x0100` = PLA, `0x0000` = USB) OR'd with a byte
//! enable (`0xFF` dword / `0x33` word / `0x11` byte, shifted to the
//! accessed byte lanes). Reads and writes move in ≤ 64-byte chunks
//! at 4-byte-aligned addresses.
//!
//! Datapath formats:
//! - **RX**: bulk-IN transfers carry an aggregation buffer of
//!   back-to-back segments; each segment is a 24-byte `rx_desc`
//!   (`opts1..opts6`, `opts1 & 0x7FFF` = frame length, frame bytes
//!   only) followed immediately by the frame.
//! - **TX**: each bulk-OUT transfer is one 8-byte `tx_desc`
//!   (`opts1 = len | TX_FS | TX_LS`, `opts2 = 0` — no checksum
//!   offload requested) followed by the frame, zero-padded to a
//!   4-byte multiple (`TX_ALIGN`).
//!
//! The MAC address is **read from the device** (`PLA_IDR`, or
//! `PLA_BACKUP` on the GbE generations, with the other as fallback)
//! and validated; a device that reports no valid address fails the
//! bind — no address is ever invented. Carrier / speed / duplex
//! come from `PLA_PHYSTATUS`, sampled by the RX pump and published
//! through `narf_net::iface::set_link_metadata`.
//!
//! Publication: each bound device registers as `usb-rtl{N}` via
//! `narf_net::iface::register_with_context` with the device-record
//! index as the send cookie, so TX always routes to the bound
//! device (the queue-22 shared PCIe publish helper is a future
//! dedup for this, not a dependency).
//!
//! ## Scope limits (honest)
//!
//! The per-chip-version PHY / firmware init tables (the long
//! version-switched OCP write sequences the reference drivers run
//! for EEE / ALDPS / PHY patch tuning) are **not** reproduced
//! here; the bind performs the MAC-level bring-up those tables
//! precede (soft reset, accept filters, multicast table, receive
//! size, RX/TX enable) and the datapath runs on the chip's reset
//! defaults otherwise. Tracked as a follow-up issue.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::class_registry::{register_class_driver_with_unbind, UsbClassMatch, UsbProbeError};
use crate::device::USBDevice;
use crate::xhci::{EndpointConfig, EndpointKind};

// ── OCP vendor-request protocol ──────────────────────────────────

/// MCU window selector for `wIndex` (high byte).
pub const MCU_TYPE_PLA: u16 = 0x0100;
pub const MCU_TYPE_USB: u16 = 0x0000;

/// `bmRequestType` for register reads (device-to-host, vendor).
pub const REQT_READ: u8 = 0xC0;
/// `bmRequestType` for register writes (host-to-device, vendor).
pub const REQT_WRITE: u8 = 0x40;
/// `bRequest` for register reads.
pub const REQ_GET_REGS: u8 = 0x05;
/// `bRequest` for register writes.
pub const REQ_SET_REGS: u8 = 0x05;

/// Byte-enable patterns packed into `wIndex` (low byte), shifted
/// left by the accessed byte-lane offset before use.
pub const BYTE_EN_DWORD: u16 = 0xFF;
pub const BYTE_EN_WORD: u16 = 0x33;
pub const BYTE_EN_BYTE: u16 = 0x11;

/// Largest single OCP read chunk (the reference model caps reads
/// at 64 bytes per control transfer).
pub const OCP_READ_CHUNK: usize = 64;

// ── PLA register map (subset the datapath needs) ─────────────────

/// Permanent station address (6 bytes used of an 8-byte read).
pub const PLA_IDR: u16 = 0xC000;
/// Receive Configuration Register (accept-filter bits).
pub const PLA_RCR: u16 = 0xC010;
/// Receive Maximum Size (bytes).
pub const PLA_RMS: u16 = 0xC016;
/// Multicast Address Registers (8 bytes; all-ones = accept all
/// multicast groups the RCR filter admits).
pub const PLA_MAR: u16 = 0xCD00;
/// Backup station address — the live MAC on GbE generations.
pub const PLA_BACKUP: u16 = 0xD000;
/// Transmit Configuration Register 1 (chip-version bits).
pub const PLA_TCR1: u16 = 0xE612;
/// Chip command byte register (reset / RX enable / TX enable).
pub const PLA_CR: u16 = 0xE813;
/// PHY link-status byte (speed / duplex / link).
pub const PLA_PHYSTATUS: u16 = 0xE908;

/// `PLA_TCR1` version field mask.
pub const TCR1_VERSION_MASK: u16 = 0x7CF0;

// `PLA_CR` bits.
pub const CR_RST: u8 = 0x10;
pub const CR_RE: u8 = 0x08;
pub const CR_TE: u8 = 0x04;

// `PLA_RCR` accept-filter bits.
pub const RCR_AAP: u32 = 1 << 0; // accept all (promiscuous)
pub const RCR_APM: u32 = 1 << 1; // accept physical match (unicast to us)
pub const RCR_AM: u32 = 1 << 2; // accept multicast
pub const RCR_AB: u32 = 1 << 3; // accept broadcast

// `PLA_PHYSTATUS` bits.
pub const PHYSTAT_1000M: u8 = 0x10;
pub const PHYSTAT_100M: u8 = 0x08;
pub const PHYSTAT_10M: u8 = 0x04;
pub const PHYSTAT_LINK: u8 = 0x02;
pub const PHYSTAT_FULL_DUP: u8 = 0x01;

// ── Datapath descriptor formats ──────────────────────────────────

/// RX aggregation segment header length (`rx_desc`, 6 × u32).
pub const RX_DESC_LEN: usize = 24;
/// `rx_desc.opts1` frame-length mask.
pub const RX_LEN_MASK: u32 = 0x7FFF;
/// Minimum Ethernet frame the chip hands up (`ETH_ZLEN`); a
/// shorter length field means the aggregation stream is corrupt
/// or exhausted — stop the walk.
pub const RX_MIN_FRAME: u32 = 60;

/// `tx_desc.opts1` first-segment bit.
pub const TX_FS: u32 = 1 << 31;
/// `tx_desc.opts1` last-segment bit.
pub const TX_LS: u32 = 1 << 30;
/// `tx_desc.opts1` length mask / maximum.
pub const TX_LEN_MASK: u32 = 0x3FFFF;

/// RX aggregation buffer posted on bulk IN. Covers the RTL8153
/// 9 KiB max frame plus aggregation slack; the FE generation's
/// frames are ≤ 1522 bytes so several aggregate per transfer.
pub const RX_BUF_LEN: usize = 16 * 1024;

// ── Pure SETUP-packet packing (fixture-pinned) ───────────────────

/// SETUP fields for an OCP register read:
/// `(bmRequestType, bRequest, wValue, wIndex)`.
pub fn ocp_read_setup(mcu: u16, addr: u16) -> (u8, u8, u16, u16) {
    (REQT_READ, REQ_GET_REGS, addr, mcu)
}

/// SETUP fields + data-stage bytes for an OCP dword write:
/// `(bmRequestType, bRequest, wValue, wIndex, data)`. `wValue` is
/// the (already 4-aligned) register address; `wIndex` is the MCU
/// window OR'd with the dword byte-enable.
pub fn ocp_write_dword_pack(mcu: u16, addr: u16, value: u32) -> (u8, u8, u16, u16, [u8; 4]) {
    (
        REQT_WRITE,
        REQ_SET_REGS,
        addr,
        mcu | BYTE_EN_DWORD,
        value.to_le_bytes(),
    )
}

/// SETUP fields + data-stage bytes for an OCP word write. The
/// address is aligned down to a dword; the value is placed in its
/// byte lanes and the word byte-enable is shifted to match.
pub fn ocp_write_word_pack(mcu: u16, addr: u16, value: u16) -> (u8, u8, u16, u16, [u8; 4]) {
    let shift = addr & 2;
    let packed = (value as u32) << (shift * 8);
    (
        REQT_WRITE,
        REQ_SET_REGS,
        addr & !3,
        mcu | (BYTE_EN_WORD << shift),
        packed.to_le_bytes(),
    )
}

/// SETUP fields + data-stage bytes for an OCP byte write.
pub fn ocp_write_byte_pack(mcu: u16, addr: u16, value: u8) -> (u8, u8, u16, u16, [u8; 4]) {
    let shift = addr & 3;
    let packed = (value as u32) << (shift * 8);
    (
        REQT_WRITE,
        REQ_SET_REGS,
        addr & !3,
        mcu | (BYTE_EN_BYTE << shift),
        packed.to_le_bytes(),
    )
}

// ── OCP accessors over the USB core device handle ────────────────

/// Read `out.len()` bytes (multiple of 4) at 4-aligned `addr` from
/// the `mcu` window, in ≤ 64-byte control transfers.
async fn ocp_read(dev: &USBDevice, mcu: u16, addr: u16, out: &mut [u8]) -> Result<(), ()> {
    if addr & 3 != 0 || out.len() % 4 != 0 || out.is_empty() {
        return Err(());
    }
    let (rt, req, _, _) = ocp_read_setup(mcu, addr);
    let mut off = 0usize;
    while off < out.len() {
        let chunk = core::cmp::min(OCP_READ_CHUNK, out.len() - off);
        let wvalue = addr.wrapping_add(off as u16);
        dev.control_in(rt, req, wvalue, mcu, &mut out[off..off + chunk])
            .await
            .map_err(|_| ())?;
        off += chunk;
    }
    Ok(())
}

async fn ocp_read_dword(dev: &USBDevice, mcu: u16, addr: u16) -> Result<u32, ()> {
    let mut buf = [0u8; 4];
    ocp_read(dev, mcu, addr, &mut buf).await?;
    Ok(u32::from_le_bytes(buf))
}

/// Word read: plain dword fetch, word extracted locally (the
/// reference model passes no byte-enable for reads — byte-enables
/// appear only in write `wIndex` values).
async fn ocp_read_word(dev: &USBDevice, mcu: u16, addr: u16) -> Result<u16, ()> {
    let shift = addr & 2;
    let (rt, req, _, _) = ocp_read_setup(mcu, addr);
    let mut buf = [0u8; 4];
    dev.control_in(rt, req, addr & !3, mcu, &mut buf)
        .await
        .map_err(|_| ())?;
    Ok((u32::from_le_bytes(buf) >> (shift * 8)) as u16)
}

/// Byte read: plain dword fetch, byte extracted locally (the
/// reference model passes no byte-enable for byte reads).
async fn ocp_read_byte(dev: &USBDevice, mcu: u16, addr: u16) -> Result<u8, ()> {
    let shift = addr & 3;
    let (rt, req, _, _) = ocp_read_setup(mcu, addr);
    let mut buf = [0u8; 4];
    dev.control_in(rt, req, addr & !3, mcu, &mut buf)
        .await
        .map_err(|_| ())?;
    Ok((u32::from_le_bytes(buf) >> (shift * 8)) as u8)
}

async fn ocp_write_dword(dev: &USBDevice, mcu: u16, addr: u16, value: u32) -> Result<(), ()> {
    let (rt, req, wvalue, windex, data) = ocp_write_dword_pack(mcu, addr, value);
    dev.control_out(rt, req, wvalue, windex, &data)
        .await
        .map_err(|_| ())?;
    Ok(())
}

async fn ocp_write_word(dev: &USBDevice, mcu: u16, addr: u16, value: u16) -> Result<(), ()> {
    let (rt, req, wvalue, windex, data) = ocp_write_word_pack(mcu, addr, value);
    dev.control_out(rt, req, wvalue, windex, &data)
        .await
        .map_err(|_| ())?;
    Ok(())
}

async fn ocp_write_byte(dev: &USBDevice, mcu: u16, addr: u16, value: u8) -> Result<(), ()> {
    let (rt, req, wvalue, windex, data) = ocp_write_byte_pack(mcu, addr, value);
    dev.control_out(rt, req, wvalue, windex, &data)
        .await
        .map_err(|_| ())?;
    Ok(())
}

// ── Pure datapath helpers (fixture-pinned) ───────────────────────

/// Extract and validate the station address from an 8-byte
/// station-address register read (IDR or BACKUP). Returns `None`
/// for the unprogrammed patterns (all-zero, all-ones) and for
/// multicast addresses — the caller falls back to the other
/// register, then fails the bind.
pub fn mac_from_station_bytes(raw: &[u8; 8]) -> Option<[u8; 6]> {
    let mac: [u8; 6] = raw[..6].try_into().ok()?;
    if mac.iter().all(|&b| b == 0) || mac.iter().all(|&b| b == 0xFF) {
        return None;
    }
    if mac[0] & 1 != 0 {
        return None; // multicast bit set — not a station address
    }
    Some(mac)
}

/// The `PLA_RCR` value for normal operation: keep the device's
/// other configuration bits, drop promiscuous, accept unicast to
/// us + multicast + broadcast.
pub fn rcr_with_accept_filters(old: u32) -> u32 {
    (old & !RCR_AAP) | RCR_APM | RCR_AM | RCR_AB
}

/// Decode a `PLA_PHYSTATUS` byte into
/// `(carrier, speed_mbps, duplex)` for `iface::set_link_metadata`.
pub fn decode_link_status(byte: u8) -> (bool, Option<u32>, Option<narf_net::iface::LinkDuplex>) {
    if byte & PHYSTAT_LINK == 0 {
        return (false, None, None);
    }
    let speed = if byte & PHYSTAT_1000M != 0 {
        Some(1000)
    } else if byte & PHYSTAT_100M != 0 {
        Some(100)
    } else if byte & PHYSTAT_10M != 0 {
        Some(10)
    } else {
        None
    };
    let duplex = if byte & PHYSTAT_FULL_DUP != 0 {
        Some(narf_net::iface::LinkDuplex::Full)
    } else {
        Some(narf_net::iface::LinkDuplex::Half)
    };
    (true, speed, duplex)
}

/// One frame located inside an RX aggregation buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxSegment {
    /// Byte offset of the frame within the aggregation buffer.
    pub offset: usize,
    /// Frame length in bytes (descriptor excluded).
    pub len: usize,
}

/// Walk an RX aggregation buffer into its frames. Stops at the
/// first segment whose length field is implausible (< ETH_ZLEN,
/// or running past the buffer) — the stream cannot be resynced
/// past a bad descriptor.
pub fn parse_rx_aggregate(buf: &[u8]) -> Vec<RxSegment> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + RX_DESC_LEN <= buf.len() {
        let opts1 = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let len = (opts1 & RX_LEN_MASK) as usize;
        if (len as u32) < RX_MIN_FRAME || off + RX_DESC_LEN + len > buf.len() {
            break;
        }
        out.push(RxSegment {
            offset: off + RX_DESC_LEN,
            len,
        });
        off += RX_DESC_LEN + len;
    }
    out
}

/// Append one TX segment (`tx_desc` + frame, padded to TX_ALIGN =
/// 4 bytes) for `frame` to `out`.
pub fn build_tx_segment(frame: &[u8], out: &mut Vec<u8>) -> Result<(), ()> {
    if frame.len() > TX_LEN_MASK as usize {
        return Err(());
    }
    let opts1 = (frame.len() as u32 & TX_LEN_MASK) | TX_FS | TX_LS;
    out.extend_from_slice(&opts1.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // opts2: no csum offload
    out.extend_from_slice(frame);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    Ok(())
}

/// Find the vendor-specific (class 0xFF) interface's bulk pair in
/// a configuration-descriptor blob. Returns
/// `(bulk_in_ep, bulk_out_ep)` as xHCI endpoint configs.
pub fn find_rtl_endpoints(cfg: &[u8]) -> Option<(EndpointConfig, EndpointConfig)> {
    let mut i = 0usize;
    let mut in_vendor_iface = false;
    let mut bulk_in: Option<EndpointConfig> = None;
    let mut bulk_out: Option<EndpointConfig> = None;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            // INTERFACE: class is byte 5.
            in_vendor_iface = cfg[i + 5] == 0xFF;
        } else if desc_type == 0x05 && in_vendor_iface && len >= 7 {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF;
            if attrs & 0x03 == 2 {
                // Bulk endpoint.
                let is_in = ep_addr & 0x80 != 0;
                let ep = EndpointConfig {
                    ep_addr,
                    max_packet,
                    kind: if is_in {
                        EndpointKind::BulkIn
                    } else {
                        EndpointKind::BulkOut
                    },
                    interval: 0,
                };
                if is_in {
                    bulk_in = Some(ep);
                } else {
                    bulk_out = Some(ep);
                }
            }
        }
        i += len;
    }
    match (bulk_in, bulk_out) {
        (Some(i), Some(o)) => Some((i, o)),
        _ => None,
    }
}

// ── Device table + publication ───────────────────────────────────

/// Chip generation, from the product id. Selects the station
/// address source order and the receive-size programming; the
/// datapath formats are identical across generations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RtlGen {
    /// RTL8152 — USB 2.0, 10/100.
    Fe,
    /// RTL8153 / 8155 / 8156 / 8157 and the dock re-badges.
    GbE,
}

pub fn generation_for_pid(pid: u16) -> RtlGen {
    if pid == 0x8152 {
        RtlGen::Fe
    } else {
        RtlGen::GbE
    }
}

/// Largest frame the generation accepts (programmed into
/// `PLA_RMS`): 1522 (1518 + FCS) for FE, 9216 jumbo-capable for
/// GbE.
pub fn rx_max_size(gen: RtlGen) -> u16 {
    match gen {
        RtlGen::Fe => 1522,
        RtlGen::GbE => 9216,
    }
}

/// One bound RTL device.
#[derive(Clone, Debug)]
pub struct RtlDevice {
    pub slot_id: u8,
    pub generation: RtlGen,
    pub mac: [u8; 6],
    pub bulk_in_dci: u8,
    pub bulk_out_dci: u8,
    /// Assigned `narf_net::iface` name (`usb-rtl{N}`).
    pub iface_name: String,
    pub pump_running: bool,
    /// Last `PLA_PHYSTATUS` byte sampled (0xFF = never sampled).
    pub link_byte: u8,
    /// Detach tombstone: set by `detach_r8152_slot`. The pump
    /// exits when `pump_running` clears; TX resolves to `None`.
    /// Records are never removed, because net-registry TX
    /// cookies are record indices — removing a record would
    /// retarget every later device's cookie at the wrong
    /// device (the ECM/NCM rule).
    pub detached: bool,
}

/// System-wide registry of bound RTL devices.
pub static RTL_DEVICES: IrqSafeSpinLock<Vec<RtlDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Resolve a device-record index to its TX target
/// `(slot_id, bulk_out_dci)`. The send trampoline routes through
/// this — and only this — so a frame can never be emitted on a
/// different device's endpoint.
pub fn tx_target(idx: usize) -> Option<(u8, u8)> {
    let g = RTL_DEVICES.lock();
    g.get(idx)
        .filter(|d| !d.detached)
        .map(|d| (d.slot_id, d.bulk_out_dci))
}

/// `SendCtxFn` trampoline: the cookie is the device-record index
/// assigned at registration time.
fn rtl_send_ctx(cookie: u64, frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    let (slot_id, bulk_out_dci) = tx_target(cookie as usize).ok_or(())?;
    let mut seg = Vec::new();
    build_tx_segment(frame, &mut seg)?;
    let c = crate::xhci::controller().ok_or(())?;
    // The net stack's send hook is sync; bridge to the async
    // bulk_out via block_on (called from TX paths that are not
    // inside an executor poll — same contract as CDC-NCM's send).
    narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, &seg).await })
        .map_err(|_| ())?;
    Ok(())
}

// ── Bind ─────────────────────────────────────────────────────────

/// Read the station address: FE parts keep it in `PLA_IDR`, GbE
/// parts in `PLA_BACKUP`; each generation tries the other as a
/// fallback. Fails when neither holds a valid address.
async fn read_station_address(dev: &USBDevice, gen: RtlGen) -> Result<[u8; 6], ()> {
    let order = match gen {
        RtlGen::Fe => [PLA_IDR, PLA_BACKUP],
        RtlGen::GbE => [PLA_BACKUP, PLA_IDR],
    };
    for base in order {
        let mut raw = [0u8; 8];
        ocp_read(dev, MCU_TYPE_PLA, base, &mut raw).await?;
        if let Some(mac) = mac_from_station_bytes(&raw) {
            return Ok(mac);
        }
    }
    Err(())
}

/// `PLA_CR` value with receiver + transmitter enabled (reset and
/// all other bits preserved from the read-back value).
pub fn cr_with_datapath_enabled(old: u8) -> u8 {
    (old & !CR_RST) | CR_RE | CR_TE
}

/// Full bind for an addressed RTL8152/8153 device: configuration,
/// endpoint setup, MAC-level bring-up, station-address read,
/// netdev publication, RX pump. Returns the device-record index.
async fn bind(device: Arc<USBDevice>) -> Result<usize, ()> {
    use core::fmt::Write;
    // Fetch the configuration descriptor (two-step like xpad:
    // 9-byte header for wTotalLength, then the full blob).
    let mut hdr = [0u8; 9];
    device
        .get_config_descriptor(0, &mut hdr)
        .await
        .map_err(|_| ())?;
    let total = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
    if !(9..=4096).contains(&total) {
        return Err(());
    }
    let mut cfg = vec![0u8; total];
    device
        .get_config_descriptor(0, &mut cfg)
        .await
        .map_err(|_| ())?;
    let cfg_value = cfg[5];
    let (in_ep, out_ep) = find_rtl_endpoints(&cfg).ok_or(())?;
    device
        .control_out(
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .map_err(|_| ())?;
    device
        .configure_endpoints(&[in_ep, out_ep])
        .await
        .map_err(|_| ())?;
    let bulk_in_dci = ((in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (out_ep.ep_addr & 0x0F) * 2;

    // ── MAC-level bring-up over the OCP protocol ──
    // Soft reset; CR_RST is self-clearing. Poll cooperatively
    // (scheduler yield between reads — never a busy spin on a
    // hardware register) and proceed even if it never clears:
    // the datapath enable below is the real gate.
    ocp_write_byte(&device, MCU_TYPE_PLA, PLA_CR, CR_RST).await?;
    for _ in 0..200 {
        let cr = ocp_read_byte(&device, MCU_TYPE_PLA, PLA_CR).await?;
        if cr & CR_RST == 0 {
            break;
        }
        narf_scheduler::yield_now().await;
    }
    // Chip version (diagnostic; the generation comes from the PID).
    let version = ocp_read_word(&device, MCU_TYPE_PLA, PLA_TCR1).await? & TCR1_VERSION_MASK;
    let gen = generation_for_pid(device.product_id());
    // Station address from the device itself — never invented.
    let mac = read_station_address(&device, gen).await?;
    // Multicast table wide open (RCR_AM does the policy), then the
    // accept filters, then the receive-size bound.
    ocp_write_dword(&device, MCU_TYPE_PLA, PLA_MAR, 0xFFFF_FFFF).await?;
    ocp_write_dword(&device, MCU_TYPE_PLA, PLA_MAR + 4, 0xFFFF_FFFF).await?;
    let rcr = ocp_read_dword(&device, MCU_TYPE_PLA, PLA_RCR).await?;
    ocp_write_dword(&device, MCU_TYPE_PLA, PLA_RCR, rcr_with_accept_filters(rcr)).await?;
    ocp_write_word(&device, MCU_TYPE_PLA, PLA_RMS, rx_max_size(gen)).await?;
    // Enable receiver + transmitter.
    let cr = ocp_read_byte(&device, MCU_TYPE_PLA, PLA_CR).await?;
    ocp_write_byte(&device, MCU_TYPE_PLA, PLA_CR, cr_with_datapath_enabled(cr)).await?;

    // ── Record + publication ──
    let idx = {
        let mut g = RTL_DEVICES.lock();
        let idx = g.len();
        g.push(RtlDevice {
            slot_id: device.slot_id(),
            generation: gen,
            mac,
            bulk_in_dci,
            bulk_out_dci,
            iface_name: format!("usb-rtl{}", idx),
            pump_running: false,
            link_byte: 0xFF,
            detached: false,
        });
        idx
    };
    let requested = {
        let g = RTL_DEVICES.lock();
        g[idx].iface_name.clone()
    };
    let assigned =
        narf_net::iface::register_with_context(&requested, mac, idx as u64, rtl_send_ctx);
    {
        let mut g = RTL_DEVICES.lock();
        g[idx].iface_name = assigned.clone();
        g[idx].pump_running = true;
    }
    let _ = writeln!(
        narf_console::Writer,
        "  net: r8152 bound slot {} as {} (gen {:?}, tcr1 version {:#06x}, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        device.slot_id(),
        assigned,
        gen,
        version,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    // Initial link sample, then the RX pump owns the device.
    sample_link(&device, idx).await;
    let pump_dev = device.clone();
    narf_scheduler::spawn(async move {
        rx_pump(pump_dev, idx).await;
    });
    Ok(idx)
}

/// Sample `PLA_PHYSTATUS` and republish link metadata on change.
async fn sample_link(device: &USBDevice, idx: usize) {
    let Ok(byte) = ocp_read_byte(device, MCU_TYPE_PLA, PLA_PHYSTATUS).await else {
        return;
    };
    let name = {
        let mut g = RTL_DEVICES.lock();
        let Some(rec) = g.get_mut(idx) else {
            return;
        };
        if rec.link_byte == byte {
            return;
        }
        rec.link_byte = byte;
        rec.iface_name.clone()
    };
    let (carrier, speed, duplex) = decode_link_status(byte);
    narf_net::iface::set_link_metadata(&name, carrier, speed, duplex);
}

/// RX pump-stop predicate: the pump runs until its record's flag
/// clears (device removal — the detach follow-on — clears it) or
/// the record vanishes.
fn pump_should_continue(idx: usize) -> bool {
    let g = RTL_DEVICES.lock();
    g.get(idx).map(|d| d.pump_running).unwrap_or(false)
}

/// Supervised RX pump: post bulk-IN reads, walk each aggregation
/// buffer, hand every frame to the stack. Stops after a bounded
/// run of consecutive transfer errors (a removed device surfaces
/// as persistent errors) or when the record's flag clears.
async fn rx_pump(device: Arc<USBDevice>, idx: usize) {
    let bulk_in_dci = {
        let g = RTL_DEVICES.lock();
        let Some(rec) = g.get(idx) else {
            return;
        };
        rec.bulk_in_dci
    };
    let mut buf = vec![0u8; RX_BUF_LEN];
    let mut errors = 0u32;
    let mut turns = 0u32;
    while pump_should_continue(idx) {
        match device.bulk_in(bulk_in_dci, &mut buf).await {
            Ok(n) if n > 0 => {
                errors = 0;
                let name = {
                    let g = RTL_DEVICES.lock();
                    g.get(idx).map(|d| d.iface_name.clone())
                };
                if let Some(name) = name {
                    for seg in parse_rx_aggregate(&buf[..n]) {
                        let mut frame = buf[seg.offset..seg.offset + seg.len].to_vec();
                        narf_net::iface::on_rx_frame_from(&name, &mut frame);
                    }
                }
            }
            Ok(_) => narf_scheduler::yield_now().await,
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
        turns = turns.wrapping_add(1);
        if turns % 32 == 0 {
            sample_link(&device, idx).await;
        }
    }
    let mut g = RTL_DEVICES.lock();
    if let Some(rec) = g.get_mut(idx) {
        rec.pump_running = false;
    }
}

// ── Class-registry probe ─────────────────────────────────────────

const MATCHES: &[UsbClassMatch] = &[
    // Realtek
    UsbClassMatch::vid_pid(0x0BDA, 0x8050),
    UsbClassMatch::vid_pid(0x0BDA, 0x8053),
    UsbClassMatch::vid_pid(0x0BDA, 0x8152),
    UsbClassMatch::vid_pid(0x0BDA, 0x8153),
    UsbClassMatch::vid_pid(0x0BDA, 0x8155),
    UsbClassMatch::vid_pid(0x0BDA, 0x8156),
    UsbClassMatch::vid_pid(0x0BDA, 0x8157),
    // Microsoft
    UsbClassMatch::vid_pid(0x045E, 0x07ab),
    UsbClassMatch::vid_pid(0x045E, 0x07c6),
    UsbClassMatch::vid_pid(0x045E, 0x0927),
    UsbClassMatch::vid_pid(0x045E, 0x0c5e),
    // Samsung
    UsbClassMatch::vid_pid(0x04E8, 0xa101),
    // Lenovo
    UsbClassMatch::vid_pid(0x17EF, 0x304f),
    UsbClassMatch::vid_pid(0x17EF, 0x3054),
    UsbClassMatch::vid_pid(0x17EF, 0x3062),
    UsbClassMatch::vid_pid(0x17EF, 0x3069),
    // TP-Link (UE300 family)
    UsbClassMatch::vid_pid(0x2357, 0x0601),
    // Linksys (USB3GIG)
    UsbClassMatch::vid_pid(0x13B1, 0x0041),
    // NVIDIA (Shield controller dock NIC)
    UsbClassMatch::vid_pid(0x0955, 0x09ff),
];

fn probe(device: Arc<USBDevice>) -> Result<(), UsbProbeError> {
    // The registry probe is synchronous, but bind needs async
    // control transfers — spawn it (xpad precedent).
    narf_scheduler::spawn_stackful(async move {
        use core::fmt::Write;
        if bind(device).await.is_err() {
            let _ = writeln!(
                narf_console::Writer,
                "  net: r8152 bind failed (no valid station address or config error)"
            );
        }
    });
    Ok(())
}

/// Detach hook for a slot: tombstone every RTL record bound to
/// it and unregister its net iface. The pump exits at its next
/// `pump_should_continue` check once `pump_running` clears;
/// TX resolves to `None` instead of retargeting a later device
/// (records are never removed — the ECM/NCM rule: net-registry
/// TX cookies are record indices). Unknown slots no-op; repeat
/// detach is a silent no-op (unregister is idempotent).
///
/// Panic-free and idempotent by the #893 hook contract: no
/// indexing and no fallible unwraps on any path. Tombstones
/// are set under the registry lock and iface names collected
/// there, but the net unregister runs after the lock is
/// released — the net registry lock must never be taken while
/// the RTL registry lock is held (UVC collect-then-unregister
/// pattern). A TX already past `tx_target` when detach lands
/// may still hit the wire; every later TX fail-closes.
///
/// Infallible bookkeeping, adapted to the [`UsbUnbindFn`]
/// contract with an unconditional `Ok(())` (#893: a hook
/// reports failure with `Err(())`, never by panicking).
pub fn detach_r8152_slot(slot_id: u8) -> Result<(), ()> {
    let ifaces: Vec<String> = {
        let mut g = RTL_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g.iter_mut().filter(|d| d.slot_id == slot_id && !d.detached) {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
    Ok(())
}

/// Wholesale variant of [`detach_r8152_slot`] for controller
/// recovery (`attach::detach_all_bindings`): tombstone every
/// RTL binding and unregister every net iface, regardless of
/// slot. Infallible and idempotent, same pump-exit and
/// never-remove reasoning as [`detach_r8152_slot`].
pub fn detach_all_r8152() {
    let ifaces: Vec<String> = {
        let mut g = RTL_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g.iter_mut().filter(|d| !d.detached) {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
}

/// Register the r8152 USB class driver, together with its
/// detach hook. The probe spawns the async bind (xpad
/// precedent); the unbind hook adapts infallible
/// `detach_r8152_slot` to the fallible `UsbUnbindFn` contract
/// with an unconditional `Ok(())` (#893: a hook reports
/// failure with `Err(())`, never by panicking).
pub fn register() {
    let _ = register_class_driver_with_unbind("r8152", MATCHES, probe, detach_r8152_slot);
}

// ── Fixtures ─────────────────────────────────────────────────────
//
// Modelled-device fixtures in the crate's kernel-test style: the
// register conversation is pinned at the level the production
// code composes it — SETUP-packet packing for each access class,
// the bind's pure decision functions run against modelled
// register contents, and the RX/TX wire formats as byte fixtures.

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_r8152_ocp_setup_packing() -> TestResult {
        // Dword read of PLA_IDR: vendor IN, req 0x05, wValue =
        // address, wIndex = PLA window alone (dword reads pass no
        // byte-enable).
        let (rt, rq, wv, wi) = ocp_read_setup(MCU_TYPE_PLA, PLA_IDR);
        if (rt, rq, wv, wi) != (0xC0, 0x05, 0xC000, 0x0100) {
            return TestResult::Fail("OCP read setup packing wrong");
        }
        // Dword write: wIndex gains the dword byte-enable.
        let (rt, rq, wv, wi, data) = ocp_write_dword_pack(MCU_TYPE_PLA, PLA_RCR, 0x0000_000E);
        if (rt, rq, wv, wi) != (0x40, 0x05, 0xC010, 0x01FF) || data != [0x0E, 0, 0, 0] {
            return TestResult::Fail("OCP dword write packing wrong");
        }
        // Word write at PLA_RMS (0xC016): aligned down to 0xC014,
        // byte-enable 0x33 << 2 in wIndex, value in the high lanes.
        let (_, _, wv, wi, data) = ocp_write_word_pack(MCU_TYPE_PLA, PLA_RMS, 1522);
        if wv != 0xC014 || wi != 0x01CC || data != [0, 0, 0xF2, 0x05] {
            return TestResult::Fail("OCP word write packing wrong");
        }
        // Byte write at PLA_CR (0xE813): aligned to 0xE810, enable
        // 0x11 << 3, value in lane 3.
        let (_, _, wv, wi, data) = ocp_write_byte_pack(MCU_TYPE_PLA, PLA_CR, CR_RST);
        if wv != 0xE810 || wi != 0x0188 || data != [0, 0, 0, CR_RST] {
            return TestResult::Fail("OCP byte write packing wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_ocp_setup_packing);

    fn smoke_r8152_station_address_validation() -> TestResult {
        let good: [u8; 8] = [0x00, 0xE0, 0x4C, 0x36, 0x0A, 0xBC, 0, 0];
        if mac_from_station_bytes(&good) != Some([0x00, 0xE0, 0x4C, 0x36, 0x0A, 0xBC]) {
            return TestResult::Fail("valid station address rejected");
        }
        if mac_from_station_bytes(&[0u8; 8]).is_some() {
            return TestResult::Fail("all-zero address accepted");
        }
        if mac_from_station_bytes(&[0xFFu8; 8]).is_some() {
            return TestResult::Fail("all-ones address accepted");
        }
        let multicast: [u8; 8] = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01, 0, 0];
        if mac_from_station_bytes(&multicast).is_some() {
            return TestResult::Fail("multicast address accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_station_address_validation);

    fn smoke_r8152_rcr_and_cr_updates() -> TestResult {
        // Start from a modelled RCR with unrelated high bits set
        // and promiscuous on: filters land, AAP clears, rest kept.
        let old = 0xDEAD_0000 | RCR_AAP;
        let new = rcr_with_accept_filters(old);
        if new & RCR_AAP != 0 || new & (RCR_APM | RCR_AM | RCR_AB) != RCR_APM | RCR_AM | RCR_AB {
            return TestResult::Fail("RCR accept-filter update wrong");
        }
        if new & 0xFFFF_0000 != 0xDEAD_0000 {
            return TestResult::Fail("RCR unrelated bits clobbered");
        }
        // CR: RE|TE set, RST clear, other bits preserved.
        let cr = cr_with_datapath_enabled(0x02);
        if cr != 0x02 | CR_RE | CR_TE {
            return TestResult::Fail("CR datapath-enable update wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rcr_and_cr_updates);

    fn smoke_r8152_link_status_decode() -> TestResult {
        let (carrier, speed, duplex) = decode_link_status(0);
        if carrier || speed.is_some() || duplex.is_some() {
            return TestResult::Fail("link-down byte decoded as up");
        }
        let (carrier, speed, duplex) =
            decode_link_status(PHYSTAT_LINK | PHYSTAT_1000M | PHYSTAT_FULL_DUP);
        if !carrier || speed != Some(1000) || duplex != Some(narf_net::iface::LinkDuplex::Full) {
            return TestResult::Fail("gigabit full-duplex link decoded wrong");
        }
        let (carrier, speed, duplex) = decode_link_status(PHYSTAT_LINK | PHYSTAT_100M);
        if !carrier || speed != Some(100) || duplex != Some(narf_net::iface::LinkDuplex::Half) {
            return TestResult::Fail("100M half-duplex link decoded wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_link_status_decode);

    fn datagram_frame(len: usize, fill: u8) -> Vec<u8> {
        let mut f = alloc::vec::Vec::new();
        f.resize(len, fill);
        f
    }

    fn smoke_r8152_rx_aggregate_walk() -> TestResult {
        // Two valid frames then a runt descriptor: the walk must
        // yield exactly the two frames and stop at the runt.
        let f1 = datagram_frame(60, 0xA5);
        let f2 = datagram_frame(100, 0x3C);
        let mut buf = alloc::vec::Vec::new();
        let push_seg = |buf: &mut Vec<u8>, frame: &[u8]| {
            buf.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // opts1
            buf.extend_from_slice(&[0u8; 20]); // opts2..opts6
            buf.extend_from_slice(frame);
        };
        push_seg(&mut buf, &f1);
        push_seg(&mut buf, &f2);
        buf.extend_from_slice(&10u32.to_le_bytes()); // runt opts1
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(&[0u8; 10]);
        let segs = parse_rx_aggregate(&buf);
        if segs.len() != 2 {
            return TestResult::Fail("aggregate walk yielded wrong frame count");
        }
        if segs[0]
            != (RxSegment {
                offset: RX_DESC_LEN,
                len: 60,
            })
        {
            return TestResult::Fail("first segment location wrong");
        }
        if segs[1]
            != (RxSegment {
                offset: RX_DESC_LEN + 60 + RX_DESC_LEN,
                len: 100,
            })
        {
            return TestResult::Fail("second segment location wrong");
        }
        if &buf[segs[0].offset..segs[0].offset + segs[0].len] != f1.as_slice()
            || &buf[segs[1].offset..segs[1].offset + segs[1].len] != f2.as_slice()
        {
            return TestResult::Fail("segment payload bytes wrong");
        }
        // Truncated tail: length field runs past the buffer → stop.
        let mut bad = datagram_frame(60, 0x11);
        bad[0..4].copy_from_slice(&500u32.to_le_bytes());
        let mut agg = alloc::vec::Vec::new();
        agg.extend_from_slice(&bad[0..4]);
        agg.extend_from_slice(&[0u8; 20]);
        agg.extend_from_slice(&bad[4..]);
        if !parse_rx_aggregate(&agg).is_empty() {
            return TestResult::Fail("over-long segment not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_rx_aggregate_walk);

    fn smoke_r8152_tx_segment_build() -> TestResult {
        let frame = datagram_frame(61, 0x5A);
        let mut out = Vec::new();
        if build_tx_segment(&frame, &mut out).is_err() {
            return TestResult::Fail("clean frame rejected");
        }
        // 8-byte desc + 61-byte frame = 69, padded to 72.
        if out.len() != 72 {
            return TestResult::Fail("TX segment padding wrong");
        }
        let opts1 = u32::from_le_bytes(out[0..4].try_into().unwrap());
        if opts1 != 61 | TX_FS | TX_LS {
            return TestResult::Fail("TX opts1 wrong");
        }
        if out[4..8] != [0, 0, 0, 0] {
            return TestResult::Fail("TX opts2 not zero");
        }
        if out[8..69] != frame[..] || out[69..] != [0, 0, 0] {
            return TestResult::Fail("TX payload/padding bytes wrong");
        }
        // Oversize frame (> TX_LEN_MASK) refused.
        let big = datagram_frame(TX_LEN_MASK as usize + 1, 0);
        if build_tx_segment(&big, &mut Vec::new()).is_ok() {
            return TestResult::Fail("oversize frame accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_segment_build);

    fn smoke_r8152_endpoint_finder() -> TestResult {
        // Modelled RTL8153 configuration: config header, a vendor
        // interface (class 0xFF) with bulk IN 0x81 / OUT 0x02 and
        // an interrupt endpoint that must be ignored.
        #[rustfmt::skip]
        let cfg: &[u8] = &[
            9, 2, 32, 0, 1, 1, 0, 0x80, 0x32, // config
            9, 4, 0, 0, 3, 0xFF, 0, 0, 0,    // vendor interface
            7, 5, 0x81, 2, 0x00, 0x04, 0,    // bulk IN, 1024
            7, 5, 0x02, 2, 0x00, 0x04, 0,    // bulk OUT, 1024
            7, 5, 0x83, 3, 16, 0, 8,         // interrupt IN
        ];
        let (i, o) = match find_rtl_endpoints(cfg) {
            Some(t) => t,
            None => return TestResult::Fail("modelled endpoints not found"),
        };
        if i.ep_addr != 0x81 || o.ep_addr != 0x02 || i.max_packet != 1024 {
            return TestResult::Fail("modelled endpoints decoded wrong");
        }
        // A CDC-class config has no vendor interface → no match.
        #[rustfmt::skip]
        let cdc: &[u8] = &[
            9, 2, 25, 0, 1, 1, 0, 0x80, 0x32,
            9, 4, 0, 0, 2, 0x0A, 0, 0, 0,
            7, 5, 0x81, 2, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
        ];
        if find_rtl_endpoints(cdc).is_some() {
            return TestResult::Fail("CDC config falsely claimed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_endpoint_finder);

    fn smoke_r8152_modelled_bind_conversation() -> TestResult {
        // Walk the bind's register conversation against a modelled
        // register file: the modelled device answers the IDR read
        // with its programmed station address, and the writes the
        // bind would issue are checked field by field.
        // 1. Read station address from PLA_IDR.
        let (rt, rq, wv, wi) = ocp_read_setup(MCU_TYPE_PLA, PLA_IDR);
        if (rt, rq, wv, wi) != (0xC0, 0x05, PLA_IDR, MCU_TYPE_PLA) {
            return TestResult::Fail("conversation: IDR read setup wrong");
        }
        let modelled_idr: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0, 0];
        let mac = match mac_from_station_bytes(&modelled_idr) {
            Some(m) => m,
            None => return TestResult::Fail("conversation: modelled MAC rejected"),
        };
        if mac != [0x10, 0x20, 0x30, 0x40, 0x50, 0x60] {
            return TestResult::Fail("conversation: MAC bytes wrong");
        }
        // 2. Multicast table: two dword writes of all-ones at
        //    PLA_MAR / PLA_MAR+4.
        for addr in [PLA_MAR, PLA_MAR + 4] {
            let (_, _, wv, wi, data) = ocp_write_dword_pack(MCU_TYPE_PLA, addr, 0xFFFF_FFFF);
            if wv != addr || wi != MCU_TYPE_PLA | BYTE_EN_DWORD || data != [0xFF; 4] {
                return TestResult::Fail("conversation: MAR write wrong");
            }
        }
        // 3. RCR write carries the accept-filter update of the
        //    modelled reset value 0.
        let (_, _, wv, _, data) =
            ocp_write_dword_pack(MCU_TYPE_PLA, PLA_RCR, rcr_with_accept_filters(0));
        if wv != PLA_RCR || data != (RCR_APM | RCR_AM | RCR_AB).to_le_bytes() {
            return TestResult::Fail("conversation: RCR write wrong");
        }
        // 4. CR byte write enables RE|TE at PLA_CR.
        let (_, _, wv, wi, data) =
            ocp_write_byte_pack(MCU_TYPE_PLA, PLA_CR, cr_with_datapath_enabled(0));
        if wv != PLA_CR & !3 || wi != 0x0188 || data != [0, 0, 0, CR_RE | CR_TE] {
            return TestResult::Fail("conversation: CR enable write wrong");
        }
        // 5. Generation/RMS pairing the bind programs.
        if generation_for_pid(0x8152) != RtlGen::Fe || rx_max_size(RtlGen::Fe) != 1522 {
            return TestResult::Fail("conversation: FE generation mapping wrong");
        }
        if generation_for_pid(0x8153) != RtlGen::GbE || rx_max_size(RtlGen::GbE) != 9216 {
            return TestResult::Fail("conversation: GbE generation mapping wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_modelled_bind_conversation);

    fn smoke_r8152_tx_routing_two_devices() -> TestResult {
        // Two modelled devices in the table: tx_target must
        // resolve each record index to ITS OWN slot/endpoint —
        // the per-device routing the send trampoline relies on.
        RTL_DEVICES.lock().clear();
        let mk = |slot_id: u8, out_dci: u8| RtlDevice {
            slot_id,
            generation: RtlGen::GbE,
            mac: [0x02, 0, 0, 0, 0, slot_id],
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            iface_name: alloc::format!("usb-rtl-model-{}", slot_id),
            pump_running: false,
            link_byte: 0xFF,
            detached: false,
        };
        {
            let mut g = RTL_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        let t0 = tx_target(0);
        let t1 = tx_target(1);
        RTL_DEVICES.lock().clear();
        if t0 != Some((7, 4)) || t1 != Some((9, 6)) {
            return TestResult::Fail("tx_target mis-routed between devices");
        }
        if tx_target(0).is_some() {
            return TestResult::Fail("tx_target resolved a removed device");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/r8152", smoke_r8152_tx_routing_two_devices);

    /// Two modelled RTL devices bind; detaching the first
    /// tombstones exactly its record (TX fail-closes, net iface
    /// unregisters, survivor untouched), detach is idempotent
    /// and a no-op for unknown slots, wholesale detach clears
    /// the rest, and a re-push of the same slot publishes under
    /// a fresh index — never a duplicate iface, never a
    /// retargeted TX cookie. Masking-defeating case: the
    /// detached record's pump had already exited
    /// (`pump_running` false before detach) yet detach still
    /// tombstones + unregisters.
    fn smoke_r8152_detach_tombstones_and_unregisters() -> TestResult {
        RTL_DEVICES.lock().clear();
        let mk = |slot_id: u8, out_dci: u8| RtlDevice {
            slot_id,
            generation: RtlGen::GbE,
            mac: [0x02, 0, 0, 0, 0, slot_id],
            bulk_in_dci: 3,
            bulk_out_dci: out_dci,
            iface_name: alloc::format!("usb-rtl-detach{}", slot_id),
            pump_running: true,
            link_byte: 0xFF,
            detached: false,
        };
        {
            let mut g = RTL_DEVICES.lock();
            g.push(mk(7, 4));
            g.push(mk(9, 6));
        }
        // Register the net ifaces for real, capturing the
        // assigned names, so the unregister half is asserted
        // against the net registry, not trusted. Names follow
        // the production rule (`usb-rtl{record index}`).
        let (name7, name9) = {
            let mut g = RTL_DEVICES.lock();
            let n7 = narf_net::iface::register_with_context(
                "usb-rtl0",
                [0x02, 0, 0, 0, 0, 7],
                0,
                rtl_send_ctx,
            );
            let n9 = narf_net::iface::register_with_context(
                "usb-rtl1",
                [0x02, 0, 0, 0, 0, 9],
                1,
                rtl_send_ctx,
            );
            g[0].iface_name = n7.clone();
            g[1].iface_name = n9.clone();
            (n7, n9)
        };
        if narf_net::iface::lookup(&name7).is_none() || narf_net::iface::lookup(&name9).is_none() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("net ifaces must resolve before detach");
        }
        // Simulate the first pump having already exited.
        {
            let mut g = RTL_DEVICES.lock();
            g[0].pump_running = false;
        }
        if detach_r8152_slot(7).is_err() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("detach must be infallible");
        }
        let ok = tx_target(0).is_none()
            && narf_net::iface::lookup(&name7).is_none()
            && tx_target(1) == Some((9, 6))
            && narf_net::iface::lookup(&name9).is_some();
        if !ok {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("detach must tombstone exactly one binding");
        }
        // Idempotent, and unknown slots are a silent no-op.
        let _ = detach_r8152_slot(7);
        let _ = detach_r8152_slot(99);
        if tx_target(1) != Some((9, 6)) {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("repeat/unknown detach must not change the registry");
        }
        detach_all_r8152();
        if tx_target(1).is_some() || narf_net::iface::lookup(&name9).is_some() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("wholesale detach must clear every binding");
        }
        // Re-push the same slot: records are never removed, so
        // the new record lands at a fresh index with a fresh
        // iface name — never a duplicate, never a recycled
        // cookie. The re-bound name follows the production
        // rule (`usb-rtl{record index}`), exactly as bind
        // assigns it.
        let idx = {
            let mut g = RTL_DEVICES.lock();
            let idx = g.len();
            g.push(mk(7, 4));
            g[idx].iface_name = alloc::format!("usb-rtl{}", idx);
            idx
        };
        if idx != 2 {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("re-bind must not reuse a tombstoned index");
        }
        let fresh = {
            let g = RTL_DEVICES.lock();
            g[idx].iface_name.clone()
        };
        if fresh == name7 {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("re-bind must not recycle the detached iface name");
        }
        let _ = detach_r8152_slot(7);
        if tx_target(idx).is_some() {
            RTL_DEVICES.lock().clear();
            return TestResult::Fail("cleanup detach must leave no live binding");
        }
        RTL_DEVICES.lock().clear();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/r8152",
        smoke_r8152_detach_tombstones_and_unregisters
    );

    /// The class-registry unbind hook installed by
    /// `r8152::register` must reach `detach_r8152_slot`
    /// through the supervisor's `dispatch_unbind` path — the
    /// wiring the hub-detach path actually uses, not just the
    /// detach function in isolation.
    fn smoke_r8152_dispatch_unbind_reaches_detach() -> TestResult {
        RTL_DEVICES.lock().clear();
        {
            let mut g = RTL_DEVICES.lock();
            g.push(RtlDevice {
                slot_id: 7,
                generation: RtlGen::GbE,
                mac: [0x02, 0, 0, 0, 0, 7],
                bulk_in_dci: 3,
                bulk_out_dci: 4,
                iface_name: alloc::format!("usb-rtl-detach{}", 7),
                pump_running: true,
                link_byte: 0xFF,
                detached: false,
            });
        }
        register();
        let report = crate::class_registry::dispatch_unbind(7);
        let live = tx_target(0);
        RTL_DEVICES.lock().clear();
        if report.invoked == 0 {
            return TestResult::Fail("dispatch_unbind invoked no hooks");
        }
        if live.is_some() {
            return TestResult::Fail("unbind hook must tombstone the slot 7 binding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/r8152",
        smoke_r8152_dispatch_unbind_reaches_detach
    );
}
