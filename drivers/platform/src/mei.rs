//! Intel MEI / HECI — the host interface to the Converged Security
//! and Manageability Engine (CSME).
//!
//! ## Reference
//!
//! Linux v7.3-rc4 `drivers/misc/mei/` (GPL-2.0; NARF is
//! GPL-2.0-or-later so adaptation is permitted):
//!
//! - `hw-me-regs.h` — PCI device IDs, the four MMIO registers, the
//!   H_CSR / ME_CSR_HA bit fields, and the config-space firmware
//!   status registers.
//! - `hw-me.c`      — `mei_me_hw_config`, `mei_me_hw_reset`,
//!   `mei_me_host_set_ready`, `mei_hbuf_filled_slots`,
//!   `mei_me_count_full_read_slots`, `mei_me_hbuf_write`.
//! - `hw.h`         — `struct mei_msg_hdr`, the HBM command IDs, the
//!   host-bus-message version.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** exposes CSME HECI-1 at PCI `00:16.0`
//! (`8086:e370`, "Panther Lake H"), which is the interface Linux's
//! `mei_me` binds. The board also shows a second HECI-class function
//! at `00:18.0` (`8086:e35d`); that ID is **not** in Linux's
//! `mei_me_pci_tbl`, nothing binds it there, and this driver does
//! not claim it either.
//!
//! ## What the hardware looks like
//!
//! HECI is four 32-bit MMIO registers in BAR0 and two circular
//! buffers measured in 4-byte *slots*:
//!
//! | offset | register    | direction                          |
//! |--------|-------------|------------------------------------|
//! | 0x00   | `H_CB_WW`   | host → firmware write window       |
//! | 0x04   | `H_CSR`     | host control/status (read-write)   |
//! | 0x08   | `ME_CB_RW`  | firmware → host read window        |
//! | 0x0C   | `ME_CSR_HA` | firmware control/status (read-only)|
//!
//! Each CSR packs the buffer depth (bits 31:24), write pointer
//! (23:16) and read pointer (15:8) alongside the ready / reset /
//! interrupt bits. The pointers are free-running bytes: the number of
//! filled slots is `(write_ptr - read_ptr)` **in `u8` wrapping
//! arithmetic**, which is why [`filled_slots`] does the subtraction
//! with `wrapping_sub` rather than a signed compare.
//!
//! ## Scope
//!
//! Link-level bring-up plus the first host-bus-message exchange:
//!
//! 1. Map BAR0, latch the host buffer depth from `H_CSR.H_CBD`.
//! 2. Reset the link (`H_RST`), wait for `ME_CSR_HA.ME_RDY`, release
//!    the reset, then publish `H_RDY`.
//! 3. Send `HOST_START_REQ_CMD` with HBM version 2.2 and read the
//!    `HOST_START_RES_CMD` reply.
//! 4. Send `HOST_ENUM_REQ_CMD` and keep the 256-bit bitmap of
//!    firmware clients the response carries.
//! 5. Read the firmware status words out of config space for the
//!    boot transcript.
//!
//! Per-client connect / disconnect, flow control, and the character
//! devices Linux exposes as `/dev/mei0` are **not** implemented. The
//! in-tree consumers that would want them — `crypto/hdcp.rs` and a
//! future PTT (fTPM-over-MEI) path — connect to a named client UUID,
//! which needs the `HOST_CLIENT_PROPERTIES` walk and per-client flow
//! control on top of what lands here.

extern crate alloc;

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `hw-me-regs.h`. Only the recent PCH generations are listed;
// the register layout below has been stable since Cannon Lake, but
// claiming a controller we have not reasoned about buys nothing.

/// Intel.
pub const MEI_VENDOR: u16 = 0x8086;

/// Cannon Lake Point H.
pub const MEI_DEV_CNP_H: u16 = 0xA360;
/// Comet Lake Point LP.
pub const MEI_DEV_CMP_LP: u16 = 0x02E0;
/// Comet Lake Point H.
pub const MEI_DEV_CMP_H: u16 = 0x06E0;
/// Tiger Lake Point LP.
pub const MEI_DEV_TGP_LP: u16 = 0xA0E0;
/// Tiger Lake Point H.
pub const MEI_DEV_TGP_H: u16 = 0x43E0;
/// Alder Lake Point S.
pub const MEI_DEV_ADP_S: u16 = 0x7AE8;
/// Alder Lake Point LP.
pub const MEI_DEV_ADP_LP: u16 = 0x7A60;
/// Alder Lake Point P.
pub const MEI_DEV_ADP_P: u16 = 0x51E0;
/// Alder Lake Point N.
pub const MEI_DEV_ADP_N: u16 = 0x54E0;
/// Raptor Lake Point S.
pub const MEI_DEV_RPL_S: u16 = 0x7A68;
/// Meteor Lake Point M.
pub const MEI_DEV_MTL_M: u16 = 0x7E70;
/// Arrow Lake Point S.
pub const MEI_DEV_ARL_S: u16 = 0x7F68;
/// Arrow Lake Point H.
pub const MEI_DEV_ARL_H: u16 = 0x7770;
/// Lunar Lake Point M.
pub const MEI_DEV_LNL_M: u16 = 0xA870;
/// Panther Lake H — the MS-03's HECI-1 at `00:16.0`.
pub const MEI_DEV_PTL_H: u16 = 0xE370;
/// Panther Lake P.
pub const MEI_DEV_PTL_P: u16 = 0xE470;
/// Wildcat Lake P.
pub const MEI_DEV_WCL_P: u16 = 0x4D70;

/// Every device ID this driver claims, in one `const` so
/// `register_pci_driver` and the match-table smoke cannot drift.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    MEI_DEV_CNP_H,
    MEI_DEV_CMP_LP,
    MEI_DEV_CMP_H,
    MEI_DEV_TGP_LP,
    MEI_DEV_TGP_H,
    MEI_DEV_ADP_S,
    MEI_DEV_ADP_LP,
    MEI_DEV_ADP_P,
    MEI_DEV_ADP_N,
    MEI_DEV_RPL_S,
    MEI_DEV_MTL_M,
    MEI_DEV_ARL_S,
    MEI_DEV_ARL_H,
    MEI_DEV_LNL_M,
    MEI_DEV_PTL_H,
    MEI_DEV_PTL_P,
    MEI_DEV_WCL_P,
];

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&did)
}

// ── MMIO registers (BAR0) ───────────────────────────────────────────

/// HECI puts its register block in BAR0.
pub const MEI_BAR: u8 = 0;

/// `H_CB_WW` — Host Circular Buffer Write Window. Write-only; each
/// 32-bit store pushes one slot towards firmware.
pub const REG_H_CB_WW: u64 = 0x00;
/// `H_CSR` — Host Control Status.
pub const REG_H_CSR: u64 = 0x04;
/// `ME_CB_RW` — ME Circular Buffer Read Window. Read-only; each
/// 32-bit load pops one slot from firmware.
pub const REG_ME_CB_RW: u64 = 0x08;
/// `ME_CSR_HA` — ME Control Status, Host Access. Read-only.
pub const REG_ME_CSR_HA: u64 = 0x0C;
/// `H_D0I3C` — D0i3 control.
pub const REG_H_D0I3C: u64 = 0x800;

// H_CSR fields.
/// Host circular-buffer depth, in slots (bits 31:24).
pub const H_CBD: u32 = 0xFF00_0000;
/// Host circular-buffer write pointer (bits 23:16).
pub const H_CBWP: u32 = 0x00FF_0000;
/// Host circular-buffer read pointer (bits 15:8).
pub const H_CBRP: u32 = 0x0000_FF00;
/// Host Reset.
pub const H_RST: u32 = 0x0000_0010;
/// Host Ready.
pub const H_RDY: u32 = 0x0000_0008;
/// Host Interrupt Generate — the doorbell.
pub const H_IG: u32 = 0x0000_0004;
/// Host Interrupt Status (write-1-to-clear).
pub const H_IS: u32 = 0x0000_0002;
/// Host Interrupt Enable.
pub const H_IE: u32 = 0x0000_0001;
/// Host D0i3 Interrupt Enable.
pub const H_D0I3C_IE: u32 = 0x0000_0020;
/// Host D0i3 Interrupt Status.
pub const H_D0I3C_IS: u32 = 0x0000_0040;
/// All interrupt-enable bits of `H_CSR`.
pub const H_CSR_IE_MASK: u32 = H_IE | H_D0I3C_IE;
/// All interrupt-status bits of `H_CSR`.
pub const H_CSR_IS_MASK: u32 = H_IS | H_D0I3C_IS;

// ME_CSR_HA fields — same layout, host-read-only.
/// ME circular-buffer depth (bits 31:24).
pub const ME_CBD_HRA: u32 = 0xFF00_0000;
/// ME circular-buffer write pointer (bits 23:16).
pub const ME_CBWP_HRA: u32 = 0x00FF_0000;
/// ME circular-buffer read pointer (bits 15:8).
pub const ME_CBRP_HRA: u32 = 0x0000_FF00;
/// ME Reset.
pub const ME_RST_HRA: u32 = 0x0000_0010;
/// ME Ready.
pub const ME_RDY_HRA: u32 = 0x0000_0008;
/// ME Interrupt Generate.
pub const ME_IG_HRA: u32 = 0x0000_0004;
/// ME Interrupt Status.
pub const ME_IS_HRA: u32 = 0x0000_0002;
/// ME Interrupt Enable.
pub const ME_IE_HRA: u32 = 0x0000_0001;

/// One circular-buffer slot is a `u32`. `MEI_SLOT_SIZE` in Linux.
pub const MEI_SLOT_SIZE: usize = 4;

// ── Firmware status registers (PCI config space) ────────────────────

/// `PCI_CFG_HFS_1` — the primary Host Firmware Status word.
pub const PCI_CFG_HFS_1: u16 = 0x40;
/// `PCI_CFG_HFS_1_D0I3_MSK` — firmware supports D0i3.
pub const PCI_CFG_HFS_1_D0I3: u32 = 0x8000_0000;
/// `PCI_CFG_HFS_2`.
pub const PCI_CFG_HFS_2: u16 = 0x48;
/// `PCI_CFG_HFS_3`.
pub const PCI_CFG_HFS_3: u16 = 0x60;
/// `PCI_CFG_HFS_4`.
pub const PCI_CFG_HFS_4: u16 = 0x64;
/// `PCI_CFG_HFS_5`.
pub const PCI_CFG_HFS_5: u16 = 0x68;
/// `PCI_CFG_HFS_6`.
pub const PCI_CFG_HFS_6: u16 = 0x6C;

// ── Host Bus Messages ───────────────────────────────────────────────

/// HBM version this driver advertises — `HBM_MAJOR_VERSION`.
pub const HBM_MAJOR_VERSION: u8 = 2;
/// `HBM_MINOR_VERSION`.
pub const HBM_MINOR_VERSION: u8 = 2;

/// Mask selecting the opcode out of an HBM command byte.
pub const MEI_HBM_CMD_OP_MSK: u8 = 0x7F;
/// Bit set by firmware on a response.
pub const MEI_HBM_CMD_RES_MSK: u8 = 0x80;

/// `HOST_START_REQ_CMD`.
pub const HOST_START_REQ_CMD: u8 = 0x01;
/// `HOST_START_RES_CMD`.
pub const HOST_START_RES_CMD: u8 = 0x81;
/// `HOST_STOP_REQ_CMD`.
pub const HOST_STOP_REQ_CMD: u8 = 0x02;
/// `HOST_STOP_RES_CMD`.
pub const HOST_STOP_RES_CMD: u8 = 0x82;
/// `ME_STOP_REQ_CMD` — firmware is going away.
pub const ME_STOP_REQ_CMD: u8 = 0x03;
/// `HOST_ENUM_REQ_CMD`.
pub const HOST_ENUM_REQ_CMD: u8 = 0x04;
/// `HOST_ENUM_RES_CMD`.
pub const HOST_ENUM_RES_CMD: u8 = 0x84;
/// `HOST_CLIENT_PROPERTIES_REQ_CMD`.
pub const HOST_CLIENT_PROPERTIES_REQ_CMD: u8 = 0x05;
/// `HOST_CLIENT_PROPERTIES_RES_CMD`.
pub const HOST_CLIENT_PROPERTIES_RES_CMD: u8 = 0x85;

/// The HBM "address" every bus message is sent to and from — both
/// `me_addr` and `host_addr` are 0 for bus messages, which is what
/// distinguishes them from client traffic.
pub const MEI_HBM_ADDR: u8 = 0;

/// Bytes in the client bitmap a `HOST_ENUM_RES_CMD` carries: 256
/// firmware addresses, one bit each.
pub const MEI_CLIENTS_MAX: usize = 256;
/// Size of that bitmap in bytes.
pub const HBM_CLIENT_BITMAP_BYTES: usize = MEI_CLIENTS_MAX / 8;

/// `struct mei_msg_hdr` — one 32-bit word.
///
/// Linux declares it as a bitfield over a `u32`; the packing, from
/// least-significant bit upwards, is `me_addr:8`, `host_addr:8`,
/// `length:9`, `reserved:3`, `extended:1`, `dma_ring:1`,
/// `internal:1`, `msg_complete:1`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MeiMsgHdr {
    pub me_addr: u8,
    pub host_addr: u8,
    /// Payload length in bytes; 9 bits, so at most 511.
    pub length: u16,
    pub extended: bool,
    pub dma_ring: bool,
    pub internal: bool,
    /// Set on the last packet of a message.
    pub msg_complete: bool,
}

impl MeiMsgHdr {
    /// Encode to the 32-bit word written into `H_CB_WW`.
    pub const fn to_u32(self) -> u32 {
        (self.me_addr as u32)
            | ((self.host_addr as u32) << 8)
            | (((self.length as u32) & 0x1FF) << 16)
            | ((self.extended as u32) << 28)
            | ((self.dma_ring as u32) << 29)
            | ((self.internal as u32) << 30)
            | ((self.msg_complete as u32) << 31)
    }

    /// Decode a header word read out of `ME_CB_RW`.
    pub const fn from_u32(w: u32) -> Self {
        Self {
            me_addr: (w & 0xFF) as u8,
            host_addr: ((w >> 8) & 0xFF) as u8,
            length: ((w >> 16) & 0x1FF) as u16,
            extended: (w >> 28) & 1 != 0,
            dma_ring: (w >> 29) & 1 != 0,
            internal: (w >> 30) & 1 != 0,
            msg_complete: (w >> 31) & 1 != 0,
        }
    }

    /// A complete, single-packet host bus message of `length` bytes.
    pub const fn bus_message(length: u16) -> Self {
        Self {
            me_addr: MEI_HBM_ADDR,
            host_addr: MEI_HBM_ADDR,
            length,
            extended: false,
            dma_ring: false,
            internal: false,
            msg_complete: true,
        }
    }
}

/// Number of 4-byte slots a message of `bytes` occupies, rounded up.
/// `mei_data2slots` in Linux.
pub const fn data_to_slots(bytes: usize) -> u32 {
    bytes.div_ceil(MEI_SLOT_SIZE) as u32
}

/// Filled slots in a circular buffer, given its CSR word and the
/// shifts for its write / read pointers.
///
/// The pointers are free-running 8-bit counters, so the difference
/// must wrap. Comparing them as plain integers would report a
/// hugely negative (or, unsigned, hugely positive) count every time
/// the write pointer wraps past 0xFF.
pub const fn filled_slots(csr: u32, wp_shift: u32, rp_shift: u32) -> u8 {
    let write_ptr = ((csr >> wp_shift) & 0xFF) as u8;
    let read_ptr = ((csr >> rp_shift) & 0xFF) as u8;
    write_ptr.wrapping_sub(read_ptr)
}

/// Filled slots in the host (write) buffer — `mei_hbuf_filled_slots`.
pub const fn host_filled_slots(hcsr: u32) -> u8 {
    filled_slots(hcsr, 16, 8)
}

/// Filled slots in the ME (read) buffer —
/// `mei_me_count_full_read_slots`.
pub const fn me_filled_slots(mecsr: u32) -> u8 {
    filled_slots(mecsr, 16, 8)
}

/// Host buffer depth in slots, from `H_CSR.H_CBD`.
pub const fn host_buffer_depth(hcsr: u32) -> u8 {
    ((hcsr & H_CBD) >> 24) as u8
}

/// ME buffer depth in slots, from `ME_CSR_HA.ME_CBD_HRA`.
pub const fn me_buffer_depth(mecsr: u32) -> u8 {
    ((mecsr & ME_CBD_HRA) >> 24) as u8
}

/// Decoded `HOST_START_RES_CMD` payload —
/// `struct hbm_host_version_response`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HbmVersionResponse {
    /// Firmware accepted the version we proposed.
    pub host_version_supported: bool,
    /// Highest HBM version firmware supports.
    pub me_major: u8,
    pub me_minor: u8,
}

impl HbmVersionResponse {
    /// Decode the 4-byte response body. `struct hbm_version` is
    /// `{ minor_version, major_version }` — minor first.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 || buf[0] != HOST_START_RES_CMD {
            return None;
        }
        Some(Self {
            host_version_supported: buf[1] != 0,
            me_minor: buf[2],
            me_major: buf[3],
        })
    }
}

// ── Timeouts ────────────────────────────────────────────────────────

/// Budget for `ME_CSR_HA.ME_RDY` to come up after a link reset.
/// Linux's `MEI_HW_READY_TIMEOUT` is 2 s.
pub const HW_READY_TIMEOUT_MS: u64 = 2_000;
/// Budget for one host bus message round trip. Linux's
/// `MEI_HBM_TIMEOUT` is 1 s.
pub const HBM_TIMEOUT_MS: u64 = 1_000;
/// Budget for the host write buffer to drain enough slots.
pub const HBUF_DRAIN_TIMEOUT_MS: u64 = 100;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MeiError {
    BarMapFailed,
    /// BAR0 was mapped but cannot cover the register block.
    BarTooSmall,
    /// `H_CSR` read back all-ones — the device is not responding.
    DeviceGone,
    /// `H_CSR.H_CBD` reported a zero-slot host buffer.
    BadBufferDepth,
    /// `ME_RDY` never came up after the link reset.
    HwReadyTimeout,
    /// The host write buffer never freed enough slots.
    HostBufferFull,
    /// A message was longer than the host buffer can hold.
    MessageTooLong,
    /// Firmware never answered within [`HBM_TIMEOUT_MS`].
    HbmTimeout,
    /// Firmware answered with something other than the expected
    /// response opcode.
    HbmUnexpected(u8),
    /// Firmware rejected the HBM version we proposed.
    HbmVersionRejected {
        me_major: u8,
        me_minor: u8,
    },
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed HECI interface with its link up and the HBM handshake
/// complete.
pub struct MeiDevice {
    mmio: MmioRegion,
    /// Serialises the circular buffers — a bus message is a
    /// multi-slot write followed by a doorbell and cannot interleave.
    io: IrqSafeSpinLock<()>,
    /// PCI device id.
    pub device_id: u16,
    /// Host write-buffer depth in slots, latched at config time.
    pub hbuf_depth: u8,
    /// HBM version firmware reported in `HOST_START_RES_CMD`.
    pub hbm_version: HbmVersionResponse,
    /// Firmware supports D0i3 (`PCI_CFG_HFS_1` bit 31).
    pub d0i3_supported: bool,
    /// `PCI_CFG_HFS_1` as read at probe.
    pub fw_status_1: u32,
    /// `PCI_CFG_HFS_2` as read at probe.
    pub fw_status_2: u32,
    /// Bitmap of firmware client addresses from `HOST_ENUM_RES_CMD`.
    pub clients: [u8; HBM_CLIENT_BITMAP_BYTES],
}

// SAFETY: the only interior-mutable state is the `io` lock itself;
// `mmio` describes an identity-mapped MMIO window this driver owns
// exclusively and the remaining fields are written once at bring-up.
unsafe impl Send for MeiDevice {}
// SAFETY: every path that touches the circular buffers takes `io`,
// so concurrent `&MeiDevice` use from several CPUs is serialized.
unsafe impl Sync for MeiDevice {}

impl core::fmt::Debug for MeiDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeiDevice")
            .field("device_id", &self.device_id)
            .field("hbuf_depth", &self.hbuf_depth)
            .field("hbm_version", &self.hbm_version)
            .field("d0i3_supported", &self.d0i3_supported)
            .field("client_count", &self.client_count())
            .finish_non_exhaustive()
    }
}

impl MeiDevice {
    /// Map BAR0, reset the link, and run the HBM handshake.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 and config space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, MeiError> {
        // SAFETY: forwarded — caller owns BAR0.
        let mmio = unsafe { map_bar(device, MEI_BAR) }.map_err(|_| MeiError::BarMapFailed)?;
        if mmio.len < REG_ME_CSR_HA + 4 {
            return Err(MeiError::BarTooSmall);
        }

        // SAFETY: `mmio` is the mapped register block and `REG_H_CSR`
        // is in range per the check above.
        let hcsr = unsafe { mmio.read32(REG_H_CSR) };
        if hcsr == 0xFFFF_FFFF {
            return Err(MeiError::DeviceGone);
        }
        // `mei_me_hw_config`: the depth does not change at runtime.
        let hbuf_depth = host_buffer_depth(hcsr);
        if hbuf_depth == 0 {
            return Err(MeiError::BadBufferDepth);
        }

        let fw_status_1 = read_cfg32(cap, device, PCI_CFG_HFS_1);
        let fw_status_2 = read_cfg32(cap, device, PCI_CFG_HFS_2);
        let d0i3_supported = fw_status_1 & PCI_CFG_HFS_1_D0I3 == PCI_CFG_HFS_1_D0I3;

        let mut dev = Self {
            mmio,
            io: IrqSafeSpinLock::new(()),
            device_id: device.id.device,
            hbuf_depth,
            hbm_version: HbmVersionResponse::default(),
            d0i3_supported,
            fw_status_1,
            fw_status_2,
            clients: [0; HBM_CLIENT_BITMAP_BYTES],
        };

        // SAFETY: `dev.mmio` is the mapped register block.
        unsafe { dev.link_reset()? };
        dev.hbm_start()?;
        dev.hbm_enumerate_clients()?;
        Ok(dev)
    }

    /// `mei_me_hw_reset` followed by `mei_me_host_set_ready`.
    ///
    /// The driver runs polled, so interrupts stay masked throughout:
    /// Linux takes the same path when `mei_me_hw_use_polling` is set.
    ///
    /// # Safety
    /// `self.mmio` must be this device's mapped register block.
    unsafe fn link_reset(&mut self) -> Result<(), MeiError> {
        // SAFETY: caller-asserted mapped register block.
        let mut hcsr = unsafe { self.mmio.read32(REG_H_CSR) };

        // H_RST can already be lit if a previous reset never finished;
        // asserting it again would be ignored, so clear it first.
        if hcsr & H_RST == H_RST {
            // SAFETY: same; `H_CSR` is read-write.
            unsafe { self.mmio.write32(REG_H_CSR, hcsr & !H_RST) };
            // SAFETY: same.
            hcsr = unsafe { self.mmio.read32(REG_H_CSR) };
        }

        // Assert reset + doorbell, clear any latched interrupt status,
        // and keep interrupts disabled (polled driver).
        hcsr |= H_RST | H_IG | H_CSR_IS_MASK;
        hcsr &= !H_CSR_IE_MASK;
        // SAFETY: same.
        unsafe { self.mmio.write32(REG_H_CSR, hcsr) };
        // Linux reads H_CSR straight back to flush the posted write.
        // SAFETY: same.
        let _ = unsafe { self.mmio.read32(REG_H_CSR) };
        compiler_fence(Ordering::SeqCst);

        // Firmware answers a host reset by re-asserting ME_RDY.
        let ready = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: same.
                let mecsr = unsafe { self.mmio.read32(REG_ME_CSR_HA) };
                mecsr & ME_RDY_HRA == ME_RDY_HRA
            },
            narf_time::Deadline::after_ms(HW_READY_TIMEOUT_MS),
        );
        if !ready {
            return Err(MeiError::HwReadyTimeout);
        }

        // `mei_me_hw_reset_release`: drop H_RST, keep the doorbell.
        // SAFETY: same.
        let mut hcsr = unsafe { self.mmio.read32(REG_H_CSR) };
        hcsr &= !H_RST;
        hcsr |= H_IG;
        // SAFETY: same.
        unsafe { self.mmio.write32(REG_H_CSR, hcsr) };

        // `mei_me_host_set_ready`: publish H_RDY.
        // SAFETY: same.
        let mut hcsr = unsafe { self.mmio.read32(REG_H_CSR) };
        hcsr |= H_IG | H_RDY;
        // SAFETY: same.
        unsafe { self.mmio.write32(REG_H_CSR, hcsr) };
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Empty slots in the host write buffer, or `None` on the
    /// overflow Linux reports as `-EOVERFLOW`.
    pub fn hbuf_empty_slots(&self) -> Option<u8> {
        // SAFETY: `self.mmio` is the mapped register block.
        let hcsr = unsafe { self.mmio.read32(REG_H_CSR) };
        let filled = host_filled_slots(hcsr);
        if filled > self.hbuf_depth {
            return None;
        }
        Some(self.hbuf_depth - filled)
    }

    /// Write one complete bus message: header word, payload slots,
    /// then the `H_IG` doorbell. `payload` is zero-padded up to a
    /// slot boundary, which is what firmware expects.
    fn write_message(&self, hdr: MeiMsgHdr, payload: &[u8]) -> Result<(), MeiError> {
        let slots_needed = 1 + data_to_slots(payload.len());
        if slots_needed > self.hbuf_depth as u32 {
            return Err(MeiError::MessageTooLong);
        }

        let _g = self.io.lock();

        let have_room = narf_scheduler::responsive_spin_until(
            || matches!(self.hbuf_empty_slots(), Some(n) if n as u32 >= slots_needed),
            narf_time::Deadline::after_ms(HBUF_DRAIN_TIMEOUT_MS),
        );
        if !have_room {
            return Err(MeiError::HostBufferFull);
        }

        // SAFETY: `self.mmio` is the mapped register block and
        // `H_CB_WW` is a write-only 32-bit port; the slot accounting
        // above guarantees firmware has room for every store.
        unsafe { self.mmio.write32(REG_H_CB_WW, hdr.to_u32()) };
        for chunk in payload.chunks(MEI_SLOT_SIZE) {
            let mut word = [0u8; MEI_SLOT_SIZE];
            word[..chunk.len()].copy_from_slice(chunk);
            // SAFETY: same.
            unsafe { self.mmio.write32(REG_H_CB_WW, u32::from_le_bytes(word)) };
        }
        compiler_fence(Ordering::SeqCst);

        // Doorbell.
        // SAFETY: same.
        let hcsr = unsafe { self.mmio.read32(REG_H_CSR) };
        // SAFETY: same.
        unsafe { self.mmio.write32(REG_H_CSR, hcsr | H_IG) };
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Wait for firmware to fill its read buffer, then pop one
    /// complete message into `out`. Returns the header.
    fn read_message(&self, out: &mut alloc::vec::Vec<u8>) -> Result<MeiMsgHdr, MeiError> {
        let ready = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: `self.mmio` is the mapped register block.
                let mecsr = unsafe { self.mmio.read32(REG_ME_CSR_HA) };
                me_filled_slots(mecsr) > 0
            },
            narf_time::Deadline::after_ms(HBM_TIMEOUT_MS),
        );
        if !ready {
            return Err(MeiError::HbmTimeout);
        }

        let _g = self.io.lock();

        // SAFETY: `ME_CB_RW` is a read-only 32-bit port; the filled
        // count above guarantees at least the header word is present.
        let hdr = MeiMsgHdr::from_u32(unsafe { self.mmio.read32(REG_ME_CB_RW) });

        let slots = data_to_slots(hdr.length as usize);
        out.clear();
        out.reserve(hdr.length as usize);
        for _ in 0..slots {
            // Firmware fills the whole message before raising the
            // slot count, so no second wait is needed here.
            // SAFETY: same.
            let w = unsafe { self.mmio.read32(REG_ME_CB_RW) };
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(hdr.length as usize);

        // Acknowledge: firmware advances its read pointer when the
        // host rings H_IG.
        // SAFETY: same.
        let hcsr = unsafe { self.mmio.read32(REG_H_CSR) };
        // SAFETY: same.
        unsafe { self.mmio.write32(REG_H_CSR, hcsr | H_IG) };
        compiler_fence(Ordering::SeqCst);
        Ok(hdr)
    }

    /// Send one bus message and wait for the matching response
    /// opcode.
    fn hbm_exchange(
        &self,
        request: &[u8],
        expect: u8,
        out: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), MeiError> {
        self.write_message(MeiMsgHdr::bus_message(request.len() as u16), request)?;
        // Firmware can interleave an unsolicited ME_STOP_REQ_CMD; skip
        // anything that is not the response we asked for rather than
        // failing the handshake on the first surprise.
        for _ in 0..4 {
            self.read_message(out)?;
            match out.first() {
                Some(&cmd) if cmd == expect => return Ok(()),
                Some(&ME_STOP_REQ_CMD) => continue,
                Some(&cmd) => return Err(MeiError::HbmUnexpected(cmd)),
                None => continue,
            }
        }
        Err(MeiError::HbmTimeout)
    }

    /// `HOST_START_REQ_CMD` — propose an HBM version and record what
    /// firmware answers.
    fn hbm_start(&mut self) -> Result<(), MeiError> {
        // struct hbm_host_version_request:
        //   { hbm_cmd, reserved, minor_version, major_version }
        let req = [HOST_START_REQ_CMD, 0, HBM_MINOR_VERSION, HBM_MAJOR_VERSION];
        let mut resp = alloc::vec::Vec::new();
        self.hbm_exchange(&req, HOST_START_RES_CMD, &mut resp)?;
        let v = HbmVersionResponse::parse(&resp)
            .ok_or(MeiError::HbmUnexpected(resp.first().copied().unwrap_or(0)))?;
        if !v.host_version_supported {
            return Err(MeiError::HbmVersionRejected {
                me_major: v.me_major,
                me_minor: v.me_minor,
            });
        }
        self.hbm_version = v;
        Ok(())
    }

    /// `HOST_ENUM_REQ_CMD` — ask firmware which client addresses
    /// exist, and keep the bitmap.
    fn hbm_enumerate_clients(&mut self) -> Result<(), MeiError> {
        // struct hbm_host_enum_request: { hbm_cmd, flags, reserved[2] }
        let req = [HOST_ENUM_REQ_CMD, 0, 0, 0];
        let mut resp = alloc::vec::Vec::new();
        self.hbm_exchange(&req, HOST_ENUM_RES_CMD, &mut resp)?;
        // struct hbm_host_enum_response:
        //   { hbm_cmd, reserved[3], valid_addresses[32] }
        if resp.len() >= 4 + HBM_CLIENT_BITMAP_BYTES {
            self.clients
                .copy_from_slice(&resp[4..4 + HBM_CLIENT_BITMAP_BYTES]);
        }
        Ok(())
    }

    /// `true` if firmware advertises a client at `addr`.
    pub fn has_client(&self, addr: u8) -> bool {
        let byte = (addr / 8) as usize;
        let bit = addr % 8;
        self.clients[byte] & (1 << bit) != 0
    }

    /// How many firmware clients the enumeration reported.
    pub fn client_count(&self) -> u32 {
        self.clients.iter().map(|b| b.count_ones()).sum()
    }

    /// `true` when firmware currently reports itself ready.
    pub fn me_ready(&self) -> bool {
        // SAFETY: `self.mmio` is the mapped register block.
        let mecsr = unsafe { self.mmio.read32(REG_ME_CSR_HA) };
        mecsr & ME_RDY_HRA == ME_RDY_HRA
    }

    /// `true` when the host side has published `H_RDY`.
    pub fn host_ready(&self) -> bool {
        // SAFETY: same.
        let hcsr = unsafe { self.mmio.read32(REG_H_CSR) };
        hcsr & H_RDY == H_RDY
    }

    /// `HOST_STOP_REQ_CMD` — tell firmware the host is going away.
    pub fn stop(&self) -> Result<(), MeiError> {
        // struct hbm_host_stop_request: { hbm_cmd, reason, reserved[2] }
        let req = [HOST_STOP_REQ_CMD, 0, 0, 0];
        let mut resp = alloc::vec::Vec::new();
        self.hbm_exchange(&req, HOST_STOP_RES_CMD, &mut resp)
    }
}

/// Read a 32-bit word out of the device's PCI config space.
///
/// The firmware-status words live at 0x40 / 0x48 / 0x60 … which are
/// vendor-specific offsets, not capability-list entries, so they are
/// addressed directly.
fn read_cfg32(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice, offset: u16) -> u32 {
    narf_bus::pci::read_config32(cap, device, offset).unwrap_or(0)
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<alloc::sync::Arc<MeiDevice>>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != MEI_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    let dev = match unsafe { MeiDevice::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  mei: bring-up failed on {:04x}:{:04x}: {:?}",
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  mei: HECI {:04x} hbuf={} slots, HBM {}.{}, {} clients, HFS1={:#010x}{}",
            dev.device_id,
            dev.hbuf_depth,
            dev.hbm_version.me_major,
            dev.hbm_version.me_minor,
            dev.client_count(),
            dev.fw_status_1,
            if dev.d0i3_supported { ", d0i3" } else { "" },
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("mei-me"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    *CONTROLLER.lock() = Some(alloc::sync::Arc::new(dev));
    Ok(())
}

/// Register the MEI PCI driver — one match entry per device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "mei-me",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: MEI_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once a HECI interface has been brought up.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed HECI interface, if any.
pub fn with_device<R>(f: impl FnOnce(&MeiDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

#[doc(hidden)]
/// Test-only: forget the probed device so a smoke can assert
/// end-state.
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
