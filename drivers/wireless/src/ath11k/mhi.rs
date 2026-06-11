//! Modem Host Interface (MHI) — ring + state-machine scaffolding.
//!
//! ath11k is firmware-driven via Qualcomm's MHI protocol rather
//! than ath10k's Copy Engines. The host enumerates a fixed set of
//! channels (IPCR ch20/ch21 are the only ones needed for QCA6390)
//! and event rings, then advances the device through a four-stage
//! state machine: RESET → READY → MISSION-MODE → AMSS-LOADED.
//!
//! This file contains only the *data plane* — TRE (Transfer Ring
//! Element) layout, ring index arithmetic, channel/event config
//! tables, and the small set of doorbell + status register
//! constants. The MMIO-driven state machine itself is gated behind
//! the BAR0 mapping that Stage-1 wires up; everything here is
//! pure-data so unit tests can exercise it offline.
//!
//! Linux references (BSD-3 / dual GPL):
//! - `drivers/net/wireless/ath/ath11k/mhi.h` — MHISTATUS / MHICTRL.
//! - `drivers/net/wireless/ath/ath11k/mhi.c` — channel + event
//!   configuration tables for QCA6390 and QCN9074.
//! - Linux `drivers/bus/mhi/host/internal.h` — TRE layout, ring
//!   index conventions, doorbell burst-vs-disabled semantics.

#![allow(dead_code)]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_bus::MmioRegion;
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareRegistry;

use crate::ath11k::pci::{read_via_window, write_via_window, ProbeError};

// ── MHI initialization ─────────────────────────────────────────────

/// Initialize the MHI controller and load the AMSS firmware.
/// Advances the chip to Mission Mode (M0).
///
/// # Safety
/// `mmio` must be a valid, live BAR0 mapping for the ath11k device;
/// this drives the chip's `MHICTRL`/`MHISTATUS`/`BHI` registers via
/// the sliding window, so the mapping must remain valid for the call.
pub unsafe fn mhi_init(
    mmio: &MmioRegion,
    did: u16,
    auth: &Cap<FirmwareRegistry, Read>,
) -> Result<(), ProbeError> {
    // 1. Reset the MHI controller.
    // SAFETY: `mmio` is the caller-asserted live BAR0 mapping; `MHICTRL`
    // is a writable chip register reached via the sliding window.
    unsafe { write_via_window(mmio, MHICTRL, MHICTRL_RESET_MASK) };

    // 2. Poll MHISTATUS until READY bit (bit 0) is set.
    // Linux uses a 2-second timeout for this.
    let mut ready = false;
    for _ in 0..2000 {
        // SAFETY: `mmio` is the caller-asserted live BAR0 mapping;
        // `MHISTATUS` is a readable chip register via the window.
        let status = unsafe { read_via_window(mmio, MHISTATUS) };
        if status & 0x1 != 0 {
            ready = true;
            break;
        }
        if status == 0xFFFF_FFFF {
            return Err(ProbeError::LinkDown);
        }
        narf_scheduler::sleep_pumps::run(); // Cooperative yield
    }
    if !ready {
        return Err(ProbeError::LtssmFailed); // Use LtssmFailed as a proxy for MHI timeout
    }

    // 3. Load the AMSS firmware via BHI.
    load_amss_firmware(mmio, did, auth)?;

    // 4. Set MHI state to M0.
    // SAFETY: `mmio` is the caller-asserted live BAR0 mapping; `MHICTRL`
    // is a readable chip register via the window.
    let mut ctrl = unsafe { read_via_window(mmio, MHICTRL) };
    ctrl &= !MHICTRL_MHISTATE_MASK;
    ctrl |= MHI_STATE_M0 << MHICTRL_MHISTATE_SHIFT;
    // SAFETY: `mmio` is the caller-asserted live BAR0 mapping; `MHICTRL`
    // is a writable chip register via the window.
    unsafe { write_via_window(mmio, MHICTRL, ctrl) };

    // 5. Poll MHISTATUS until state is M0 (bits 15:8 == 2).
    let mut m0_reached = false;
    for _ in 0..2000 {
        // SAFETY: `mmio` is the caller-asserted live BAR0 mapping;
        // `MHISTATUS` is a readable chip register via the window.
        let status = unsafe { read_via_window(mmio, MHISTATUS) };
        let state = (status >> 8) & 0xFF;
        if state == MHI_STATE_M0 {
            m0_reached = true;
            break;
        }
        narf_scheduler::sleep_pumps::run();
    }
    if !m0_reached {
        return Err(ProbeError::NotImplemented); // M0 handshake failed
    }

    Ok(())
}

/// Load the AMSS firmware blob into the chip via the BHI.
fn load_amss_firmware(
    mmio: &MmioRegion,
    did: u16,
    auth: &Cap<FirmwareRegistry, Read>,
) -> Result<(), ProbeError> {
    // Determine the firmware path based on the device ID.
    // QCA6390 -> ath11k/QCA6390/hw2.0/amss.bin
    // WCN6855 -> ath11k/WCN6855/hw2.0/amss.bin
    let chip_prefix = match did {
        crate::ath11k::hw::ATH11K_DEV_QCA6390 => "QCA6390/hw2.0",
        crate::ath11k::hw::ATH11K_DEV_WCN6855 | crate::ath11k::hw::ATH11K_DEV_QCA2066 => {
            "WCN6855/hw2.0"
        }
        crate::ath11k::hw::ATH11K_DEV_QCN9074 => "QCN9074/hw1.0",
        crate::ath11k::hw::ATH11K_DEV_WCN7850 => "WCN7850/hw2.0",
        _ => "QCA6390/hw2.0",
    };
    let fw_name = format!("ath11k/{}/amss.bin", chip_prefix);

    let _ = writeln!(
        narf_console::Writer,
        "  ath11k: loading firmware {}",
        fw_name
    );

    let cap = narf_firmware::open(&fw_name, auth).map_err(|_| ProbeError::NotImplemented)?;
    let view = narf_firmware::view_of(&cap).map_err(|_| ProbeError::NotImplemented)?;

    // Allocate a DMA-coherent buffer and copy the firmware.
    // ath11k firmware blobs are typically 1-2 MiB.
    let mut dma_buf = narf_io::alloc_coherent(view.bytes.len(), narf_lib::id::DomainId::DRIVER_0)
        .map_err(|_| ProbeError::Bar0MapFailed)?;
    dma_buf.as_mut_slice().copy_from_slice(view.bytes);

    let phys = dma_buf.phys_addr().as_u64();
    let size = view.bytes.len() as u32;

    // Read the BHI offset from BAR0+0x28.
    // SAFETY: `mmio` is the live BAR0 mapping passed down from
    // `mhi_init`; `BHIOFF` is a readable chip register via the window.
    let bhi_off = unsafe { read_via_window(mmio, BHIOFF) };

    // Program BHI registers.
    // SAFETY: `mmio` is the live BAR0 mapping passed down from
    // `mhi_init`; `bhi_off + BHI_*` address the writable BHI image
    // descriptor + doorbell registers within the chip register file.
    unsafe {
        write_via_window(mmio, bhi_off + BHI_IMGADDR_LOW, phys as u32);
        write_via_window(mmio, bhi_off + BHI_IMGADDR_HIGH, (phys >> 32) as u32);
        write_via_window(mmio, bhi_off + BHI_IMGSIZE, size);
        // Doorbell trigger (sequence 1).
        write_via_window(mmio, bhi_off + BHI_IMGTXDB, 1);
    }

    // Poll BHI_STATUS for SUCCESS.
    let mut success = false;
    for _ in 0..5000 {
        // SAFETY: `mmio` is the live BAR0 mapping passed down from
        // `mhi_init`; `bhi_off + BHI_STATUS` is a readable chip register.
        let status = unsafe { read_via_window(mmio, bhi_off + BHI_STATUS) };
        if status == BHI_STATUS_SUCCESS {
            success = true;
            break;
        }
        if status == BHI_STATUS_ERROR {
            return Err(ProbeError::NotImplemented);
        }
        narf_scheduler::sleep_pumps::run();
    }

    if !success {
        return Err(ProbeError::NotImplemented);
    }

    // Keep the DMA buffer alive until M0 is reached (or beyond if needed).
    // For this bring-up stage, we'll just let it leak if successful or
    // we can find a better place to store it.
    core::mem::forget(dma_buf);

    Ok(())
}

// ── MHI state machine ──────────────────────────────────────────────
//
// The MHI register block sits at a chip-specific offset inside
// BAR0. For QCA6390 / QCN9074 / WCN6855 it's the BAR0 base + the
// constants below. Linux's `mhi.h` exposes the same numbers.

pub const MHISTATUS: u32 = 0x48;
pub const MHICTRL: u32 = 0x38;
pub const MHICFG: u32 = 0x10;
pub const BHIOFF: u32 = 0x28;

pub const MHICTRL_RESET_MASK: u32 = 0x2;
pub const MHICTRL_MHISTATE_MASK: u32 = 0x0000_FF00;
pub const MHICTRL_MHISTATE_SHIFT: u32 = 8;
pub const MHI_STATE_M0: u32 = 0x2;

// BHI relative offsets (to the value in BHIOFF)
pub const BHI_IMGADDR_LOW: u32 = 0x08;
pub const BHI_IMGADDR_HIGH: u32 = 0x0c;
pub const BHI_IMGSIZE: u32 = 0x10;
pub const BHI_IMGTXDB: u32 = 0x18;
pub const BHI_EXECENV: u32 = 0x28;
pub const BHI_STATUS: u32 = 0x2c;

pub const BHI_STATUS_SUCCESS: u32 = 2;
pub const BHI_STATUS_ERROR: u32 = 3;

pub const PCIE_TXVECDB: u32 = 0x360;
pub const PCIE_TXVECSTATUS: u32 = 0x368;
pub const PCIE_RXVECDB: u32 = 0x394;
pub const PCIE_RXVECSTATUS: u32 = 0x39C;

// ── MHI state machine ──────────────────────────────────────────────

/// MHI execution environments — the device's notion of what stage
/// of bring-up it's in. Mirrors `enum mhi_ee_type` in
/// `linux/mhi.h`. Values are baked into the MHISTATUS register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MhiExecEnv {
    /// Power-on reset; nothing's loaded.
    Pbl = 0,
    /// Secondary bootloader running.
    Sbl = 1,
    /// AMSS firmware running (mission mode for ath11k).
    Amss = 2,
    /// RDDM (Ramdump Debug Domain Mode) — coredump capture.
    Rddm = 3,
    /// WFW (WLAN firmware) — Cat-3 firmware running.
    Wfw = 4,
    /// PT_HW (passthrough) — disabled / removed.
    PtHw = 5,
    /// Edge / unrecognised value.
    Disabled = 0xff,
}

impl MhiExecEnv {
    pub fn from_raw(v: u32) -> Self {
        match v & 0x7 {
            0 => MhiExecEnv::Pbl,
            1 => MhiExecEnv::Sbl,
            2 => MhiExecEnv::Amss,
            3 => MhiExecEnv::Rddm,
            4 => MhiExecEnv::Wfw,
            5 => MhiExecEnv::PtHw,
            _ => MhiExecEnv::Disabled,
        }
    }
}

/// MHI controller state — driver-side bring-up phase. Linux's
/// equivalent enum is `mhi_state` in `linux/mhi.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MhiState {
    Reset,
    Ready,
    M0,
    M1,
    M2,
    M3,
    SysErr,
    Disabled,
}

// ── TRE (Transfer Ring Element) layout ─────────────────────────────

/// One Transfer Ring Element. Each MHI ring is a circular buffer
/// of these 16-byte descriptors. The exact bit layout of `flags`
/// depends on TRE type — for data TREs the bottom 16 bits carry
/// the payload byte count, and `BEI/IEOT/IEOB/CHAIN` flags occupy
/// bits 8..11 of the *high* word.
///
/// Layout per `linux/mhi.h::struct mhi_tre`:
///   - ptr   (u64): DMA pointer to the payload (LE on x86_64).
///   - dword0 (u32): payload length / immediate fields.
///   - dword1 (u32): type + flags.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MhiTre {
    pub ptr_lo: u32,
    pub ptr_hi: u32,
    pub dword0: u32,
    pub dword1: u32,
}

impl MhiTre {
    pub const SIZE: usize = 16;

    /// Pack a data-channel TRE: payload at `dma`, length `len`, IEOT
    /// (interrupt-on-EOT) + IEOB (interrupt-on-EOB) latched.
    /// Encoding per `linux/drivers/bus/mhi/host/main.c`:
    ///   - dword0 bits[15:0] = length,
    ///   - dword1 bits[7:0]  = type (DATA = 0x2),
    ///   - dword1 bit  8     = IEOT,
    ///   - dword1 bit  9     = IEOB,
    ///   - dword1 bit 10     = CHAIN,
    ///   - dword1 bit 11     = BEI (bei: block event interrupt).
    pub fn pack_data(dma: u64, len: u16, ieot: bool, ieob: bool, chain: bool, bei: bool) -> Self {
        let mut t = MhiTre {
            ptr_lo: dma as u32,
            ptr_hi: (dma >> 32) as u32,
            dword0: len as u32,
            dword1: 0x02, // type = DATA
        };
        if ieot {
            t.dword1 |= 1 << 8;
        }
        if ieob {
            t.dword1 |= 1 << 9;
        }
        if chain {
            t.dword1 |= 1 << 10;
        }
        if bei {
            t.dword1 |= 1 << 11;
        }
        t
    }

    pub fn dma(&self) -> u64 {
        (self.ptr_lo as u64) | ((self.ptr_hi as u64) << 32)
    }

    pub fn len(&self) -> u16 {
        (self.dword0 & 0xFFFF) as u16
    }

    /// True when this TRE carries a zero-length payload (`dword0[15:0]` == 0).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn tre_type(&self) -> u8 {
        (self.dword1 & 0xFF) as u8
    }

    pub fn ieot(&self) -> bool {
        (self.dword1 & (1 << 8)) != 0
    }

    pub fn ieob(&self) -> bool {
        (self.dword1 & (1 << 9)) != 0
    }
}

// ── Ring config tables ─────────────────────────────────────────────

/// Direction of a transfer ring relative to the host.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingDir {
    /// Host → device (TX): payload buffers carry IPC requests.
    ToDevice,
    /// Device → host (RX): payload buffers receive IPC responses.
    FromDevice,
}

/// Doorbell-burst mode. ath11k disables burst on its IPCR channels
/// per Linux's `MHI_DB_BRST_DISABLE` (value 2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DoorbellMode {
    Enable = 0,
    Disable = 2,
}

/// Per-channel configuration. One per logical MHI channel.
/// Mirrors `struct mhi_channel_config` in `linux/mhi.h`.
#[derive(Copy, Clone, Debug)]
pub struct ChannelConfig {
    pub num: u8,
    pub name: &'static str,
    pub num_elements: u32,
    pub event_ring: u8,
    pub dir: RingDir,
    pub ee_mask: u32,
    pub doorbell: DoorbellMode,
}

/// Per-event-ring configuration. Mirrors `struct
/// mhi_event_config`.
#[derive(Copy, Clone, Debug)]
pub struct EventConfig {
    pub num_elements: u32,
    pub irq_moderation_ms: u32,
    pub irq: u32,
    pub priority: u32,
    pub control: bool,
}

/// QCA6390 channel table — ch20 (IPCR TX) + ch21 (IPCR RX), 64
/// elements each. Verbatim from `mhi.c::ath11k_mhi_channels_qca6390`.
pub const ATH11K_MHI_CHANNELS_QCA6390: &[ChannelConfig] = &[
    ChannelConfig {
        num: 20,
        name: "IPCR",
        num_elements: 64,
        event_ring: 1,
        dir: RingDir::ToDevice,
        ee_mask: 0x4,
        doorbell: DoorbellMode::Disable,
    },
    ChannelConfig {
        num: 21,
        name: "IPCR",
        num_elements: 64,
        event_ring: 1,
        dir: RingDir::FromDevice,
        ee_mask: 0x4,
        doorbell: DoorbellMode::Disable,
    },
];

/// QCN9074 channel table — 32 elements each, larger ee_mask.
pub const ATH11K_MHI_CHANNELS_QCN9074: &[ChannelConfig] = &[
    ChannelConfig {
        num: 20,
        name: "IPCR",
        num_elements: 32,
        event_ring: 1,
        dir: RingDir::ToDevice,
        ee_mask: 0x14,
        doorbell: DoorbellMode::Disable,
    },
    ChannelConfig {
        num: 21,
        name: "IPCR",
        num_elements: 32,
        event_ring: 1,
        dir: RingDir::FromDevice,
        ee_mask: 0x14,
        doorbell: DoorbellMode::Disable,
    },
];

/// Two event rings — control (32 entries, irq 1) + data (256
/// entries, irq 2, moderated). Same for QCA6390 and QCN9074.
pub const ATH11K_MHI_EVENTS: &[EventConfig] = &[
    EventConfig {
        num_elements: 32,
        irq_moderation_ms: 0,
        irq: 1,
        priority: 0,
        control: true,
    },
    EventConfig {
        num_elements: 256,
        irq_moderation_ms: 1,
        irq: 2,
        priority: 1,
        control: false,
    },
];

// ── Ring index arithmetic ──────────────────────────────────────────

/// A single host-side MHI ring (transfer or event).
///
/// Tracks the host's view of read/write pointers as element
/// indices. The device's doorbell semantics translate these into
/// byte addresses internally. `count` is the modulus.
#[derive(Clone, Debug)]
pub struct MhiRing {
    pub count: u32,
    pub rp: u32, // read pointer (consumer; updated on completion)
    pub wp: u32, // write pointer (producer; updated on insert)
    pub trbs: Vec<MhiTre>,
}

impl MhiRing {
    /// Allocate an empty ring with `count` zeroed TREs.
    pub fn new(count: u32) -> Self {
        let mut trbs = Vec::with_capacity(count as usize);
        trbs.resize(count as usize, MhiTre::default());
        MhiRing {
            count,
            rp: 0,
            wp: 0,
            trbs,
        }
    }

    /// Free slots between `wp` (next write) and `rp` (next read).
    /// MHI reserves one slot to disambiguate full vs empty — the
    /// largest usable depth is `count - 1`.
    pub fn space(&self) -> u32 {
        if self.wp >= self.rp {
            self.count - 1 - (self.wp - self.rp)
        } else {
            self.rp - self.wp - 1
        }
    }

    /// True iff the ring has no outstanding TREs (`wp == rp`).
    pub fn is_empty(&self) -> bool {
        self.wp == self.rp
    }

    /// True iff the ring is full — `wp + 1 == rp` mod `count`.
    pub fn is_full(&self) -> bool {
        (self.wp + 1) % self.count == self.rp
    }

    /// Insert one TRE at `wp` and advance. Returns the index used.
    /// `None` if full.
    pub fn push(&mut self, tre: MhiTre) -> Option<u32> {
        if self.is_full() {
            return None;
        }
        let idx = self.wp;
        self.trbs[idx as usize] = tre;
        self.wp = (self.wp + 1) % self.count;
        Some(idx)
    }

    /// Mark one TRE consumed (advances `rp`). Returns the index
    /// just released. `None` if already empty.
    pub fn pop(&mut self) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let idx = self.rp;
        self.rp = (self.rp + 1) % self.count;
        Some(idx)
    }
}

// ── Doorbell address arithmetic ────────────────────────────────────
//
// The MHI host writes a 64-bit doorbell value (combined DB_VAL +
// DB_OFF) to (BAR0 + 0x100 + 8*ch_id). Channel 0..127 are valid.
// The doorbell at BAR0 + 0x100 + 8*N is the per-channel write
// pointer; the host updates it whenever it inserts a new TRE.

pub const MHI_CHDB_BASE: u32 = 0x100;
pub const MHI_ERDB_BASE: u32 = 0x300; // event-ring doorbells

/// Byte offset (relative to BAR0) of channel `ch`'s doorbell.
pub fn ch_doorbell_offset(ch: u8) -> u32 {
    MHI_CHDB_BASE + 8 * ch as u32
}

/// Byte offset of event-ring `er`'s doorbell.
pub fn er_doorbell_offset(er: u8) -> u32 {
    MHI_ERDB_BASE + 8 * er as u32
}

/// Pick the channel table appropriate for a given PCI device id.
/// Linux carries one of these tables per chip; we collapse to two
/// shapes — QCA6390 (64-element rings) and QCN9074 (32-element).
/// WCN6855 / QCA2066 share the QCA6390 channel layout in Linux.
pub fn channels_for_did(did: u16) -> &'static [ChannelConfig] {
    use crate::ath11k::hw::*;
    match did {
        ATH11K_DEV_QCA6390 | ATH11K_DEV_WCN6855 | ATH11K_DEV_QCA2066 | ATH11K_DEV_WCN7850 => {
            ATH11K_MHI_CHANNELS_QCA6390
        }
        ATH11K_DEV_QCN9074 | ATH11K_DEV_QCN6122 => ATH11K_MHI_CHANNELS_QCN9074,
        _ => ATH11K_MHI_CHANNELS_QCA6390,
    }
}
