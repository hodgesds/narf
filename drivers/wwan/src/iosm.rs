// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/iosm.rs — Intel IOSM (IPC Over Shared Memory) scaffold
//
// IOSM is the IPC protocol used by Intel XMM 7360/7560 ePCI modems.  The
// modem is attached as a PCIe endpoint and exposes a shared-memory ring via
// BAR0 and a scratchpad MMIO region via BAR2.  The host advances the modem
// through a state machine similar to Qualcomm's MHI protocol; NARF already
// carries an MHI scaffold from the ath11k driver so IOSM can reuse those
// ring primitives when Stage-2 bring-up begins.
//
// Stage-0/1 scope:
//   - PCI vendor/device-ID table (XMM 7560 + 7360).
//   - BAR constants (doorbell BAR0, scratchpad BAR2).
//   - Doorbell register offsets.
//
// Deferred (Stage-2+):
//   - BAR0 MMIO mapping via `narf-bus::map_bar`.
//   - Scratchpad config-tuple write (IPC_MEM_CONFIG_* layout).
//   - MHI-style ring allocate + doorbell pump.
//   - Firmware load via `narf-firmware`.
//   - Channel bring-up (WWAN / AT / RPC channels).
//
// Linux cross-references (GPL-2.0-or-later):
//   drivers/net/wwan/iosm/iosm_ipc_pcie.h   — device IDs + BAR constants
//   drivers/net/wwan/iosm/iosm_ipc_pcie.c   — PCI probe + pci_device_id table
//   drivers/net/wwan/iosm/iosm_ipc_imem.h   — IPC shared-memory layout
//   drivers/net/wwan/iosm/iosm_ipc_protocol.h — phase/stage state machine

#![allow(dead_code)]

// ─── PCI identifiers ─────────────────────────────────────────────────────────

/// Intel PCIe vendor ID.
///
/// Linux ref: `include/linux/pci_ids.h` PCI_VENDOR_ID_INTEL = 0x8086.
pub const PCI_VENDOR_INTEL: u16 = 0x8086;

/// Device ID for the Intel XMM 7560 modem.
///
/// Linux ref: `iosm_ipc_pcie.h` INTEL_CP_DEVICE_7560_ID = 0x7560.
pub const INTEL_CP_DEVICE_7560_ID: u16 = 0x7560;

/// Device ID for the Intel XMM 7360 modem.
///
/// Linux ref: `iosm_ipc_pcie.h` INTEL_CP_DEVICE_7360_ID = 0x7360.
pub const INTEL_CP_DEVICE_7360_ID: u16 = 0x7360;

/// A minimal PCI device descriptor used by the static match table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDeviceId {
    pub vendor: u16,
    pub device: u16,
    /// Human-readable chip name, for log messages.
    pub name:   &'static str,
}

/// IOSM PCI device-ID table.
///
/// NARF's PCI bus dispatcher will walk this slice when probing PCIe endpoints.
/// Linux uses `MODULE_DEVICE_TABLE(pci, iosm_pci_ids)` for the same purpose.
///
/// Linux ref: `iosm_ipc_pcie.c` `iosm_pci_ids[]`.
pub static IOSM_PCI_DEVICES: &[PciDeviceId] = &[
    PciDeviceId {
        vendor: PCI_VENDOR_INTEL,
        device: INTEL_CP_DEVICE_7560_ID,
        name:   "Intel XMM 7560",
    },
    PciDeviceId {
        vendor: PCI_VENDOR_INTEL,
        device: INTEL_CP_DEVICE_7360_ID,
        name:   "Intel XMM 7360",
    },
];

// ─── BAR layout ──────────────────────────────────────────────────────────────

/// BAR index for the IPC doorbell register set.
///
/// Linux ref: `iosm_ipc_pcie.h` IPC_DOORBELL_BAR0 = 0.
pub const IPC_DOORBELL_BAR: u8 = 0;

/// BAR index for the scratchpad/config region.
///
/// Linux ref: `iosm_ipc_pcie.h` IPC_SCRATCHPAD_BAR2 = 2.
pub const IPC_SCRATCHPAD_BAR: u8 = 2;

// ─── Doorbell register offsets (within BAR0) ─────────────────────────────────

/// Per-channel doorbell stride: each channel's doorbell is at
/// `IPC_DOORBELL_BASE + channel_id * IPC_DOORBELL_CH_OFFSET`.
///
/// Linux ref: `iosm_ipc_pcie.h` IPC_DOORBELL_CH_OFFSET = BIT(5) = 32.
pub const IPC_DOORBELL_CH_OFFSET: u32 = 1 << 5;

/// Write-pointer register offset within the per-channel doorbell slot.
///
/// Linux ref: `iosm_ipc_pcie.h` IPC_WRITE_PTR_REG_0 = BIT(4) = 16.
pub const IPC_WRITE_PTR_REG_0: u32 = 1 << 4;

/// Capture-pointer register offset within the per-channel doorbell slot.
///
/// Linux ref: `iosm_ipc_pcie.h` IPC_CAPTURE_PTR_REG_0 = BIT(3) = 8.
pub const IPC_CAPTURE_PTR_REG_0: u32 = 1 << 3;

// ─── IPC phase / state machine ───────────────────────────────────────────────
//
// The IOSM modem transitions through a sequence of operational phases that
// are signalled via a status register in the scratchpad region.  The host
// polls or interrupts on phase changes.
//
// Linux ref: `iosm_ipc_imem.h` enum ipc_phase.

/// IPC operational phase codes read from the modem's phase register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IpcPhase {
    /// Power-on / reset; scratchpad not yet valid.
    Off          = 0x00,
    /// ROM bootloader active; waiting for firmware download.
    Rom          = 0x01,
    /// Firmware is loaded and initialising.
    Boot         = 0x02,
    /// Modem is fully operational.
    Run          = 0x10,
    /// Modem has entered a crash state; coredump available.
    Crash        = 0x11,
    /// Unrecognised phase value.
    Unknown      = 0xFF,
}

impl IpcPhase {
    /// Decode from the raw register value.
    pub fn from_raw(v: u32) -> Self {
        match v {
            0x00 => Self::Off,
            0x01 => Self::Rom,
            0x02 => Self::Boot,
            0x10 => Self::Run,
            0x11 => Self::Crash,
            _    => Self::Unknown,
        }
    }
}
