//! Intel PCIe-attached Bluetooth controller — Stage-1 bring-up.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 (GPL-2.0; NARF is GPL-2.0-or-later so adaptation
//! is permitted):
//!
//! - `drivers/bluetooth/btintel_pcie.h` — the CSR register map, the
//!   `FUNC_CTRL` control bits, and the `BOOT_STAGE` bit meanings.
//! - `drivers/bluetooth/btintel_pcie.c` — `btintel_pcie_table[]`,
//!   `btintel_pcie_reset_bt`, `btintel_pcie_get_mac_access` /
//!   `btintel_pcie_release_mac_access`, and the `CSR_HW_REV_REG` /
//!   `CSR_RF_ID_REG` reads that produce CNVi / CNVr.
//! - `drivers/bluetooth/btintel.h` — the `BTINTEL_CNVI_*` top-type
//!   constants and `INTEL_CNVX_TOP_TYPE` / `INTEL_CNVX_TOP_STEP`.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** carries the controller at PCI `00:14.7`
//! (`8086:e376`, "Scorpius, Panther Lake-H484"). It is the CNVi
//! Bluetooth companion to the BE211 Wi-Fi side at `00:14.3`.
//!
//! ## Why this is not a `btusb` clone
//!
//! Every Intel Bluetooth controller before Lunar Lake hung off the
//! internal USB hub, and NARF reaches those through
//! [`crate::usb_transport`]. From Lunar Lake on, the controller is a
//! **PCIe function of its own**, and the host talks to it over DMA
//! descriptor rings — TFD/TXQ outbound, FRBD/URBD/RXQ inbound — with
//! a 4-byte packet-type prefix instead of the 1-byte BT SIG HCI type.
//! None of the USB transport applies.
//!
//! ## Scope
//!
//! Put the controller in a known state and identify it:
//!
//! 1. Map BAR0 (the whole CSR window).
//! 2. `btintel_pcie_reset_bt`: drop `FUNC_ENA` / `MAC_INIT` /
//!    `FUNC_INIT`, ask for bus-master disconnect, wait for
//!    `BUS_MASTER_STS`, then pulse `SW_RESET`. A successful shared
//!    hardware reset leaves `BOOT_STAGE` reading exactly 0, which is
//!    how Linux checks it worked.
//! 3. Take MAC access (`MAC_ACCESS_REQ`, wait for `MAC_ACCESS_STS`)
//!    and read `HW_REV` (CNVi) and `RF_ID` (CNVr), then release it.
//!
//! 4. Publish the [`rings`] descriptor set through the
//!    context-information block, start the MAC, and wait for the
//!    device to reach its ROM bootloader.
//!
//! From there [`BtIntelPcie::send_packet`] and
//! [`BtIntelPcie::recv_packet`] carry HCI traffic.
//!
//! ## What the controller can do at this point
//!
//! It answers HCI commands **from its ROM bootloader** — version and
//! vendor queries, and the secure-send commands that download
//! operational firmware. It has no Bluetooth radio behind it yet:
//! that needs `intel/ibt-*.sfi` pushed over this transport, which is
//! a separate job riding on top of what lands here.
//!
//! Also absent: MSI-X. The GP0 alive interrupt and the TX/RX
//! completion interrupts are all polled instead — the boot-stage
//! transition GP0 announces is readable from `BOOT_STAGE`, and the
//! completion rings' index arrays say the same thing the completion
//! interrupts would.
//!
//! No [`crate::transport::HciTransport`] is registered yet. The HCI
//! core's bring-up sequence assumes a controller running operational
//! firmware, and pointing it at a bootloader would have it time out
//! on the first `Read Local Version` rather than report anything
//! useful.

extern crate alloc;

pub mod fw;
pub mod rings;

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `btintel_pcie_table[]`.

/// Intel.
pub const BT_VENDOR: u16 = 0x8086;

/// BlazarI — Wildcat Lake.
pub const BT_DEV_BLAZARIW: u16 = 0x4D76;
/// BlazarI — Lunar Lake.
pub const BT_DEV_BLAZARI: u16 = 0xA876;
/// Scorpius — Panther Lake-H484. The MS-03's `00:14.7`.
pub const BT_DEV_SCP_PTL_H484: u16 = 0xE376;
/// Scorpius — Panther Lake-H404.
pub const BT_DEV_SCP_PTL_H404: u16 = 0xE476;
/// Scorpius2 — Nova Lake-PCD-H.
pub const BT_DEV_SCP2_NVL_H: u16 = 0xD346;
/// Scorpius2 — Nova Lake-PCD-S.
pub const BT_DEV_SCP2_NVL_S: u16 = 0x6E74;

/// Every device ID this driver claims, in one `const` so
/// `register_pci_driver` and the match-table smoke cannot drift.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    BT_DEV_BLAZARIW,
    BT_DEV_BLAZARI,
    BT_DEV_SCP_PTL_H484,
    BT_DEV_SCP_PTL_H404,
    BT_DEV_SCP2_NVL_H,
    BT_DEV_SCP2_NVL_S,
];

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&did)
}

/// Human-readable SKU tag for a device id.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        BT_DEV_BLAZARIW => "blazariw-wcl",
        BT_DEV_BLAZARI => "blazari-lnl",
        BT_DEV_SCP_PTL_H484 => "scorpius-ptl-h484",
        BT_DEV_SCP_PTL_H404 => "scorpius-ptl-h404",
        BT_DEV_SCP2_NVL_H => "scorpius2-nvl-h",
        BT_DEV_SCP2_NVL_S => "scorpius2-nvl-s",
        _ => "btintel-pcie",
    }
}

// ── CSR registers (BAR0) ────────────────────────────────────────────

/// The CSR window is BAR0.
pub const BT_BAR: u8 = 0;

/// `BTINTEL_PCIE_CSR_FUNC_CTRL_REG`.
pub const CSR_FUNC_CTRL: u64 = 0x024;
/// `BTINTEL_PCIE_CSR_HW_REV_REG` — CNVi top identity.
pub const CSR_HW_REV: u64 = 0x028;
/// `BTINTEL_PCIE_CSR_RF_ID_REG` — CNVr (radio) identity.
pub const CSR_RF_ID: u64 = 0x09C;
/// `BTINTEL_PCIE_CSR_BOOT_STAGE_REG`.
pub const CSR_BOOT_STAGE: u64 = 0x108;
/// `BTINTEL_PCIE_CSR_IPC_CONTROL_REG`.
pub const CSR_IPC_CONTROL: u64 = 0x10C;
/// `BTINTEL_PCIE_CSR_IPC_STATUS_REG`.
pub const CSR_IPC_STATUS: u64 = 0x110;

/// `IPC_SLEEP_CTL` — host-driven D-state control. The operational
/// firmware waits for a D0 write here after its bootup notification
/// before it will serve HCI.
pub const CSR_IPC_SLEEP_CTL: u64 = 0x114;

/// `BTINTEL_PCIE_STATE_D0` — fully powered.
pub const POWER_STATE_D0: u32 = 0;
/// `BTINTEL_PCIE_STATE_D3_HOT`.
pub const POWER_STATE_D3_HOT: u32 = 2;
/// `BTINTEL_PCIE_STATE_D3_COLD`.
pub const POWER_STATE_D3_COLD: u32 = 3;
/// `BTINTEL_PCIE_CSR_CI_ADDR_LSB_REG` — low half of the context-info
/// DMA address the device fetches its boot parameters from.
pub const CSR_CI_ADDR_LSB: u64 = 0x118;
/// `BTINTEL_PCIE_CSR_CI_ADDR_MSB_REG`.
pub const CSR_CI_ADDR_MSB: u64 = 0x11C;
/// `BTINTEL_PCIE_CSR_IMG_RESPONSE_REG`.
pub const CSR_IMG_RESPONSE: u64 = 0x12C;
/// `BTINTEL_PCIE_CSR_MBOX_1_REG`.
pub const CSR_MBOX_1: u64 = 0x170;
/// `BTINTEL_PCIE_CSR_MBOX_STATUS_REG`.
pub const CSR_MBOX_STATUS: u64 = 0x180;
/// `BTINTEL_PCIE_CSR_HBUS_TARG_WRPTR` — the RX doorbell.
pub const CSR_HBUS_TARG_WRPTR: u64 = 0x460;
/// `BTINTEL_PCIE_CSR_MSIX_BASE`.
pub const CSR_MSIX_BASE: u64 = 0x2000;

// FUNC_CTRL bits.
/// `FUNC_ENA` — function enable.
pub const FUNC_CTRL_FUNC_ENA: u32 = 1 << 0;
/// `MAC_INIT` — start the primary bootloader.
pub const FUNC_CTRL_MAC_INIT: u32 = 1 << 6;
/// `FUNC_INIT`.
pub const FUNC_CTRL_FUNC_INIT: u32 = 1 << 7;
/// `MAC_ACCESS_STS` — the device has granted MAC access.
pub const FUNC_CTRL_MAC_ACCESS_STS: u32 = 1 << 20;
/// `MAC_ACCESS_REQ` — the host is asking for MAC access.
pub const FUNC_CTRL_MAC_ACCESS_REQ: u32 = 1 << 21;
/// `BUS_MASTER_STS` — bus mastering has quiesced.
pub const FUNC_CTRL_BUS_MASTER_STS: u32 = 1 << 28;
/// `BUS_MASTER_DISCON` — ask the device to stop mastering.
pub const FUNC_CTRL_BUS_MASTER_DISCON: u32 = 1 << 29;
/// `SW_RESET`.
pub const FUNC_CTRL_SW_RESET: u32 = 1 << 31;

// BOOT_STAGE bits.
/// Running from ROM.
pub const BOOT_STAGE_ROM: u32 = 1 << 0;
/// Running the intermediate loader.
pub const BOOT_STAGE_IML: u32 = 1 << 1;
/// Running operational firmware.
pub const BOOT_STAGE_OPFW: u32 = 1 << 2;
/// ROM is locked down.
pub const BOOT_STAGE_ROM_LOCKDOWN: u32 = 1 << 10;
/// IML is locked down.
pub const BOOT_STAGE_IML_LOCKDOWN: u32 = 1 << 11;
/// The device raised a warning.
pub const BOOT_STAGE_DEVICE_WARNING: u32 = 1 << 12;
/// The device is in its abort handler.
pub const BOOT_STAGE_ABORT_HANDLER: u32 = 1 << 13;
/// The device has halted.
pub const BOOT_STAGE_DEVICE_HALTED: u32 = 1 << 14;
/// MAC access is on.
pub const BOOT_STAGE_MAC_ACCESS_ON: u32 = 1 << 16;
/// The device is alive.
pub const BOOT_STAGE_ALIVE: u32 = 1 << 23;
/// D3 state is ready.
pub const BOOT_STAGE_D3_STATE_READY: u32 = 1 << 24;

// ── CNVi / CNVr decode ──────────────────────────────────────────────
//
// `INTEL_CNVX_TOP_TYPE` / `INTEL_CNVX_TOP_STEP` in `btintel.h`.

/// Top type — bits 11:0 of `HW_REV` / `RF_ID`.
pub const fn cnvx_top_type(cnvx: u32) -> u16 {
    (cnvx & 0x0000_0FFF) as u16
}

/// Top stepping — bits 27:24.
pub const fn cnvx_top_step(cnvx: u32) -> u8 {
    ((cnvx & 0x0F00_0000) >> 24) as u8
}

/// `BTINTEL_CNVI_BLAZARI` — Lunar Lake.
pub const CNVI_BLAZARI: u16 = 0x900;
/// `BTINTEL_CNVI_BLAZARIW` — Wildcat Lake.
pub const CNVI_BLAZARIW: u16 = 0x901;
/// `BTINTEL_CNVI_GAP` — Gale Peak2, Meteor Lake.
pub const CNVI_GAP: u16 = 0x910;
/// `BTINTEL_CNVI_BLAZARU` — BlazarU, Meteor Lake.
pub const CNVI_BLAZARU: u16 = 0x930;
/// `BTINTEL_CNVI_SCP` — Scorpius Peak, Panther Lake.
pub const CNVI_SCP: u16 = 0xA00;
/// `BTINTEL_CNVI_SCP2` — Scorpius Peak2, Nova Lake.
pub const CNVI_SCP2: u16 = 0xA10;
/// `BTINTEL_CNVI_SCP2F` — Scorpius Peak2F, Nova Lake.
pub const CNVI_SCP2F: u16 = 0xA20;

/// Human-readable name for a CNVi top type.
pub const fn cnvi_name(top_type: u16) -> &'static str {
    match top_type {
        CNVI_BLAZARI => "BlazarI",
        CNVI_BLAZARIW => "BlazarIW",
        CNVI_GAP => "GalePeak2",
        CNVI_BLAZARU => "BlazarU",
        CNVI_SCP => "ScorpiusPeak",
        CNVI_SCP2 => "ScorpiusPeak2",
        CNVI_SCP2F => "ScorpiusPeak2F",
        _ => "unknown-cnvi",
    }
}

// ── Timeouts ────────────────────────────────────────────────────────
//
// Linux polls with `usleep_range` and a retry count; the equivalent
// wall-clock budget is used here.

/// Linux retries the bus-master quiesce three times at ~10 ms.
pub const BUS_MASTER_QUIESCE_MS: u64 = 40;
/// Settle time after the bus-master quiesce and after `SW_RESET`.
pub const RESET_SETTLE_MS: u64 = 12;
/// Linux retries the MAC-access grant 15 times at ~1 ms.
pub const MAC_ACCESS_TIMEOUT_MS: u64 = 20;
/// `BTINTEL_DEFAULT_INTR_TIMEOUT_MS` — how long the device is given
/// to reach its ROM bootloader after `MAC_INIT`.
pub const ALIVE_TIMEOUT_MS: u64 = 3_000;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BtPcieError {
    BarMapFailed,
    /// BAR0 does not cover the CSR window.
    BarTooSmall,
    /// Registers read back all-ones — the device is not responding.
    DeviceGone,
    /// `BOOT_STAGE` was non-zero after `SW_RESET`, so the shared
    /// hardware reset did not take.
    ResetFailed(u32),
    /// The device never granted MAC access.
    MacAccessTimeout,
    /// Ran out of memory allocating the descriptor rings.
    NoMemory,
    /// An HCI packet did not fit one 4 KiB DMA buffer.
    PacketTooLarge,
    /// An index array held a value outside its ring.
    RingIndexOutOfRange,
    /// The device did not retire a posted transfer descriptor.
    TxTimeout,
    /// The device never reported reaching its ROM bootloader.
    AliveTimeout,
    /// `BOOT_STAGE` came back without `ROM` after `MAC_INIT`.
    NotInBootloader(u32),
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed PCIe Bluetooth controller, reset and identified.
pub struct BtIntelPcie {
    mmio: MmioRegion,
    /// Serialises `FUNC_CTRL` read-modify-writes.
    ctrl: IrqSafeSpinLock<()>,
    /// PCI device id.
    pub device_id: u16,
    /// `CSR_HW_REV` — the CNVi identity word.
    pub cnvi: u32,
    /// `CSR_RF_ID` — the CNVr (radio) identity word.
    pub cnvr: u32,
    /// `BOOT_STAGE` as read after the reset.
    pub boot_stage: u32,
    /// DMA descriptor set, once the transport is up.
    rings: rings::Rings,
}

// SAFETY: the only interior-mutable state is the `ctrl` lock itself;
// `mmio` describes an identity-mapped MMIO window this driver owns
// exclusively and the remaining fields are written once at bring-up.
unsafe impl Send for BtIntelPcie {}
// SAFETY: every read-modify-write of `FUNC_CTRL` takes `ctrl`, so
// concurrent `&BtIntelPcie` use from several CPUs is serialized.
unsafe impl Sync for BtIntelPcie {}

impl core::fmt::Debug for BtIntelPcie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BtIntelPcie")
            .field("device_id", &self.device_id)
            .field("cnvi", &self.cnvi)
            .field("cnvr", &self.cnvr)
            .field("boot_stage", &self.boot_stage)
            .finish_non_exhaustive()
    }
}

impl BtIntelPcie {
    /// CNVi top type.
    pub const fn cnvi_top_type(&self) -> u16 {
        cnvx_top_type(self.cnvi)
    }

    /// CNVi stepping.
    pub const fn cnvi_step(&self) -> u8 {
        cnvx_top_step(self.cnvi)
    }

    /// CNVr top type.
    pub const fn cnvr_top_type(&self) -> u16 {
        cnvx_top_type(self.cnvr)
    }

    /// CNVr stepping.
    pub const fn cnvr_step(&self) -> u8 {
        cnvx_top_step(self.cnvr)
    }

    /// Map BAR0, reset the controller, and read its identity.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, BtPcieError> {
        // SAFETY: forwarded — caller owns BAR0.
        let mmio = unsafe { map_bar(device, BT_BAR) }.map_err(|_| BtPcieError::BarMapFailed)?;
        if mmio.len < CSR_HBUS_TARG_WRPTR + 4 {
            return Err(BtPcieError::BarTooSmall);
        }

        // SAFETY: `mmio` is the mapped CSR window and `CSR_FUNC_CTRL`
        // is in range per the check above.
        if unsafe { mmio.read32(CSR_FUNC_CTRL) } == 0xFFFF_FFFF {
            return Err(BtPcieError::DeviceGone);
        }

        let mut dev = Self {
            mmio,
            ctrl: IrqSafeSpinLock::new(()),
            device_id: device.id.device,
            cnvi: 0,
            cnvr: 0,
            boot_stage: 0,
            rings: rings::Rings::alloc()?,
        };

        // SAFETY: `dev.mmio` is the mapped CSR window.
        unsafe { dev.reset()? };
        // SAFETY: same.
        unsafe { dev.read_identity()? };
        // SAFETY: same; the rings and context info are published.
        unsafe { dev.enable_bt()? };
        Ok(dev)
    }

    /// `btintel_pcie_reset_bt`.
    ///
    /// # Safety
    /// `self.mmio` must be this device's mapped CSR window.
    unsafe fn reset(&mut self) -> Result<(), BtPcieError> {
        let _g = self.ctrl.lock();

        // Quiesce: drop the enable bits and ask the device to stop
        // mastering the bus.
        // SAFETY: caller-asserted mapped CSR window.
        let mut reg = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
        reg &= !(FUNC_CTRL_FUNC_ENA | FUNC_CTRL_MAC_INIT | FUNC_CTRL_FUNC_INIT);
        reg |= FUNC_CTRL_BUS_MASTER_DISCON;
        // SAFETY: same; `FUNC_CTRL` is a writable control register.
        unsafe { self.mmio.write32(CSR_FUNC_CTRL, reg) };
        compiler_fence(Ordering::SeqCst);

        // Linux does not treat a quiesce timeout as fatal — it falls
        // through to the reset either way — so the result is ignored
        // rather than turned into an error the caller cannot act on.
        let _ = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: same.
                let r = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
                r & FUNC_CTRL_BUS_MASTER_STS != 0
            },
            narf_time::Deadline::after_ms(BUS_MASTER_QUIESCE_MS),
        );
        settle(RESET_SETTLE_MS);

        // Pulse SW_RESET.
        // SAFETY: same.
        let mut reg = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
        reg &= !(FUNC_CTRL_FUNC_ENA | FUNC_CTRL_MAC_INIT | FUNC_CTRL_FUNC_INIT);
        reg |= FUNC_CTRL_SW_RESET;
        // SAFETY: same.
        unsafe { self.mmio.write32(CSR_FUNC_CTRL, reg) };
        compiler_fence(Ordering::SeqCst);
        settle(RESET_SETTLE_MS);

        // A successful shared hardware reset leaves BOOT_STAGE at
        // exactly 0. Any other value means the device did not take
        // the reset — Linux returns -ENODEV here.
        // SAFETY: same.
        let boot_stage = unsafe { self.mmio.read32(CSR_BOOT_STAGE) };
        if boot_stage != 0 {
            return Err(BtPcieError::ResetFailed(boot_stage));
        }
        self.boot_stage = boot_stage;
        Ok(())
    }

    /// Take MAC access, read CNVi / CNVr, release it again.
    ///
    /// # Safety
    /// `self.mmio` must be this device's mapped CSR window.
    unsafe fn read_identity(&mut self) -> Result<(), BtPcieError> {
        // SAFETY: caller-asserted mapped CSR window.
        unsafe { self.get_mac_access()? };

        // SAFETY: same.
        self.cnvi = unsafe { self.mmio.read32(CSR_HW_REV) };
        // SAFETY: same.
        self.cnvr = unsafe { self.mmio.read32(CSR_RF_ID) };

        // SAFETY: same.
        unsafe { self.release_mac_access() };
        Ok(())
    }

    /// `btintel_pcie_get_mac_access`.
    ///
    /// # Safety
    /// `self.mmio` must be this device's mapped CSR window.
    unsafe fn get_mac_access(&self) -> Result<(), BtPcieError> {
        let _g = self.ctrl.lock();
        // SAFETY: caller-asserted mapped CSR window.
        let reg = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
        if reg & FUNC_CTRL_MAC_ACCESS_REQ == 0 {
            // SAFETY: same.
            unsafe {
                self.mmio
                    .write32(CSR_FUNC_CTRL, reg | FUNC_CTRL_MAC_ACCESS_REQ)
            };
            compiler_fence(Ordering::SeqCst);
        }
        let granted = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: same.
                let r = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
                r & FUNC_CTRL_MAC_ACCESS_STS != 0
            },
            narf_time::Deadline::after_ms(MAC_ACCESS_TIMEOUT_MS),
        );
        if !granted {
            return Err(BtPcieError::MacAccessTimeout);
        }
        Ok(())
    }

    /// `btintel_pcie_release_mac_access`.
    ///
    /// # Safety
    /// `self.mmio` must be this device's mapped CSR window.
    unsafe fn release_mac_access(&self) {
        let _g = self.ctrl.lock();
        // SAFETY: caller-asserted mapped CSR window.
        let reg = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
        if reg & FUNC_CTRL_MAC_ACCESS_REQ != 0 {
            // SAFETY: same.
            unsafe {
                self.mmio
                    .write32(CSR_FUNC_CTRL, reg & !FUNC_CTRL_MAC_ACCESS_REQ)
            };
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// `btintel_pcie_enable_bt` — publish the context-information
    /// address, start the MAC, and wait for the device to reach its
    /// ROM bootloader.
    ///
    /// # Safety
    /// `self.mmio` must be this device's mapped CSR window.
    unsafe fn enable_bt(&mut self) -> Result<(), BtPcieError> {
        let ci = self.rings.ctx_info_phys();
        {
            let _g = self.ctrl.lock();
            // SAFETY: caller-asserted mapped CSR window. The context
            // address must land before MAC_INIT: the device fetches
            // the block as part of coming up.
            unsafe {
                self.mmio.write32(CSR_CI_ADDR_LSB, ci as u32);
                self.mmio.write32(CSR_CI_ADDR_MSB, (ci >> 32) as u32);
            }
            compiler_fence(Ordering::SeqCst);

            // SAFETY: same.
            let mut reg = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
            reg &= !(FUNC_CTRL_FUNC_INIT | FUNC_CTRL_BUS_MASTER_DISCON | FUNC_CTRL_SW_RESET);
            reg |= FUNC_CTRL_FUNC_ENA | FUNC_CTRL_MAC_INIT;
            // SAFETY: same.
            unsafe { self.mmio.write32(CSR_FUNC_CTRL, reg) };
            compiler_fence(Ordering::SeqCst);

            // MAC is up; enable the BT function on top of it.
            // SAFETY: same.
            let reg = unsafe { self.mmio.read32(CSR_FUNC_CTRL) } | FUNC_CTRL_FUNC_INIT;
            // SAFETY: same.
            unsafe { self.mmio.write32(CSR_FUNC_CTRL, reg) };
            // Linux reads the register straight back to flush the
            // posted write before it starts waiting.
            // SAFETY: same.
            let _ = unsafe { self.mmio.read32(CSR_FUNC_CTRL) };
        }
        compiler_fence(Ordering::SeqCst);

        // Linux waits on the GP0 mailbox interrupt; this polls
        // BOOT_STAGE for the same transition, which is the state that
        // interrupt announces.
        let alive = narf_scheduler::responsive_spin_until(
            || self.current_boot_stage() & BOOT_STAGE_ROM != 0,
            narf_time::Deadline::after_ms(ALIVE_TIMEOUT_MS),
        );
        let stage = self.current_boot_stage();
        if !alive {
            return Err(BtPcieError::AliveTimeout);
        }
        if stage & BOOT_STAGE_DEVICE_HALTED != 0 {
            return Err(BtPcieError::NotInBootloader(stage));
        }
        self.boot_stage = stage;

        // Hand the device the RX ring now that it is running.
        // SAFETY: `self.mmio` is the mapped CSR window.
        unsafe { self.rings.start_rx(&self.mmio) };
        Ok(())
    }

    /// Send one HCI packet.
    ///
    /// `pkt_type` is one of the `rings::HCI_*_PKT` constants — the
    /// Intel 4-byte type word, not the 1-byte BT SIG indicator.
    pub fn send_packet(&self, pkt_type: u32, payload: &[u8]) -> Result<(), BtPcieError> {
        // SAFETY: `self.mmio` is this device's mapped CSR window and
        // the rings were published during bring-up.
        unsafe { self.rings.transmit(&self.mmio, pkt_type, payload) }
    }

    /// Pop one received HCI packet, if the device has completed one.
    pub fn recv_packet(&self) -> Option<(u32, alloc::vec::Vec<u8>)> {
        // SAFETY: as above.
        unsafe { self.rings.receive(&self.mmio) }
    }

    /// `true` when the controller has RX completions waiting.
    pub fn rx_pending(&self) -> bool {
        self.rings.rx_completions_pending()
    }

    /// Write the host-side D-state. The operational firmware blocks
    /// on this after sending its bootup notification.
    pub fn set_power_state(&self, state: u32) {
        // SAFETY: `self.mmio` is the mapped CSR window and
        // `IPC_SLEEP_CTL` is a plain 32-bit register within it.
        unsafe { self.mmio.write32(CSR_IPC_SLEEP_CTL, state) };
    }

    /// Current `BOOT_STAGE`.
    pub fn current_boot_stage(&self) -> u32 {
        // SAFETY: `self.mmio` is the mapped CSR window.
        unsafe { self.mmio.read32(CSR_BOOT_STAGE) }
    }
}

/// Wait `ms` milliseconds without holding the CPU in a tight loop any
/// longer than the deadline. The reset sequence has mandatory settle
/// delays with nothing to poll, so there is no predicate to wait on.
fn settle(ms: u64) {
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_ms(ms));
}

/// Render a `BOOT_STAGE` word as a short list of set flags, for the
/// boot transcript.
pub fn boot_stage_flags(stage: u32) -> alloc::string::String {
    use core::fmt::Write as _;
    let mut s = alloc::string::String::new();
    let named: &[(u32, &str)] = &[
        (BOOT_STAGE_ROM, "rom"),
        (BOOT_STAGE_IML, "iml"),
        (BOOT_STAGE_OPFW, "opfw"),
        (BOOT_STAGE_ROM_LOCKDOWN, "rom-lockdown"),
        (BOOT_STAGE_IML_LOCKDOWN, "iml-lockdown"),
        (BOOT_STAGE_DEVICE_WARNING, "warning"),
        (BOOT_STAGE_ABORT_HANDLER, "abort"),
        (BOOT_STAGE_DEVICE_HALTED, "halted"),
        (BOOT_STAGE_MAC_ACCESS_ON, "mac-access"),
        (BOOT_STAGE_ALIVE, "alive"),
        (BOOT_STAGE_D3_STATE_READY, "d3-ready"),
    ];
    for (bit, name) in named {
        if stage & bit != 0 {
            if !s.is_empty() {
                s.push('|');
            }
            let _ = write!(s, "{}", name);
        }
    }
    if s.is_empty() {
        s.push_str("none");
    }
    s
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<alloc::sync::Arc<BtIntelPcie>>> =
    IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != BT_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // BUS_MASTER is set even though this stage issues no DMA: the
    // reset sequence asks the device to *stop* mastering and waits
    // for BUS_MASTER_STS, which only means something if mastering was
    // enabled to begin with.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    let dev = match unsafe { BtIntelPcie::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  btintel-pcie: bring-up failed on {:04x}: {:?}",
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
            "  btintel-pcie: {} CNVi={} step {} (raw {:#010x}) CNVr={:#05x} step {} boot-stage={}",
            name_for(dev.device_id),
            cnvi_name(dev.cnvi_top_type()),
            dev.cnvi_step(),
            dev.cnvi,
            dev.cnvr_top_type(),
            dev.cnvr_step(),
            boot_stage_flags(dev.current_boot_stage()),
        );
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("btintel-pcie"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    *CONTROLLER.lock() = Some(alloc::sync::Arc::new(dev));
    Ok(())
}

/// Download operational firmware into the probed controller.
///
/// Runs from a `Stage::Late` initcall rather than from `probe`: the
/// PCI probe pass is `Stage::Device`, and the firmware registry is
/// not populated until the `Stage::Late` initramfs and rootfs scans
/// have run. Probing brings the transport up; this makes the
/// controller usable.
pub fn load_firmware() {
    use core::fmt::Write as _;

    // The controller is reached through an `Arc` clone so the
    // registry lock is not held across the download, which spins for
    // as long as the controller takes to verify and boot an image.
    let controller = CONTROLLER.lock().clone();
    let Some(controller) = controller else {
        return;
    };

    let Some(write_auth) = narf_firmware::trusted_loader_authority() else {
        let _ = writeln!(
            narf_console::Writer,
            "  btintel-pcie: no firmware authority; controller left in its ROM bootloader",
        );
        return;
    };
    let auth = match write_auth.derive() {
        Ok(a) => a,
        Err(_) => return,
    };

    match fw::setup(&controller, &auth) {
        Ok(ver) => {
            let _ = writeln!(
                narf_console::Writer,
                "  btintel-pcie: firmware {} running (img-type {:#04x}, build {}-{}.{})",
                if ver.fw_id.is_empty() { "?" } else { &ver.fw_id },
                ver.img_type,
                ver.min_fw_build_nn,
                ver.min_fw_build_cw,
                ver.min_fw_build_yy,
            );
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  btintel-pcie: firmware download failed: {:?}",
                e,
            );
        }
    }
}

/// Register the PCIe Bluetooth driver — one match entry per device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: BT_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once a controller has been brought up.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed controller, if any.
pub fn with_controller<R>(f: impl FnOnce(&BtIntelPcie) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

#[doc(hidden)]
/// Test-only: forget the probed controller so a smoke can assert
/// end-state.
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
