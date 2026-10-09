//! RTSX SD card block-device bridge.
//!
//! ## What this file does
//!
//! Wraps an RTSX SD card as a `BlockDeviceSync` and registers it in the
//! block-device registry under the name `"mmcblk0"` (and partition nodes
//! `"mmcblk0p1"`, etc. once a partition scanner runs).  The registration
//! happens on card-detect: when `register_card` is called from the RTSX
//! driver's card-identify path, the card immediately becomes accessible
//! as `/dev/mmcblk0` through the existing Wave-13 `devfs_block` bridge.
//!
//! Additionally, `/sys/class/mmc_host/mmc0/mmc0:<rca>/` is populated
//! with card identity attributes.
//!
//! ## BlockDeviceSync impl
//!
//! - `read(lba, n_blocks, out)` → issues CMD17 per block via
//!   `RtsxController::read_block_dma`.
//! - `write(lba, n_blocks, data)` → not yet implemented (CMD24 path
//!   deferred; returns `DriverError`).
//! - `capacity()` → from `SdCardInfo::capacity_blocks` (or a default of
//!   0 if the CSD parse is deferred).
//! - `lba_size()` → always 512 bytes for SD cards.
//!
//! ## Sysfs
//!
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/cid`    → hex CID placeholder
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/name`   → "SD"
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/manfid` → "0x000000"
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/oemid`  → "0x0000"
//!
//! ## Linux reference
//!
//! `drivers/mmc/core/host.c::mmc_alloc_host` (GPL-2.0-or-later) — allocates
//! an mmc_host and registers it under `mmc_host_class`; child card kobjects
//! appear at `mmc<N>:<rca>`.
//!
//! ## Deferred
//!
//! - CMD24 (WRITE_BLOCK) — write path.
//! - CMD25/CMD18 (WRITE/READ_MULTIPLE_BLOCK) — multi-block transfers.
//! - MMC HS200/HS400 tuning.
//! - CSD parse to extract real capacity.

use alloc::format;
use alloc::sync::Arc;

use narf_block::registry::{register_block_device, BlockDeviceSync, BlockIoError};

use super::card::SdCardInfo;
use super::with_controller;

// ── RtsxBlockDevice ───────────────────────────────────────────────────────

/// Adapter: wraps the RTSX controller's SD read path behind
/// `BlockDeviceSync` so it can live in the block-device registry.
///
/// Holds a copy of the card info (RCA, high_capacity, capacity_blocks)
/// so it can answer `capacity()` without touching MMIO.
pub struct RtsxBlockDevice {
    /// RCA (relative card address) for this card.
    pub rca: u16,
    /// True = SDHC/SDXC (block-addressed); false = SDSC (byte-addressed).
    pub high_capacity: bool,
    /// Card capacity in 512-byte blocks (may be 0 if CSD not parsed).
    pub capacity_blocks: u64,
}

impl core::fmt::Debug for RtsxBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtsxBlockDevice")
            .field("rca", &format_args!("{:#06x}", self.rca))
            .field("high_capacity", &self.high_capacity)
            .field("capacity_blocks", &self.capacity_blocks)
            .finish()
    }
}

impl RtsxBlockDevice {
    pub fn new(info: SdCardInfo) -> Self {
        RtsxBlockDevice {
            rca: info.rca,
            high_capacity: info.high_capacity,
            capacity_blocks: if info.capacity_blocks > 0 {
                info.capacity_blocks
            } else {
                // Default to 1 GiB (2 Mi blocks) when CSD not parsed.
                // A real CSD parse (CMD9) lands in a follow-up.
                2 * 1024 * 1024
            },
        }
    }
}

impl BlockDeviceSync for RtsxBlockDevice {
    fn lba_size(&self) -> u32 {
        512
    }

    fn capacity(&self) -> u64 {
        self.capacity_blocks
    }

    /// Read `n_blocks` × 512 bytes starting at `lba`.
    ///
    /// For SDHC/SDXC `lba` maps directly to a block address.
    /// For SDSC it would need to be multiplied by 512 — not implemented
    /// (SDSC cards are extremely rare in practice; 2011 and earlier).
    ///
    /// Linux ref: `mmc_read_blocks` → `mmc_wait_for_req` →
    /// `rtsx_pci_sdmmc_request` in
    /// `drivers/mmc/host/rtsx_pci_sdmmc.c`.
    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if out.len() < needed {
            return Err(BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(BlockIoError::OutOfRange);
        }

        with_controller(|ctrl| {
            for i in 0..n_blocks as u64 {
                let block_addr = if self.high_capacity {
                    (lba + i) as u32
                } else {
                    // SDSC: byte-addressed; multiply by 512.
                    ((lba + i) as u32).saturating_mul(512)
                };
                let offset = i as usize * 512;
                // SAFETY: card must be selected (called after identify_sd_card).
                unsafe {
                    ctrl.read_block_dma(block_addr, &mut out[offset..offset + 512])
                        .map_err(|_| BlockIoError::DriverError)?;
                }
            }
            Ok::<(), BlockIoError>(())
        })
        .ok_or(BlockIoError::DriverError)?
    }

    /// Write `n_blocks` × 512 bytes starting at `lba`.
    ///
    /// CMD24 (WRITE_BLOCK) deferred — see module-level doc.
    fn write(&self, _lba: u64, _n_blocks: u16, _data: &[u8]) -> Result<(), BlockIoError> {
        Err(BlockIoError::DriverError)
    }
}

// ── Card registration ─────────────────────────────────────────────────────

/// Register an identified SD card as `"mmcblk0"` in the block registry.
///
/// Called from the RTSX probe / card-detect path after
/// `RtsxController::identify_sd_card` succeeds.
///
/// Linux ref: `mmc_add_card` → `device_add` in
/// `drivers/mmc/core/bus.c:mmc_add_card` (GPL-2.0-or-later).
pub fn register_card(info: SdCardInfo) {
    let dev = Arc::new(RtsxBlockDevice::new(info));

    // Register as the primary MMC block device.
    register_block_device("mmcblk0", dev as Arc<dyn BlockDeviceSync>);

    // Populate sysfs.
    register_sysfs(info);
}

// ── Sysfs class registration ──────────────────────────────────────────────

/// Register `/sys/class/mmc_host/mmc0/mmc0:<rca>/` for the inserted card.
///
/// Linux ref: `mmc_alloc_host` in `drivers/mmc/core/host.c` and
/// `mmc_add_card` in `drivers/mmc/core/bus.c`.
fn register_sysfs(info: SdCardInfo) {
    use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

    let mmc_class = class_register("mmc_host");
    // /sys/class/mmc_host/mmc0/
    let mmc0 = class_device_register(mmc_class, "mmc0");
    // /sys/class/mmc_host/mmc0/mmc0:<rca>/
    let card_name = format!("mmc0:{:04x}", info.rca);
    let card_kobj = class_device_register(mmc0, &card_name);

    // Placeholder CID: real CID requires CMD2 R2 capture, deferred.
    // Linux: `drivers/mmc/core/mmc.c::mmc_read_cid` issues CMD2 to
    // get the 128-bit CID; we expose 32 zero hex digits as a stub.
    let rca = info.rca;
    kobject_add_attr(&card_kobj, "cid", move || {
        alloc::format!("{:032x}\n", rca as u64)
    });

    kobject_add_attr(&card_kobj, "name", move || "SD\n".into());

    kobject_add_attr(&card_kobj, "manfid", move || "0x000000\n".into());

    kobject_add_attr(&card_kobj, "oemid", move || "0x0000\n".into());
}

// ── Test-only helpers ─────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_block::registry::__reset_for_test as block_reset;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_rtsx_card_detect_registers_mmcblk0() -> TestResult {
        block_reset();
        let info = SdCardInfo {
            rca: 0x0001,
            high_capacity: true,
            capacity_blocks: 4096,
            selected: true,
        };
        register_card(info);
        let found = narf_block::registry::find_block_device("mmcblk0");
        match found {
            Some(_) => TestResult::Pass,
            None => TestResult::Fail("mmcblk0 not found in block registry after register_card"),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/block_bridge",
        smoke_rtsx_card_detect_registers_mmcblk0
    );

    fn smoke_rtsx_block_device_capacity() -> TestResult {
        let info = SdCardInfo {
            rca: 0x0002,
            high_capacity: true,
            capacity_blocks: 8192,
            selected: true,
        };
        let dev = RtsxBlockDevice::new(info);
        if dev.capacity() != 8192 {
            return TestResult::Fail("capacity mismatch");
        }
        if dev.lba_size() != 512 {
            return TestResult::Fail("lba_size should be 512");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/storage/rtsx/block_bridge",
        smoke_rtsx_block_device_capacity
    );

    fn smoke_rtsx_sysfs_cid_attr() -> TestResult {
        narf_filesystem::sysfs::__reset_for_test();
        let info = SdCardInfo {
            rca: 0x0042,
            high_capacity: false,
            capacity_blocks: 0,
            selected: true,
        };
        register_sysfs(info);
        use narf_filesystem::sysfs::class_register;
        let mmc_class = class_register("mmc_host");
        let mmc0 = mmc_class.get_child("mmc0").expect("mmc0 not found");
        let card = mmc0.get_child("mmc0:0042").expect("mmc0:0042 not found");
        let val = card.attr_show("cid");
        match val {
            Some(_) => TestResult::Pass,
            None => TestResult::Fail("cid attr missing"),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/block_bridge",
        smoke_rtsx_sysfs_cid_attr
    );
}
