//! RTSX SD card block-device bridge.
//!
//! ## What this file does
//!
//! Wraps an RTSX SD card as a `BlockDeviceSync` and registers it in the
//! block-device registry under the name `"mmcblk0"`.  The registration
//! happens on card-detect: when `register_card` is called from the
//! RTSX driver's card-identify path, the card immediately becomes
//! accessible as `/dev/mmcblk0` through the existing Wave-13
//! `devfs_block` bridge.  Registration also runs the block layer's
//! partition scan, so a partitioned card gains `mmcblk0p<N>` children
//! (#834).  `unregister_card` removes the partitions and the parent
//! again when the poll task observes a removal.
//!
//! Additionally, `/sys/class/mmc_host/mmc0/mmc0:<rca>/` is populated
//! with the card's real identity attributes, decoded from the CID the
//! identify sequence captured with CMD2.
//!
//! ## BlockDeviceSync impl
//!
//! - `read(lba, n_blocks, out)` → CMD17 per block via
//!   `RtsxController::read_block` (ping-pong buffer path).
//! - `write(lba, n_blocks, data)` → CMD24 per block via
//!   `RtsxController::write_block`.
//! - `capacity()` → `SdCardInfo::capacity_blocks`, decoded from the
//!   card's real CSD during identify.  A card whose CSD does not parse
//!   never reaches registration, so no default capacity exists here.
//! - `lba_size()` → always 512 bytes for SD cards.
//!
//! ## Sysfs
//!
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/cid`    → hex CID (real, CMD2)
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/name`   → CID product name
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/manfid` → CID manufacturer ID
//! - `/sys/class/mmc_host/mmc0/mmc0:<rca>/oemid`  → CID OEM ID
//!
//! ## Linux reference
//!
//! `drivers/mmc/core/host.c::mmc_alloc_host` (GPL-2.0-or-later) — allocates
//! an mmc_host and registers it under `mmc_host_class`; child card kobjects
//! appear at `mmc<N>:<rca>`.
//!
//! ## Deferred
//!
//! - CMD18/CMD25 (READ/WRITE_MULTIPLE_BLOCK) over the ADMA ring
//!   buffer — transfers here are single-block (CMD17/CMD24).
//! - MMC cards / HS200 tuning — this bridge serves SD cards only.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::registry::{
    register_block_device, unregister_block_device, BlockDeviceSync, BlockIoError,
};
use narf_drivers_storage_core::sd_proto::Cid;

use super::card::SdCardInfo;
use super::with_controller;

// ── RtsxBlockDevice ───────────────────────────────────────────────────────

/// Adapter: wraps the RTSX controller's SD read/write paths behind
/// `BlockDeviceSync` so it can live in the block-device registry.
///
/// Holds a copy of the card info (RCA, high_capacity, capacity_blocks)
/// so it can answer `capacity()` without touching MMIO.
pub struct RtsxBlockDevice {
    /// RCA (relative card address) for this card.
    pub rca: u16,
    /// True = SDHC/SDXC (block-addressed); false = SDSC (byte-addressed).
    pub high_capacity: bool,
    /// Card capacity in 512-byte blocks, from the card's real CSD.
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
            capacity_blocks: info.capacity_blocks,
        }
    }

    /// Translate a block-layer LBA to the on-card command argument:
    /// block address for SDHC/SDXC, byte address for SDSC.
    fn card_addr(&self, lba: u64) -> u32 {
        if self.high_capacity {
            lba as u32
        } else {
            (lba as u32).saturating_mul(512)
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

    /// Read `n_blocks` × 512 bytes starting at `lba` (CMD17 per block).
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
                let addr = self.card_addr(lba + i);
                let offset = i as usize * 512;
                let mut block = [0u8; 512];
                ctrl.read_block(addr, &mut block)
                    .map_err(|_| BlockIoError::DriverError)?;
                out[offset..offset + 512].copy_from_slice(&block);
            }
            Ok::<(), BlockIoError>(())
        })
        .ok_or(BlockIoError::DriverError)?
    }

    /// Write `n_blocks` × 512 bytes starting at `lba` (CMD24 per block).
    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if data.len() < needed {
            return Err(BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(BlockIoError::OutOfRange);
        }

        with_controller(|ctrl| {
            for i in 0..n_blocks as u64 {
                let addr = self.card_addr(lba + i);
                let offset = i as usize * 512;
                let mut block = [0u8; 512];
                block.copy_from_slice(&data[offset..offset + 512]);
                ctrl.write_block(addr, &block)
                    .map_err(|_| BlockIoError::DriverError)?;
            }
            Ok::<(), BlockIoError>(())
        })
        .ok_or(BlockIoError::DriverError)?
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
    register_block_device("mmcblk0", dev.clone() as Arc<dyn BlockDeviceSync>);

    // Scan the card for partitions (MBR / GPT) and register each as
    // `mmcblk0p<N>` — the same publication contract MSC / AHCI /
    // NVMe follow (#834). Best-effort: a card with no readable
    // partition table (blank card, superfloppy layout) just keeps
    // its bare whole-disk entry, so the scan's error is dropped,
    // exactly as at the other call sites.
    let _ = narf_block::partition::scan_and_register_partitions(dev, "mmcblk0");

    // Populate sysfs.
    register_sysfs(info);
}

/// Unregister a previously registered SD card: remove `"mmcblk0"`
/// from the block registry and drop its sysfs card kobject.
///
/// Called from the card-detect path when a ready card is removed.
pub fn unregister_card(info: SdCardInfo) {
    // Withdraw the partition children first: they borrow the card's
    // I/O path, and the registry has no cascade — MSC's unregister
    // does the same snapshot-then-remove dance.
    let children: Vec<&'static str> = narf_block::registry::block_devices()
        .iter()
        .filter(|e| e.parent == Some("mmcblk0"))
        .map(|e| e.name)
        .collect();
    for child in children {
        unregister_block_device(child);
    }
    unregister_block_device("mmcblk0");
    unregister_sysfs(info);
}

// ── Sysfs class registration ──────────────────────────────────────────────

/// Register `/sys/class/mmc_host/mmc0/mmc0:<rca>/` for the inserted card,
/// with identity attributes decoded from the card's real CID.
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

    let cid = Cid::parse_shifted(&info.cid);

    // Real CID captured by CMD2 during identify, in the shifted-word
    // layout (the controller strips the CRC7+end byte, so the top
    // byte of the 128-bit field is zero — the same representation
    // SDHCI hosts hand to the MMC core).
    let raw = info.cid;
    kobject_add_attr(&card_kobj, "cid", move || {
        format!("{:08x}{:08x}{:08x}{:08x}\n", raw[3], raw[2], raw[1], raw[0])
    });

    let name = cid_name_string(&cid);
    kobject_add_attr(&card_kobj, "name", move || format!("{}\n", name));

    let manfid = cid.manufacturer_id;
    kobject_add_attr(&card_kobj, "manfid", move || {
        format!("0x{:06x}\n", manfid as u32)
    });

    let oemid = ((cid.oem_id[0] as u16) << 8) | (cid.oem_id[1] as u16);
    kobject_add_attr(&card_kobj, "oemid", move || format!("0x{:04x}\n", oemid));
}

/// Remove the card's sysfs kobject (host kobject `mmc0` stays).
fn unregister_sysfs(info: SdCardInfo) {
    use narf_filesystem::sysfs::class_register;

    let mmc_class = class_register("mmc_host");
    if let Some(mmc0) = mmc_class.get_child("mmc0") {
        let card_name = format!("mmc0:{:04x}", info.rca);
        mmc0.remove_child(&card_name);
    }
}

/// Product name from the CID as a printable string: the 5-byte PNM
/// field is ASCII; trailing NUL/space padding is trimmed.
fn cid_name_string(cid: &Cid) -> String {
    let raw = core::str::from_utf8(&cid.product_name).unwrap_or("SD");
    let trimmed = raw.trim_end_matches(['\0', ' ']);
    if trimmed.is_empty() {
        String::from("SD")
    } else {
        String::from(trimmed)
    }
}

// ── Test-only helpers ─────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_block::registry::__reset_for_test as block_reset;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Runs [`smoke_rtsx_card_detect_registers_mmcblk0_inner`] against a scratch registry and restores the
    /// boot-time entries afterwards, so later suites still see the probed disks.
    fn smoke_rtsx_card_detect_registers_mmcblk0() -> TestResult {
        let saved = narf_block::registry::__snapshot_for_test();
        let r = smoke_rtsx_card_detect_registers_mmcblk0_inner();
        narf_block::registry::__restore_for_test(saved);
        r
    }

    fn smoke_rtsx_card_detect_registers_mmcblk0_inner() -> TestResult {
        block_reset();
        let info = SdCardInfo {
            rca: 0x0001,
            high_capacity: true,
            capacity_blocks: 4096,
            selected: true,
            cid: [0; 4],
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
            cid: [0; 4],
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
            cid: [0x42; 4],
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

    /// The sysfs identity attributes must be the card's REAL CID
    /// fields, not placeholders: build an SdCardInfo with a known
    /// CID (manufacturer 0x03, product name "SU08G") and check the
    /// decoded attrs.
    fn smoke_rtsx_sysfs_identity_from_cid() -> TestResult {
        narf_filesystem::sysfs::__reset_for_test();
        // Build the SdCardInfo CID via the same R2 conversion the
        // driver uses, from a CID register with MID=0x03,
        // OID="SD", PNM="SU08G".
        let mut frame = [0u8; 16];
        frame[0] = 0x3F;
        frame[1..16].copy_from_slice(&[
            0x03, b'S', b'D', b'S', b'U', b'0', b'8', b'G', 0x80, 0x12, 0x34, 0x56, 0x78, 0x01,
            0x42,
        ]);
        let info = SdCardInfo {
            rca: 0x0007,
            high_capacity: true,
            capacity_blocks: 1024,
            selected: true,
            cid: crate::rtsx::card::r2_frame_to_shifted_words(&frame),
        };
        register_sysfs(info);
        use narf_filesystem::sysfs::class_register;
        let mmc_class = class_register("mmc_host");
        let mmc0 = mmc_class.get_child("mmc0").expect("mmc0 not found");
        let card = mmc0.get_child("mmc0:0007").expect("mmc0:0007 not found");
        match card.attr_show("manfid") {
            Some(v) if v.contains("0x000003") => {}
            _ => return TestResult::Fail("manfid attr must decode the real CID manufacturer ID"),
        }
        match card.attr_show("name") {
            Some(v) if v.contains("SU08G") => {}
            _ => return TestResult::Fail("name attr must decode the real CID product name"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/storage/rtsx/block_bridge",
        smoke_rtsx_sysfs_identity_from_cid
    );
}
