//! eMMC driver on the SDHCI host — clean-room.
//!
//! Reference: **JEDEC Standard JESD84-B51 — "Embedded Multi-Media
//! Card (e•MMC) Electrical Standard (5.1)"** (public document).
//! Section numbers below refer to it; EXT_CSD field offsets are
//! §7.4 Table 93, decoded by `narf_drivers_storage_core::emmc`.
//!
//! No GPL Linux source consulted.
//!
//! ## Identification
//!
//! An eMMC card does not implement APP_CMD, so the SD sequence in
//! [`super::Sdhci::identify_sequence`] fails its CMD55 probe with
//! [`super::SdhciError::NotSdCard`] and `identify_any` falls through
//! here. The eMMC sequence (§6.4) is:
//!
//! ```text
//!   CMD0   GO_IDLE_STATE (reset to Idle)
//!   CMD1   SEND_OP_COND, polled until the OCR busy bit sets (§6.4.2/§6.4.3)
//!   CMD2   ALL_SEND_CID
//!   CMD3   SET_RELATIVE_ADDR (the host assigns RCA 1, §6.4.4)
//!   CMD9   SEND_CSD (capacity fallback when SEC_COUNT is 0)
//!   CMD7   SELECT_CARD → Tran state
//!   CMD8   SEND_EXT_CSD (one 512-byte data block)
//!   CMD6   SWITCH PARTITION_CONFIG to the user area (pin the access
//!          cache to a known state; exercises the switch path once)
//! ```
//!
//! Bus-width negotiation and the post-identification clock raise
//! belong to #837; HS200/HS400 to #838. This driver stays on the
//! identification profile (1-bit, 400 kHz) until those land —
//! exactly where the SD path stays today.
//!
//! ## Partitions
//!
//! The user area is published as `emmc0` with the usual MBR/GPT
//! scan (`emmc0p<N>`). The hardware partitions are separate address
//! spaces selected by PARTITION_CONFIG (§7.4.69): boot 1/2 as
//! `emmc0boot0` / `emmc0boot1`, general-purpose 1..4 as
//! `emmc0gp0`..`emmc0gp3`, each a plain block device. Every I/O
//! through one of those devices first switches the card to its
//! access value (CMD6 + CMD13 verification) and the switch is
//! cached, so back-to-back I/O to one partition costs no switch.
//!
//! RPMB is decoded and sized but deliberately NOT published as a
//! plain block device: JESD84-B51 §6.15 admits only authenticated
//! request/response frames (CMD23 + CMD17/CMD24 carrying a MAC and
//! a nonce / write counter) — a plain block read would return a
//! frame, and a plain write would be rejected by the device. The
//! authenticated-frame protocol is a follow-up; see the PR body.

use alloc::sync::Arc;

use crate::emmc::{
    ExtCsd, CARD_STATE_TRAN, CARD_STATUS_SWITCH_ERROR, EXT_CSD_PARTITION_CONFIG, MMC_CMD1_ARG,
    MMC_OCR_BUSY, MMC_OCR_SECTOR_MODE, PARTITION_ACCESS_BOOT1, PARTITION_ACCESS_BOOT2,
    PARTITION_ACCESS_GP1, PARTITION_ACCESS_USER, PARTITION_CONFIG_PARTITION_ACCESS_MASK,
};
use crate::sd_proto::R1Status;

use super::{with_controller, Sdhci, SdhciError, RESP_136, RESP_48, RESP_48_BUSY, RESP_NONE};

/// An identified eMMC card.
#[derive(Copy, Clone, Debug)]
pub struct EmmcCard {
    /// Relative card address assigned by CMD3 (1, the JEDEC
    /// default — §6.4.1).
    pub rca: u16,
    /// CID register read via CMD2 (response 136), raw words.
    /// Read by the fixture (which asserts the CMD2 capture); a
    /// sysfs-style card identity will consume it.
    #[allow(dead_code)]
    pub cid: [u32; 4],
    /// Decoded EXT_CSD register read via CMD8.
    pub ext_csd: ExtCsd,
    /// User-area capacity in 512-byte blocks.
    pub capacity_blocks: u64,
    /// True when the card requires sector addressing (OCR bit 30
    /// in the final CMD1 response, §6.4.2).
    pub sector_mode: bool,
}

impl EmmcCard {
    /// Boot partition size in 512-byte blocks (both boot
    /// partitions share one BOOT_SIZE_MULT).
    pub(crate) fn boot_blocks(&self) -> u64 {
        self.ext_csd.boot_partition_bytes() / 512
    }

    /// RPMB partition size in 512-byte blocks (decoded and sized
    /// only — see the module docs on why RPMB is not published).
    pub(crate) fn rpmb_blocks(&self) -> u64 {
        self.ext_csd.rpmb_partition_bytes() / 512
    }

    /// General-purpose partition `index` (0..4 → GP1..GP4) size in
    /// 512-byte blocks.
    pub(crate) fn gp_blocks(&self, index: usize) -> u64 {
        self.ext_csd.gp_partition_blocks(index)
    }
}

/// One address space of the card, selected by PARTITION_CONFIG
/// access value (§7.4.69).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum EmmcPartition {
    User,
    Boot0,
    Boot1,
    Gp(u8),
}

impl EmmcPartition {
    const fn access_value(self) -> u8 {
        match self {
            Self::User => PARTITION_ACCESS_USER,
            Self::Boot0 => PARTITION_ACCESS_BOOT1,
            Self::Boot1 => PARTITION_ACCESS_BOOT2,
            Self::Gp(i) => PARTITION_ACCESS_GP1 + i,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::User => "emmc0",
            Self::Boot0 => "emmc0boot0",
            Self::Boot1 => "emmc0boot1",
            Self::Gp(0) => "emmc0gp0",
            Self::Gp(1) => "emmc0gp1",
            Self::Gp(2) => "emmc0gp2",
            Self::Gp(_) => "emmc0gp3",
        }
    }
}

impl Sdhci {
    /// Run the eMMC identification sequence (§6.4).
    ///
    /// # Safety
    /// MMIO ownership; called only once at bring-up (via
    /// `identify_any`) or once per fixture install in tests.
    pub(crate) unsafe fn identify_emmc_sequence(&self) -> Result<EmmcCard, SdhciError> {
        // CMD0 — reset to Idle (§6.4.1). The SD attempt already
        // sent one; a fresh reset makes the eMMC attempt
        // independent of whatever state the SD probe left behind.
        let _ = self.cmd(0, 0, RESP_NONE, false, 0, 0, 0)?;

        // CMD1 — SEND_OP_COND (§6.4.2/§6.4.3). Poll until the busy
        // bit (31) sets. The access-mode bits are only valid in the
        // final (ready) response — ignore them while busy.
        let mut ocr = 0u32;
        for _ in 0..1_000u32 {
            ocr = self.cmd(1, MMC_CMD1_ARG, RESP_48, false, 0, 0, 0)?;
            if ocr & MMC_OCR_BUSY != 0 {
                break;
            }
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }
        }
        if ocr & MMC_OCR_BUSY == 0 {
            return Err(SdhciError::CmdTimeout);
        }
        let sector_mode = ocr & MMC_OCR_SECTOR_MODE != 0;

        // CMD2 — ALL_SEND_CID (R2).
        let _ = self.cmd(2, 0, RESP_136, false, 0, 0, 0)?;
        let cid = self.read_response_136();

        // CMD3 — SET_RELATIVE_ADDR (R1): the host assigns the RCA
        // (§6.4.4). 1 is the JEDEC default address (§6.4.1).
        let rca: u16 = 1;
        let _ = self.cmd(3, (rca as u32) << 16, RESP_48, false, 0, 0, 0)?;

        // CMD9 — SEND_CSD (R2), addressed by RCA.
        let _ = self.cmd(9, (rca as u32) << 16, RESP_136, false, 0, 0, 0)?;
        let csd_raw = self.read_response_136();

        // CMD7 — SELECT_CARD (R1b) → Tran state.
        let _ = self.cmd(7, (rca as u32) << 16, RESP_48_BUSY, false, 0, 0, 0)?;

        // CMD8 — SEND_EXT_CSD (R1 + one 512-byte data block).
        let ext_csd = self.read_ext_csd()?;

        // Capacity (§6.4.2): SEC_COUNT is authoritative when
        // nonzero; a zero SEC_COUNT means a <2 GiB card whose
        // capacity comes from the legacy CSD (same v1.0 layout as
        // the SD CSD — JESD84-B51 §7.3 fields C_SIZE [73:62] /
        // C_SIZE_MULT [49:47] / READ_BL_LEN [83:80]).
        let capacity_blocks = if ext_csd.sec_count > 0 {
            ext_csd.sec_count as u64
        } else {
            match crate::sd_proto::Csd::parse_shifted(&csd_raw) {
                Some(csd) => csd.capacity_bytes / 512,
                None => return Err(SdhciError::BadExtCsd),
            }
        };
        if capacity_blocks == 0 {
            return Err(SdhciError::BadExtCsd);
        }

        // Pin the partition access to the user area (preserving the
        // boot-enable bits): whatever a previous session left in
        // PARTITION_CONFIG, the driver's access cache starts at
        // user, so make the card agree before any I/O. This also
        // exercises the CMD6 + CMD13 switch path once at identify
        // time.
        let user_value = ext_csd.partition_config & !PARTITION_CONFIG_PARTITION_ACCESS_MASK;
        self.switch_ext_csd_byte(rca, EXT_CSD_PARTITION_CONFIG as u8, user_value)?;

        Ok(EmmcCard {
            rca,
            cid,
            ext_csd,
            capacity_blocks,
            sector_mode,
        })
    }

    /// Read the 512-byte EXT_CSD register via CMD8 (SEND_EXT_CSD).
    fn read_ext_csd(&self) -> Result<ExtCsd, SdhciError> {
        let mut buf = [0u8; 512];
        self.read_pio_block(8, 0, &mut buf)?;
        ExtCsd::parse(&buf).map_err(|_| SdhciError::BadExtCsd)
    }

    /// Send SEND_STATUS (CMD13) and return the raw R1 status word.
    fn send_status(&self, rca: u16) -> Result<u32, SdhciError> {
        self.cmd(13, (rca as u32) << 16, RESP_48, false, 0, 0, 0)
    }

    /// Write one EXT_CSD byte via SWITCH (CMD6, §6.6.1) and verify
    /// it with SEND_STATUS (CMD13): the switch is only done once
    /// CMD13 reports Tran state + ready-for-data with no
    /// SWITCH_ERROR (§6.6.2.2).
    fn switch_ext_csd_byte(&self, rca: u16, index: u8, value: u8) -> Result<(), SdhciError> {
        let arg = ExtCsd::switch_argument(index, value);
        let _ = self.cmd(6, arg, RESP_48_BUSY, false, 0, 0, 0)?;
        // CMD6 is R1b: the card may hold DAT0 busy after
        // responding. Poll CMD13 until the card is back in Tran
        // state and ready, or the SWITCH_ERROR bit says the switch
        // was refused.
        for _ in 0..100u32 {
            let status = self.send_status(rca)?;
            let st = R1Status { raw: status };
            if status & CARD_STATUS_SWITCH_ERROR != 0 {
                return Err(SdhciError::SwitchError);
            }
            if st.current_state() == CARD_STATE_TRAN && st.ready_for_data() {
                return Ok(());
            }
            for _ in 0..1_000 {
                core::hint::spin_loop();
            }
        }
        Err(SdhciError::CmdTimeout)
    }

    /// Switch the card to PARTITION_CONFIG access `access` unless
    /// it is already there. The cached value is updated only after
    /// the SWITCH verifies, so a failed switch leaves the cache
    /// (and the card) on the previous partition.
    pub(crate) fn ensure_partition_access(&self, access: u8) -> Result<(), SdhciError> {
        if *self.emmc_access.lock() == access {
            return Ok(());
        }
        // Copy the RCA + the boot-enable bits out of the card slot;
        // no lock is held across the SWITCH commands.
        let (rca, partition_config) = {
            let g = self.emmc.lock();
            let card = g.as_ref().ok_or(SdhciError::NoCard)?;
            (card.rca, card.ext_csd.partition_config)
        };
        // Preserve the boot-enable/ack bits; only the access field
        // moves. (The stored PARTITION_CONFIG's access bits go stale
        // after a switch, but bits [7:3] never change here, so the
        // stored copy stays a valid base.)
        let value = (partition_config & !PARTITION_CONFIG_PARTITION_ACCESS_MASK)
            | (access & PARTITION_CONFIG_PARTITION_ACCESS_MASK);
        self.switch_ext_csd_byte(rca, EXT_CSD_PARTITION_CONFIG as u8, value)?;
        *self.emmc_access.lock() = access;
        Ok(())
    }
}

/// Publish an identified eMMC card: the user area as `emmc0` with
/// a partition scan (`emmc0p<N>`), the boot partitions as
/// `emmc0boot0` / `emmc0boot1`, and each configured general-purpose
/// partition as `emmc0gp<N>` — the same publication contract the SD
/// path follows (#834). A card whose capacity decoded to zero blocks
/// is never published; a user area with no readable partition table
/// just keeps its bare whole-disk entry, so the scan is best-effort
/// and its error is dropped, exactly as at the other call sites.
/// The hardware partitions register as children of `emmc0`, so the
/// disk policy treats them as one medium.
pub(crate) fn publish_emmc(card: &EmmcCard) {
    use core::fmt::Write as _;
    if card.capacity_blocks == 0 {
        return;
    }
    let user = Arc::new(EmmcBlockDevice {
        part: EmmcPartition::User,
        capacity_blocks: card.capacity_blocks,
        sector_mode: card.sector_mode,
    });
    narf_block::registry::register_block_device("emmc0", user.clone());
    let _ = narf_block::partition::scan_and_register_partitions(user, "emmc0");

    // Boot partitions (BOOT_SIZE_MULT × 128 KiB each).
    if card.boot_blocks() > 0 {
        for part in [EmmcPartition::Boot0, EmmcPartition::Boot1] {
            let dev = Arc::new(EmmcBlockDevice {
                part,
                capacity_blocks: card.boot_blocks(),
                sector_mode: card.sector_mode,
            });
            narf_block::registry::register_partition_device(part.name(), "emmc0", dev, None);
        }
    }

    // General-purpose partitions — only when the high-capacity
    // erase definition is selected (ERASE_GROUP_DEF = 1), which is
    // what the §7.4.89 size formula is stated in terms of.
    if card.ext_csd.erase_group_def != 0 {
        for i in 0..4usize {
            let blocks = card.gp_blocks(i);
            if blocks > 0 {
                let part = EmmcPartition::Gp(i as u8);
                let dev = Arc::new(EmmcBlockDevice {
                    part,
                    capacity_blocks: blocks,
                    sector_mode: card.sector_mode,
                });
                narf_block::registry::register_partition_device(part.name(), "emmc0", dev, None);
            }
        }
    }

    // RPMB is decoded and sized but not published: it admits only
    // authenticated frames (see the module docs). Surface its size
    // so a missing `emmc0rpmb` is a visible decision, not a silent
    // gap.
    let _ = writeln!(
        narf_console::Writer,
        "  emmc: emmc0 {} blocks (sector mode: {}), boot 2x{} blocks, gp [{}, {}, {}, {}] blocks, rpmb {} blocks (auth-only, not published)",
        card.capacity_blocks,
        card.sector_mode,
        card.boot_blocks(),
        card.gp_blocks(0),
        card.gp_blocks(1),
        card.gp_blocks(2),
        card.gp_blocks(3),
        card.rpmb_blocks(),
    );
}

struct EmmcBlockDevice {
    part: EmmcPartition,
    capacity_blocks: u64,
    sector_mode: bool,
}

impl narf_block::registry::BlockDeviceSync for EmmcBlockDevice {
    // NOTE (#841): flush/capabilities/write_fua are intentionally
    // the trait defaults. The eMMC write cache (CACHE_CTRL) is off
    // after reset unless a driver enables it, and this driver never
    // does — so a write is durable once the card leaves programming
    // state, and the no-op flush is the write-through treatment,
    // not a vacuous advertisement — exactly as for the SD path.
    fn lba_size(&self) -> u32 {
        512
    }

    fn capacity(&self) -> u64 {
        self.capacity_blocks
    }

    fn read(
        &self,
        lba: u64,
        n_blocks: u16,
        out: &mut [u8],
    ) -> Result<(), narf_block::registry::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if out.len() < needed {
            return Err(narf_block::registry::BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(narf_block::registry::BlockIoError::OutOfRange);
        }

        with_controller(|ctrl| {
            ctrl.ensure_partition_access(self.part.access_value())
                .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
            for i in 0..n_blocks as u64 {
                let arg = if self.sector_mode {
                    (lba + i) as u32
                } else {
                    ((lba + i) as u32).saturating_mul(512)
                };
                let offset = i as usize * 512;
                let mut buf = [0u8; 512];
                ctrl.read_pio_block(17, arg, &mut buf)
                    .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
                out[offset..offset + 512].copy_from_slice(&buf);
            }
            Ok(())
        })
        .unwrap_or(Err(narf_block::registry::BlockIoError::DriverError))
    }

    fn write(
        &self,
        lba: u64,
        n_blocks: u16,
        data: &[u8],
    ) -> Result<(), narf_block::registry::BlockIoError> {
        if n_blocks == 0 {
            return Ok(());
        }
        let needed = n_blocks as usize * 512;
        if data.len() < needed {
            return Err(narf_block::registry::BlockIoError::BufferTooSmall);
        }
        let max_lba = self.capacity_blocks.saturating_sub(n_blocks as u64);
        if lba > max_lba {
            return Err(narf_block::registry::BlockIoError::OutOfRange);
        }

        with_controller(|ctrl| {
            ctrl.ensure_partition_access(self.part.access_value())
                .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
            for i in 0..n_blocks as u64 {
                let arg = if self.sector_mode {
                    (lba + i) as u32
                } else {
                    ((lba + i) as u32).saturating_mul(512)
                };
                let offset = i as usize * 512;
                let mut buf = [0u8; 512];
                buf.copy_from_slice(&data[offset..offset + 512]);
                ctrl.write_pio_block(24, arg, &buf)
                    .map_err(|_| narf_block::registry::BlockIoError::DriverError)?;
            }
            Ok(())
        })
        .unwrap_or(Err(narf_block::registry::BlockIoError::DriverError))
    }
}
