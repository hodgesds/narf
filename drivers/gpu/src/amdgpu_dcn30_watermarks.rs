//! The PMFW watermark range table for DCN 3.0 (Navi22). Linux builds it in
//! `dcn3_fpu_build_wm_range_table` (dcn30_fpu.c) and hands it to PMFW from
//! `dcn30_init_hw` through `dcn3_notify_wm_ranges` (dcn30_clk_mgr.c):
//! `WatermarksExternal_t` (smu11_driver_if_sienna_cichlid.h) is zeroed, the
//! valid DCEFCLK rows are filled, and the DAL mailbox sends
//! `SetDalDramAddrHigh/Low` then `TransferTableDram2Smu(TABLE_WATERMARKS)`.
//!
//! On this ASIC Linux does not use the swsmu `sienna_cichlid_set_watermarks_table`
//! / `smu_cmn_write_watermarks_table` path: `amdgpu_dm_smu_write_watermarks_table`
//! returns early for every DCN other than 2.0.x. Both paths deliver the same
//! `Watermarks_t` to PMFW; this module mirrors the one Linux runs for DCN 3.0.
//!
//! The table only tells PMFW which HUBBUB watermark set (A-D) fits each
//! DCFCLK/UCLK range; it does not program HUBBUB. Uploading it is the PMFW
//! half of `DisplayAdmission::watermarks`, run only under the explicit
//! `amdgpu.navi22_pg=wm` opt-in.
use crate::amdgpu_dcn_clk::Error;
use core::future::Future;

/// smu11_driver_if_sienna_cichlid.h `TABLE_WATERMARKS`.
pub const TABLE_WATERMARKS: u32 = 1;
/// dalsmc.h.
pub(crate) const SET_DAL_DRAM_ADDR_HIGH: u32 = 0x5;
pub(crate) const SET_DAL_DRAM_ADDR_LOW: u32 = 0x6;
pub(crate) const TRANSFER_TABLE_DRAM2SMU: u32 = 0x8;
/// `NUM_WM_RANGES` and `WM_COUNT` (WM_SOCCLK, WM_DCEFCLK).
const RANGES: usize = 4;
const WM_DCEFCLK: usize = 1;
/// `WatermarkRowGeneric_t`: four u16 clocks, WmSetting, Flags, Padding[2].
const ROW_BYTES: usize = 12;
/// `sizeof(WatermarksExternal_t)`: `Watermarks_t` (2 x 4 rows) plus
/// `MmHubPadding[8]`.
pub const BYTES: usize = 2 * RANGES * ROW_BYTES + 8 * 4;

/// `WATERMARKS_FLAGS_e`, written to the row's Flags (`pmfw_breakdown.wm_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    ClockRange = 0,
    DummyPstate = 1,
    Mall = 2,
}
/// One `wm_table.nv_entries[i]` PMFW breakdown (MHz).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub min_dcfclk: u16,
    pub max_dcfclk: u16,
    pub min_uclk: u16,
    pub max_uclk: u16,
    pub kind: Kind,
}
/// `dcn3_fpu_build_wm_range_table`: set A (normal), B unused (commented out
/// in Linux), C (dummy p-state), D (MALL); each covers every DCFCLK and UCLK
/// from the lowest memory DPM level (`clk_table.entries[0].memclk_mhz`).
pub fn navi22_ranges(min_uclk_mhz: u16) -> [Option<Range>; RANGES] {
    let range = |kind| {
        Some(Range {
            min_dcfclk: 0,
            max_dcfclk: 0xffff,
            min_uclk: min_uclk_mhz,
            max_uclk: 0xffff,
            kind,
        })
    };
    [
        range(Kind::ClockRange),
        None,
        range(Kind::DummyPstate),
        range(Kind::Mall),
    ]
}
/// `dcn3_notify_wm_ranges`' table: zeroed, then one DCEFCLK row per valid
/// set with `WmSetting = i`. SOCCLK rows and padding stay zero.
pub fn encode(ranges: &[Option<Range>; RANGES]) -> [u8; BYTES] {
    let mut table = [0u8; BYTES];
    for (i, range) in ranges.iter().enumerate() {
        let Some(r) = range else { continue };
        let row = &mut table[(WM_DCEFCLK * RANGES + i) * ROW_BYTES..][..ROW_BYTES];
        for (at, value) in [r.min_dcfclk, r.max_dcfclk, r.min_uclk, r.max_uclk]
            .into_iter()
            .enumerate()
        {
            row[at * 2..at * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        row[8] = i as u8;
        row[9] = r.kind as u8;
    }
    table
}

/// The DAL (DALSMC) mailbox; `ClockManager` owns it.
pub(crate) trait DalMailbox {
    fn dal(&mut self, message: u32, argument: u32) -> impl Future<Output = Result<u32, Error>>;
}
/// The mailbox part of `dcn3_notify_wm_ranges`, after the table at the GPU
/// address `address` was written and HDP-flushed. Linux ignores each reply;
/// here a rejection stops the sequence and is returned.
pub(crate) async fn notify(dal: &mut impl DalMailbox, address: u64) -> Result<(), Error> {
    if address == 0 || address % 4 != 0 {
        return Err(Error::Invalid);
    }
    dal.dal(SET_DAL_DRAM_ADDR_HIGH, (address >> 32) as u32)
        .await?;
    dal.dal(SET_DAL_DRAM_ADDR_LOW, address as u32).await?;
    dal.dal(TRANSFER_TABLE_DRAM2SMU, TABLE_WATERMARKS).await?;
    Ok(())
}

/// CPU write of the table into a retained VRAM buffer, then the HDP flush
/// (`amdgpu_hdp_flush`) through the remap PSP startup installed, as the
/// SMU owner does for its driver table. Linux uses a GART buffer
/// (`DC_MEM_ALLOC_TYPE_GART`), which needs no HDP flush.
///
/// # Safety
/// `memory` is this GPU's retained pool reservation (at least [`BYTES`]),
/// `regs` its BAR5 mapping and `nbio` the NBIF base-2 bank bounded through
/// 0x12d; the caller owns the GPU exclusively.
pub(crate) unsafe fn stage(
    memory: &crate::amdgpu_vram::Reservation,
    regs: narf_bus::MmioRegion,
    nbio: u64,
    table: &[u8; BYTES],
) -> Result<(), Error> {
    if memory.size() < BYTES as u64 || regs.len < 0x7f004 {
        return Err(Error::Invalid);
    }
    // SAFETY: nbio bounded through REMAP_HDP_MEM_FLUSH_CNTL by the caller.
    if unsafe { regs.read32(nbio + 0x12d * 4) } != 0x7f000 {
        return Err(Error::Invalid);
    }
    let mapping = memory.mapping();
    for (index, word) in table.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        // SAFETY: bounded by the reservation size checked above.
        unsafe { mapping.write32(index as u64 * 4, word) };
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: verified remap; the MEMSIZE read drains the posted flush.
    unsafe {
        regs.write32(0x7f000, 0);
        regs.read32(nbio + 0xc3 * 4);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn dcn30_watermark_table_matches_linux() -> TestResult {
        let table = encode(&navi22_ranges(96));
        if BYTES != 128 {
            return TestResult::Fail("sizeof(WatermarksExternal_t)");
        }
        // WM_SOCCLK rows, set B and MmHubPadding stay zero.
        if table[..48].iter().any(|b| *b != 0)
            || table[60..72].iter().any(|b| *b != 0)
            || table[96..].iter().any(|b| *b != 0)
        {
            return TestResult::Fail("unused rows not zero");
        }
        let row = |i: usize| &table[48 + i * 12..60 + i * 12];
        let expect =
            |setting: u8, flags: u8| [0, 0, 0xff, 0xff, 96, 0, 0xff, 0xff, setting, flags, 0, 0];
        if row(0) != expect(0, 0) || row(2) != expect(2, 1) || row(3) != expect(3, 2) {
            return TestResult::Fail("DCEFCLK rows");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-watermarks",
        dcn30_watermark_table_matches_linux
    );

    struct Dal {
        sent: Vec<(u32, u32)>,
        reject: Option<u32>,
    }
    impl DalMailbox for Dal {
        async fn dal(&mut self, message: u32, argument: u32) -> Result<u32, Error> {
            self.sent.push((message, argument));
            if self.reject == Some(message) {
                return Err(Error::Rejected(0xff));
            }
            Ok(0)
        }
    }
    fn dcn30_watermark_upload_uses_dal_messages() -> TestResult {
        let mut dal = Dal {
            sent: Vec::new(),
            reject: None,
        };
        let address = 0x82_fe00_1000;
        narf_scheduler::block_on_spin(notify(&mut dal, address)).unwrap();
        if dal.sent != [(0x5, 0x82), (0x6, 0xfe00_1000), (0x8, 1)] {
            return TestResult::Fail("dcn3_notify_wm_ranges messages");
        }
        let mut dal = Dal {
            sent: Vec::new(),
            reject: Some(0x6),
        };
        if narf_scheduler::block_on_spin(notify(&mut dal, address)).is_ok()
            || dal.sent.len() != 2
            || narf_scheduler::block_on_spin(notify(&mut dal, 0)) != Err(Error::Invalid)
            || dal.sent.len() != 2
        {
            return TestResult::Fail("rejection/invalid address");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-watermarks",
        dcn30_watermark_upload_uses_dal_messages
    );
}
