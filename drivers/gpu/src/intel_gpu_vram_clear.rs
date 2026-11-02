//! Trusted Xe-HPG flat-CCS initialization, before GEM publication. MIT Linux
//! b90c984d xe_migrate.c::{emit_copy_ccs,xe_migrate_clear}, instructions/
//! xe_gpu_commands.h and xe_mi_commands.h. CPU zeroing the WC data does not
//! initialize surface-state compression metadata; every allocation/reuse
//! therefore runs a data clear and direct-zero -> indirect-VRAM CCS copy on
//! BCS0. Software reservation performs no BAR I/O before GT wake ownership.
use super::*;

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_vram_clear_model.rs"]
mod model;
#[cfg(feature = "kernel-test")]
pub(crate) use model::{execute_fixture, fixture_finish, fixture_seed, fixture_state};

const CODE: u64 = 0x1234_0000_0000;
const ZERO: u64 = 0x1234_0010_0000;
const TARGET: u64 = 0x2345_0000_0000;
const CHUNK: u64 = 64 * 1024 * 1024;

pub(crate) fn prepare_vram_clear(object: Arc<GemObject>) -> Result<ResidentBatch, FsError> {
    object.begin_ccs_clear()?;
    let size = object.size();
    if size == 0 || size & 65535 != 0 || size > 256 * 1024 * 1024 {
        return Err(FsError::InvalidData);
    }
    let gem = GemState::new();
    let code = gem.object(gem.create(PAGE, |_, _| Ok(()))?)?;
    // One command copies at most 1024 blocks of 256 CCS bytes. All commands
    // reuse this immutable zero source; no user namespace retains it.
    let zero = gem.object(gem.create(CHUNK / 256, |_, _| Ok(()))?)?;
    let mut words = Vec::new();
    for offset in (0..size).step_by(CHUNK as usize) {
        let bytes = (size - offset).min(CHUNK);
        let blocks = bytes / 65536;
        // xe_migrate.c::emit_clear_main_copy: Xe-HPG's sixteen-DW linear
        // XY_FAST_COLOR_BLT, 32-bit zero color, UC MOCS1, 4096-byte pitch,
        // local-memory destination. No CPU can reach this private target.
        words.extend_from_slice(&[
            0x5110_000e,
            0x0040_0fff,
            0,
            ((bytes / 4096) as u32) << 16 | 1024,
            (TARGET + offset) as u32,
            ((TARGET + offset) >> 32) as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        // XY_CTRL_SURF_COPY_BLT, direct source bit21, indirect destination;
        // CCS_SIZE[17:8] counts 256-byte metadata blocks minus one. UC MOCS1
        // (xe_mocs.c DG2) is in bits31:26 of both upper address words.
        words.extend_from_slice(&[
            0x5200_0003 | (1 << 21) | ((blocks as u32 - 1) << 8),
            ZERO as u32,
            (ZERO >> 32) as u32 | (1 << 26),
            (TARGET + offset) as u32,
            ((TARGET + offset) >> 32) as u32 | (1 << 26),
        ]);
    }
    // Publish auxiliary-surface writes before the ordinary copy-ring
    // breadcrumb. Linux xe_migrate_clear requests MI_FLUSH_DW_CCS for this.
    words.extend_from_slice(&[0x1301_0003, 0, 0, 0, 0, 0x0500_0000]);
    if words.len() % 2 != 0 {
        words.push(0);
    }
    for (i, word) in words.iter().enumerate() {
        code.write(i as u64 * 4, &word.to_le_bytes())?;
    }
    ResidentBatch::from_vm(
        GtPlatform::Alchemist,
        &[
            VmMapping {
                object: Some(code),
                va: CODE,
                offset: 0,
                length: PAGE,
                writable: false,
                pat: 0,
            },
            VmMapping {
                object: Some(zero),
                va: ZERO,
                offset: 0,
                length: CHUNK / 256,
                writable: false,
                pat: 0,
            },
            VmMapping {
                object: Some(object),
                va: TARGET,
                offset: 0,
                length: size,
                writable: true,
                pat: 0,
            },
        ],
        Some(CODE),
        false,
        None,
    )
}
