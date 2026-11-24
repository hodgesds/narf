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
pub(crate) use model::{
    execute_fixture, fixture_add_window, fixture_copies, fixture_finish, fixture_metadata,
    fixture_page_shifts, fixture_pointer, fixture_seed, fixture_state,
};

const CODE: u64 = 0x1234_0000_0000;
const ZERO: u64 = 0x1234_0010_0000;
const TARGET: u64 = 0x2345_0000_0000;
const CHUNK: u64 = 64 * 1024 * 1024;

/// Build the trusted flat-CCS clear batch for a VRAM object. This performs
/// the CCS-clear claim itself (`begin_ccs_clear`, ccs 1 -> 2): callers must
/// not claim it first, or the second claim fails with `InvalidData`.
pub(crate) fn prepare_vram_clear(
    platform: GtPlatform,
    object: Arc<GemObject>,
) -> Result<ResidentBatch, FsError> {
    if !platform.is_dg2() {
        return Err(FsError::Unsupported);
    }
    object.begin_ccs_clear()?;
    let size = object.size();
    if size == 0 || size & 65535 != 0 || size > 256 * 1024 * 1024 {
        return Err(FsError::InvalidData);
    }
    let gem = GemState::new();
    let code = gem.object(gem.create(PAGE, |_, _| Ok(()))?)?;
    // The common trusted copy emitter initializes data and the CCS emitter
    // initializes metadata from the same immutable private zero storage.
    let zero = gem.object(gem.create(copy::COPY_CHUNK, |_, _| Ok(()))?)?;
    let mut words = Vec::new();
    for offset in (0..size).step_by(copy::COPY_CHUNK as usize) {
        copy::emit_data_copy(
            &mut words,
            platform,
            ZERO,
            TARGET + offset,
            (size - offset).min(copy::COPY_CHUNK),
        );
    }
    for offset in (0..size).step_by(CHUNK as usize) {
        let bytes = (size - offset).min(CHUNK);
        copy::emit_ccs_copy(&mut words, ZERO, true, TARGET + offset, bytes);
    }
    // Publish auxiliary-surface writes before the ordinary copy-ring
    // breadcrumb. Linux xe_migrate_clear requests MI_FLUSH_DW_CCS for this.
    copy::finish(&mut words, true);
    for (i, word) in words.iter().enumerate() {
        code.write(i as u64 * 4, &word.to_le_bytes())?;
    }
    ResidentBatch::from_vm(
        platform,
        &[
            VmMapping {
                dumpable: false,
                object: Some(code),
                va: CODE,
                offset: 0,
                length: PAGE,
                writable: false,
                pat: 0,
            },
            VmMapping {
                dumpable: false,
                object: Some(zero),
                va: ZERO,
                offset: 0,
                length: copy::COPY_CHUNK,
                writable: false,
                pat: 0,
            },
            VmMapping {
                dumpable: false,
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

/// Xe2+ `XY_CTRL_SURF_COPY_BLT` moves at most 1024 pages (4 MiB) of main
/// surface per command; Linux clears integrated flat CCS in passes of that
/// size (`MAX_CCS_LIMITED_TRANSFER`).
const SYSTEM_CCS_CHUNK: u64 = 4 * 1024 * 1024;
/// Integrated Xe2 keeps one CCS byte per 512 bytes (`NUM_BYTES_PER_CCS_BYTE`).
const SYSTEM_CCS_ZERO: u64 = SYSTEM_CCS_CHUNK / 512;
/// `xe->pat.idx[XE_CACHE_NONE_COMPRESSION]`: indirect CCS access needs a
/// compression-enabled uncached PTE.
const PAT_NONE_COMPRESSION: u8 = 12;
/// `xe->pat.idx[XE_CACHE_WB]` on Xe2/Xe3.
const PAT_WB: u8 = 2;
/// Xe2 uncached MOCS (`gt->mocs.uc_index`) in the address dwords.
const XE2_UC_MOCS: u32 = 3 << 28;

/// The clear batch for `size` bytes at `TARGET`: one `XY_CTRL_SURF_COPY_BLT`
/// per 4 MiB (direct zero source, bit 21; indirect destination, bit 20 clear;
/// `XE2_CCS_SIZE_MASK` bits 18:9 = pages - 1; UC MOCS in both address
/// dwords), then `MI_FLUSH_DW` with the CCS flush and BB_END.
pub(crate) fn system_ccs_clear_words(size: u64) -> Vec<u32> {
    let mut words = Vec::new();
    for offset in (0..size).step_by(SYSTEM_CCS_CHUNK as usize) {
        let pages = ((size - offset).min(SYSTEM_CCS_CHUNK) / PAGE) as u32;
        let target = TARGET + offset;
        words.extend_from_slice(&[
            0x5200_0003 | 1 << 21 | (pages - 1) << 9,
            ZERO as u32,
            (ZERO >> 32) as u32 | XE2_UC_MOCS,
            target as u32,
            (target >> 32) as u32 | XE2_UC_MOCS,
        ]);
    }
    copy::finish(&mut words, true);
    words
}

/// The integrated Xe2/Xe3 flat-CCS clear Linux runs for every buffer it
/// populates (`xe_bo_move` with `XE_MIGRATE_CLEAR_FLAG_CCS_DATA`,
/// `xe_migrate_clear` with `clear_only_system_ccs`): the data is already
/// zero, so only the compression metadata is written, from a private zero
/// source read directly into the object's CCS addressed indirectly through
/// a PAT 12 mapping, then `MI_FLUSH_DW` with the CCS flush. Zero metadata
/// means uncompressed, so data written through uncompressed PATs survives.
pub(crate) fn prepare_system_ccs_clear(
    platform: GtPlatform,
    object: Arc<GemObject>,
) -> Result<ResidentBatch, FsError> {
    if !platform.is_headless_integrated() || object.is_vram() || object.is_userptr() {
        return Err(FsError::Unsupported);
    }
    let size = object.size();
    if size == 0 || size & 4095 != 0 {
        return Err(FsError::InvalidData);
    }
    let words = system_ccs_clear_words(size);
    let code_bytes = (words.len() as u64 * 4).next_multiple_of(PAGE);
    let code = GemObject::private_system(code_bytes)?;
    let zero = GemObject::private_system(SYSTEM_CCS_ZERO)?;
    for (index, word) in words.iter().enumerate() {
        code.write(index as u64 * 4, &word.to_le_bytes())?;
    }
    let mut batch = ResidentBatch::from_vm(
        platform,
        &[
            VmMapping {
                object: Some(code),
                va: CODE,
                offset: 0,
                length: code_bytes,
                writable: false,
                pat: PAT_WB,
                dumpable: false,
            },
            VmMapping {
                object: Some(zero),
                va: ZERO,
                offset: 0,
                length: SYSTEM_CCS_ZERO,
                writable: false,
                pat: PAT_WB,
                dumpable: false,
            },
            VmMapping {
                object: Some(object),
                va: TARGET,
                offset: 0,
                length: size,
                writable: true,
                pat: PAT_NONE_COMPRESSION,
                dumpable: false,
            },
        ],
        Some(CODE),
        false,
        None,
    )?;
    // Order after every job already writing the object.
    batch.implicit_sync = true;
    Ok(batch)
}

/// BMG ordinary PAT2 local data is never interpreted through compressed PATs.
/// Fresh GPU-only ranges are initialized through the existing source MEM_COPY
/// codec, from private WB zero storage that can never be mmaped or exported.
pub(crate) fn prepare_smallbar_clear(object: Arc<GemObject>) -> Result<ResidentBatch, FsError> {
    object.begin_gpu_vram_clear()?;
    let size = object.size();
    if size == 0 || size & 4095 != 0 || size > 128 * 1024 * 1024 {
        return Err(FsError::InvalidData);
    }
    let code = GemObject::private_system(PAGE)?;
    let zero = GemObject::private_system(copy::COPY_CHUNK)?;
    let mut words = Vec::new();
    for offset in (0..size).step_by(copy::COPY_CHUNK as usize) {
        copy::emit_data_copy(
            &mut words,
            GtPlatform::Battlemage,
            ZERO,
            TARGET + offset,
            (size - offset).min(copy::COPY_CHUNK),
        );
    }
    copy::finish(&mut words, false);
    if words.len() > 1024 {
        return Err(FsError::InvalidData);
    }
    for (index, word) in words.iter().enumerate() {
        code.write(index as u64 * 4, &word.to_le_bytes())?;
    }
    let mut batch = ResidentBatch::from_vm(
        GtPlatform::Battlemage,
        &[
            VmMapping {
                object: Some(code),
                va: CODE,
                offset: 0,
                length: PAGE,
                writable: false,
                pat: 2,
                dumpable: false,
            },
            VmMapping {
                object: Some(zero),
                va: ZERO,
                offset: 0,
                length: copy::COPY_CHUNK,
                writable: false,
                pat: 2,
                dumpable: false,
            },
            VmMapping {
                object: Some(object),
                va: TARGET,
                offset: 0,
                length: size,
                writable: true,
                pat: 2,
                dumpable: false,
            },
        ],
        Some(CODE),
        false,
        None,
    )?;
    batch.implicit_sync = true;
    Ok(batch)
}
