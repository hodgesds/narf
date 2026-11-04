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
    fixture_pointer, fixture_seed, fixture_state,
};

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
    // The common trusted copy emitter initializes data and the CCS emitter
    // initializes metadata from the same immutable private zero storage.
    let zero = gem.object(gem.create(copy::COPY_CHUNK, |_, _| Ok(()))?)?;
    let mut words = Vec::new();
    for offset in (0..size).step_by(copy::COPY_CHUNK as usize) {
        copy::emit_data_copy(
            &mut words,
            GtPlatform::Alchemist,
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
        GtPlatform::Alchemist,
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
