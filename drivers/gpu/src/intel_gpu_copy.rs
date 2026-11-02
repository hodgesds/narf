//! Retained kernel copy jobs. MIT Linux b90c984d xe_migrate.c::emit_copy,
//! emit_xy_fast_copy, emit_mem_copy, xe_migrate_ccs_copy and xe_gpu_commands.h.
//! This owns a private batch/PPGTT graph; it does not relocate a live binding.
use super::*;

const CODE: u64 = 0x1234_0000_0000;
const SOURCE: u64 = 0x2345_0000_0000;
const DESTINATION: u64 = 0x3456_0000_0000;
const CCS_ZERO: u64 = 0x4567_0000_0000;
pub(super) const COPY_CHUNK: u64 = 8 * 1024 * 1024;
const MAX_COPY: u64 = 128 * 1024 * 1024;

/// An immutable copy of owned BO ranges. Offsets/length are page aligned;
/// DG2 local-memory ranges additionally use complete 64 KiB groups.
/// Kernel/dma-buf copies are excluded by the returned terminal reservation.
/// The caller must separately exclude uncontrolled CPU aliases and must not
/// publish a relocated binding before successful terminal completion.
#[derive(Clone, Debug)]
pub struct CopyRequest {
    source: Arc<GemObject>,
    source_offset: u64,
    destination: Arc<GemObject>,
    destination_offset: u64,
    length: u64,
}

impl CopyRequest {
    pub fn new(
        source: Arc<GemObject>,
        source_offset: u64,
        destination: Arc<GemObject>,
        destination_offset: u64,
        length: u64,
    ) -> Result<Self, FsError> {
        if length == 0
            || length > MAX_COPY
            || (source_offset | destination_offset | length) & (PAGE - 1) != 0
        {
            return Err(FsError::InvalidData);
        }
        for (object, offset) in [(&source, source_offset), (&destination, destination_offset)] {
            // USERPTR and WC-system copies need an independently qualified
            // cache/invalidator contract; ordinary owned WB and LMEM suffice.
            if object.is_userptr() || object.is_wc() {
                return Err(FsError::Unsupported);
            }
            object.range(offset, length as usize)?;
            if object.is_vram() && (offset | length) & (object.vram_page_size() - 1) != 0 {
                return Err(FsError::InvalidData);
            }
        }
        if Arc::ptr_eq(&source, &destination)
            && source_offset < destination_offset + length
            && destination_offset < source_offset + length
        {
            return Err(FsError::InvalidData);
        }
        Ok(Self {
            source,
            source_offset,
            destination,
            destination_offset,
            length,
        })
    }

    pub(crate) fn validate_pool(
        &self,
        pool: Option<&Arc<crate::intel_gpu_vram::Vram>>,
    ) -> Result<(), FsError> {
        for object in [&self.source, &self.destination] {
            if object.is_vram() && pool.is_none_or(|pool| !object.in_vram_pool(pool)) {
                return Err(FsError::InvalidData);
            }
        }
        Ok(())
    }

    pub(crate) fn uses_vram(&self) -> bool {
        self.source.is_vram() || self.destination.is_vram()
    }

    pub(crate) fn prepare(self, platform: GtPlatform) -> Result<ResidentBatch, FsError> {
        if !matches!(platform, GtPlatform::Alchemist | GtPlatform::Battlemage) {
            return Err(FsError::Unsupported);
        }
        // DG2's compressed data and auxiliary representation must travel
        // together. An ordinary system destination cannot retain that CCS.
        if platform == GtPlatform::Alchemist && self.source.is_vram() && !self.destination.is_vram()
        {
            return Err(FsError::Unsupported);
        }
        let gem = GemState::new();
        let code = gem.object(gem.create(PAGE, |_, _| Ok(()))?)?;
        let pat = if platform == GtPlatform::Battlemage {
            2
        } else {
            0
        };
        let mut mappings = vec![
            mapping(code.clone(), CODE, 0, PAGE, false, pat),
            mapping(
                self.source.clone(),
                SOURCE,
                self.source_offset,
                self.length,
                false,
                pat,
            ),
            mapping(
                self.destination.clone(),
                DESTINATION,
                self.destination_offset,
                self.length,
                true,
                pat,
            ),
        ];
        let ccs = platform == GtPlatform::Alchemist && self.destination.is_vram();
        if ccs && !self.source.is_vram() {
            let zero = gem.object(gem.create(COPY_CHUNK / 256, |_, _| Ok(()))?)?;
            mappings.push(mapping(zero, CCS_ZERO, 0, COPY_CHUNK / 256, false, 0));
        }
        let mut words = Vec::new();
        for offset in (0..self.length).step_by(COPY_CHUNK as usize) {
            let length = (self.length - offset).min(COPY_CHUNK);
            emit_data_copy(
                &mut words,
                platform,
                SOURCE + offset,
                DESTINATION + offset,
                length,
            );
            if ccs {
                emit_ccs_copy(
                    &mut words,
                    if self.source.is_vram() {
                        SOURCE + offset
                    } else {
                        CCS_ZERO
                    },
                    !self.source.is_vram(),
                    DESTINATION + offset,
                    length,
                );
            }
        }
        finish(&mut words, ccs);
        for (i, word) in words.iter().enumerate() {
            code.write(i as u64 * 4, &word.to_le_bytes())?;
        }
        let mut batch = ResidentBatch::from_vm(platform, &mappings, Some(CODE), false, None)?;
        // Kernel migration/copy callers do not carry Xe explicit dependencies.
        // The scheduler atomically rejects a conflicting source/destination.
        batch.implicit_sync = true;
        Ok(batch)
    }
}

fn mapping(
    object: Arc<GemObject>,
    va: u64,
    offset: u64,
    length: u64,
    writable: bool,
    pat: u8,
) -> VmMapping {
    VmMapping {
        object: Some(object),
        va,
        offset,
        length,
        writable,
        pat,
        dumpable: false,
    }
}

/// Both source formats use linear 4096-byte rows. Eight MiB chunks fit the
/// signed XY coordinates and Xe2's 16-bit count of 256-byte page units.
pub(super) fn emit_data_copy(
    words: &mut Vec<u32>,
    platform: GtPlatform,
    source: u64,
    destination: u64,
    length: u64,
) {
    debug_assert!(length != 0 && length <= COPY_CHUNK && length % PAGE == 0);
    if platform == GtPlatform::Battlemage {
        words.extend_from_slice(&[
            0x5688_0008,
            (length / 256 - 1) as u32,
            (length / PAGE - 1) as u32,
            4095,
            4095,
            source as u32,
            (source >> 32) as u32,
            destination as u32,
            (destination >> 32) as u32,
            0x3000_0018, // UC MOCS3 for source and destination.
        ]);
    } else {
        words.extend_from_slice(&[
            0x5080_0008,
            0xc300_1000, // 32-bit linear copy, Xe-HPG Tile4 selectors.
            0,
            ((length / PAGE) as u32) << 16 | 1024,
            destination as u32,
            (destination >> 32) as u32,
            0,
            4096,
            source as u32,
            (source >> 32) as u32,
        ]);
    }
}

pub(super) fn emit_ccs_copy(
    words: &mut Vec<u32>,
    source: u64,
    direct: bool,
    destination: u64,
    length: u64,
) {
    debug_assert!(length != 0 && length <= 64 * 1024 * 1024 && length & 65535 == 0);
    words.extend_from_slice(&[
        0x5200_0003 | (u32::from(direct) << 21) | ((length / 65536 - 1) as u32) << 8,
        source as u32,
        (source >> 32) as u32 | (1 << 26),
        destination as u32,
        (destination >> 32) as u32 | (1 << 26),
    ]);
}

pub(super) fn finish(words: &mut Vec<u32>, ccs: bool) {
    if ccs {
        words.extend_from_slice(&[0x1301_0003, 0, 0, 0, 0]);
    }
    words.push(0x0500_0000);
    if words.len() % 2 != 0 {
        words.push(0);
    }
}
