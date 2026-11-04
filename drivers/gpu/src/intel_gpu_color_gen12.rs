//! MIT Linux b90c984d intel_color.c: icl_gamma_mode, glk_load_degamma_lut,
//! icl_program_gamma_{superfine,multi}_segment, icl_read_lut_multi_segment.
//! Display12 fine/coarse data cannot be reliably read back. Its complete
//! target stream is canonical software state; only visible bypass is restored.
use super::*;
pub(crate) const DISPLAY12_LUT_SIZE: usize = 262145;
pub(crate) const DISPLAY12_WORDS: usize = 18 + 1024 + 3;
pub(crate) const MAX_COLOR_BLOB: usize = DISPLAY12_LUT_SIZE * 8;
pub(crate) const MAX_COLOR_BLOB_TOTAL: usize = 16 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Mtl,
    Display12,
    Display13,
}
impl Profile {
    pub(crate) fn gen12(family: crate::intel_gpu_gt::Gen12Platform) -> Self {
        match family {
            crate::intel_gpu_gt::Gen12Platform::TigerLake
            | crate::intel_gpu_gt::Gen12Platform::AlderLakeS => Self::Display12,
            crate::intel_gpu_gt::Gen12Platform::AlderLakeP
            | crate::intel_gpu_gt::Gen12Platform::AlderLakeN => Self::Display13,
        }
    }
    pub(crate) fn sizes(self) -> (usize, usize) {
        if self == Self::Display12 {
            (DISPLAY12_LUT_SIZE, 33)
        } else {
            (LUT_SIZE, DEGAMMA_SIZE)
        }
    }
    pub(crate) fn pre_words(self) -> usize {
        self.sizes().1 + 2
    }
}
fn rgb(bytes: &[u8], i: usize) -> [u16; 3] {
    let b = &bytes[i * 8..i * 8 + 6];
    core::array::from_fn(|c| u16::from_le_bytes([b[c * 2], b[c * 2 + 1]]))
}
pub(super) fn decode_display12(bytes: &[u8]) -> Result<Arc<Lut>, FsError> {
    if bytes.len() != MAX_COLOR_BLOB {
        return Err(FsError::InvalidData);
    }
    // Every ABI entry is checked, including entries not sampled by hardware.
    // ICL_COLORS requests monotonic RGB, without equal-channel gamma policy.
    let mut previous = [0; 3];
    for i in 0..DISPLAY12_LUT_SIZE {
        let c = rgb(bytes, i);
        if (0..3).any(|k| c[k] < previous[k]) {
            return Err(FsError::InvalidData);
        }
        previous = c;
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(DISPLAY12_WORDS)
        .map_err(|_| FsError::OutOfMemory)?;
    let mut push = |i| {
        let c = rgb(bytes, i);
        entries.push(
            u32::from(c[0] & 63) << 24 | u32::from(c[1] & 63) << 14 | u32::from(c[2] & 63) << 4,
        );
        entries
            .push(u32::from(c[0] >> 6) << 20 | u32::from(c[1] >> 6) << 10 | u32::from(c[2] >> 6));
    };
    for i in 0..9 {
        push(i);
    }
    for i in 1..257 {
        push(i * 8);
    }
    for i in 0..256 {
        push(i * 1024);
    }
    entries.extend(rgb(bytes, 262144).map(u32::from));
    Ok(Arc::new(Lut { entries }))
}
pub(super) fn matches_display12(io: &impl MmioWindow, entries: &[u32]) -> bool {
    // Do not read PAL_PREC_DATA fine/coarse: source explicitly says readout
    // is incorrect. Stream completion/later frame proves those writes.
    let mut valid = true;
    io.write32(0x4a408, 0);
    io.write32(0x4a408, 1 << 15);
    for &word in &entries[..18] {
        valid &= io.read32(0x4a40c) == word;
    }
    io.write32(0x4a408, 0);
    valid
        && [0x4a410, 0x4a414, 0x4a418]
            .into_iter()
            .zip(&entries[1042..])
            .all(|(r, v)| io.read32(r) == *v)
        && MAX_REGS.into_iter().all(|r| io.read32(r) == 1 << 16)
}
