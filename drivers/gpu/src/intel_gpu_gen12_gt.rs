//! Pre-GMD Xe-LP graphics owner. MIT Linux b90c984d xe_{pci,pat,mocs,wa,
//! lrc,reg_whitelist}.c and regs/xe_{gt,engine,lrc_layout}_regs.h.
//! These operations run only under the enclosing GT's reset/wake owner.
#[path = "intel_gpu_gen12_reset.rs"]
pub(crate) mod reset;
use crate::{intel_gpu_aux::MmioWindow, intel_gpu_gt_hw::HardwareError, intel_gpu_rcs::GpuBacking};

/// Complete gen12_mocs_desc; undefined indices use the published base row2.
/// Values are literal bspec rows, not another generation's table.
pub(crate) fn mocs(index: usize) -> (u32, u16) {
    match index {
        3 | 51 => (0x5, 0x10),
        4 | 49 | 61 => (0x5, 0x30),
        5 | 50 | 60 | 62 | 63 => (0x37, 0x10),
        6 => (0x17, 0x10),
        7 => (0x17, 0x30),
        8 => (0x27, 0x10),
        9 => (0x27, 0x30),
        10 => (0x77, 0x10),
        11 => (0x77, 0x30),
        12 => (0x57, 0x10),
        13 => (0x57, 0x30),
        14 => (0x67, 0x10),
        15 => (0x67, 0x30),
        18 => (0x60037, 0x30),
        19 => (0x737, 0x30),
        20 => (0x337, 0x30),
        21 => (0x137, 0x30),
        22 => (0x3b7, 0x30),
        23 => (0x7b7, 0x30),
        _ => (0x37, 0x30),
    }
}

pub(crate) fn cache(mmio: &impl MmioWindow) -> Result<(), HardwareError> {
    for (reg, value) in [(0x4800, 3), (0x4804, 1), (0x4808, 2), (0x480c, 0)] {
        mmio.write32(reg, value);
        if mmio.read32(reg) != value {
            return Err(HardwareError::Unavailable);
        }
    }
    for index in 0..64 {
        let reg = 0x4000 + index as u64 * 4;
        let value = mocs(index).0;
        mmio.write32(reg, value);
        if mmio.read32(reg) != value {
            return Err(HardwareError::Unavailable);
        }
    }
    for index in 0..32 {
        let reg = 0xb020 + index as u64 * 4;
        let value = u32::from(mocs(index * 2).1) | u32::from(mocs(index * 2 + 1).1) << 16;
        mmio.write32(reg, value);
        if mmio.read32(reg) != value {
            return Err(HardwareError::Unavailable);
        }
    }
    Ok(())
}

/// One private timestamp restore sequence. The target is this context's
/// owned register-image value, never a firmware/user-selected pointer.
fn timestamp(image: &impl GpuBacking, ring: &impl GpuBacking, offset: u64) {
    let target = image.ggtt_offset() + 4096 + 0x23 * 4;
    for (i, header) in [0x14e80002, 0x14e80002, 0x14c80002].into_iter().enumerate() {
        for (word, value) in [header, 0x3a8, target, 0].into_iter().enumerate() {
            ring.write32(offset + i as u64 * 16 + word as u64 * 4, value);
        }
    }
}

/// Fresh per-context restore WAs occupy the unused second page of its owned
/// 8KiB ring. Admission bounds the actual ring commands below this page.
/// Both buffers share retirement; no extra independently droppable lease.
pub(crate) fn restore_was(
    image: &impl GpuBacking,
    ring: &impl GpuBacking,
    render: bool,
    user: bool,
    virtual_engine: bool,
) {
    timestamp(image, ring, 4096);
    let mut cursor = 4096 + 48;
    if render {
        for value in [0x11000001, 0xd8, 0x00400040] {
            ring.write32(cursor, value);
            cursor += 4;
        }
        timestamp(image, ring, 4224);
        // A mid-restore sequence has no BBE; hardware consumes one full
        // cache line. Preserve the golden context's class-specific offset.
        for i in 12..16 {
            ring.write32(4224 + i * 4, 0);
        }
        image.write32(4096 + 0x15 * 4, (ring.ggtt_offset() + 4224) | 1);
    }
    if virtual_engine {
        // xe_lrc.c::setup_utilization_wa: record the actual hardware class
        // and physical instance after each GuC placement, before START.
        for value in [0x12480002, 0x8c, image.ggtt_offset() + 0x818, 0] {
            ring.write32(cursor, value);
            cursor += 4;
        }
    }
    if user {
        // setup_utilization_wa follows the timestamp workaround on every
        // restore; its private saved sentinel is not a user batch command.
        for value in [0x10400002, image.ggtt_offset() + 4096 + 0x23 * 4, 0, 1] {
            ring.write32(cursor, value);
            cursor += 4;
        }
    }
    ring.write32(cursor, 0x05000000);
    image.write32(4096 + 0x13 * 4, (ring.ggtt_offset() + 4096) | 1);
}
