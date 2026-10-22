//! Pinned Mesa26.2.4 GFX12 META rectangle draw, not a compute clear.
//! The primary harness generates actual ACO NGG/PS and Addrlib3 linear CB
//! state, geometry rings, draw and pixel-completion PM4 for both GC12 dies.
use crate::amdgpu_rdna4::Rdna4Chip;
use narf_filesystem::FsError;

#[path = "amdgpu_gfx12_draw_data.rs"]
mod data;

pub(crate) const VA: u64 = 0x0200_0000;
pub(crate) const CODE_BYTES: u64 = 0x1_0000;
pub(crate) const IB: u64 = 0x2000;
pub(crate) const UPLOAD: u64 = 0x1_0000;
pub(crate) const DESCRIPTORS: u64 = 0x3_0000;
pub(crate) const TARGET: u64 = 0x4_0000;
pub(crate) const GE: u64 = 0x20_0000;
const GUARD: u64 = 0x1_0000;
pub(crate) const WIDTH: u32 = 64;
pub(crate) const HEIGHT: u32 = 64;
pub(crate) const PITCH: u64 = 256;
pub(crate) const RECT: [u32; 4] = [7, 11, 29, 23];
pub(crate) const COLOR: u32 = 0xff00_00ff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Inputs {
    pub chip: Rdna4Chip,
    /// GC discovery's physical SE count, including harvested engines.
    pub max_se: u32,
    /// Retained authenticated PFP image, not a later registry lookup.
    pub pfp_version: u32,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fixture {
    pub target: u16,
    pub ge_bytes: u64,
    pub pm4: &'static [u32],
    pub descriptors: &'static [u32],
}
impl Fixture {
    pub fn new(inputs: Inputs) -> Result<Self, FsError> {
        let modern = inputs.pfp_version >= 2680;
        let (target, max_se, ge_bytes, pm4, descriptors) = match inputs.chip {
            Rdna4Chip::Navi44 => (
                1200,
                2,
                0x40_0000,
                if modern {
                    data::PM4_1200_2680
                } else {
                    data::PM4_1200_2630
                },
                data::DESCRIPTORS_1200,
            ),
            Rdna4Chip::Navi48 => (
                1201,
                4,
                0xa8_0000,
                if modern {
                    data::PM4_1201_2680
                } else {
                    data::PM4_1201_2630
                },
                data::DESCRIPTORS_1201,
            ),
        };
        if inputs.max_se != max_se {
            return Err(FsError::InvalidData);
        }
        Ok(Self {
            target,
            ge_bytes,
            pm4,
            descriptors,
        })
    }
    pub fn bytes(self) -> u64 {
        GE + self.ge_bytes + GUARD
    }
    pub fn ib_dwords(self) -> u32 {
        self.pm4.len() as u32
    }
    pub fn geometry(self, offset: u64) -> bool {
        (GE..GE + self.ge_bytes).contains(&offset)
    }

    /// Every immutable/code/IB/descriptor word, every target pixel and all
    /// padding/guards have a deterministic value. Only allocated GE ring
    /// interiors may change to unspecified hardware working data.
    pub fn word(self, offset: u64, client: usize, drawn: bool) -> u32 {
        if let Some(word) = [
            (0, data::NGG),
            (0x1000, data::PS),
            (IB, self.pm4),
            (UPLOAD, data::UPLOAD),
            (DESCRIPTORS, self.descriptors),
        ]
        .into_iter()
        .find_map(|(start, words)| {
            offset
                .checked_sub(start)
                .and_then(|at| words.get((at / 4) as usize))
                .copied()
        }) {
            return word;
        }
        let pixel = offset
            .checked_sub(TARGET)
            .filter(|at| *at < PITCH * u64::from(HEIGHT));
        if drawn
            && pixel.is_some_and(|at| {
                let x = (at % PITCH / 4) as u32;
                let y = (at / PITCH) as u32;
                (RECT[0]..RECT[0] + RECT[2]).contains(&x)
                    && (RECT[1]..RECT[1] + RECT[3]).contains(&y)
            })
        {
            return COLOR;
        }
        0x91d4_c37b ^ (offset as u32).wrapping_mul(0x9e37_79b9) ^ ((client as u32 + 1) << 24)
    }
}
