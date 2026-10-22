//! Bounded frame-OBU parser for the native encoder's fixed reduced-still keyframe.
//! Sequence parameters come from the separately preserved Mesa-built prefix.
//! This intentionally refuses inter frames, extra OBUs, QM/segmentation/deltaQ,
//! screen-content/render overrides and other producer settings we did not send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Picture {
    pub tile_offset: u32,
    pub tile_bytes: u32,
    pub base_q_idx: u8,
    pub quant_delta: [i8; 5],
    pub filter_level: [u8; 4],
    pub sharpness: u8,
    pub mode_ref_delta_enabled: bool,
    pub mode_ref_delta_update: bool,
    pub ref_deltas: [i8; 8],
    pub mode_deltas: [i8; 2],
    pub tx_mode: u8,
    pub reduced_tx_set: bool,
}
struct Bits<'a> {
    data: &'a [u8],
    at: usize,
}
impl Bits<'_> {
    fn bits(&mut self, count: usize) -> Option<u8> {
        if count > 8 {
            return None;
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | ((self.data.get(self.at / 8)? >> (7 - self.at % 8)) & 1);
            self.at += 1;
        }
        Some(value)
    }
    fn zero(&mut self, count: usize) -> Option<()> {
        (self.bits(count)? == 0).then_some(())
    }
    fn signed(&mut self) -> Option<i8> {
        let n = i16::from(self.bits(7)?);
        Some(if n & 64 != 0 { n - 128 } else { n } as i8)
    }
    fn delta_q(&mut self) -> Option<i8> {
        if self.bits(1)? == 0 {
            Some(0)
        } else {
            self.signed()
        }
    }
}
/// Input is exactly the firmware's one OBU_FRAME, excluding CPU sequence/padding.
/// Tile offsets are relative to this slice; callers add the preserved sequence
/// header length when constructing the compact decoder bitstream.
pub(super) fn inspect(frame: &[u8]) -> Option<Picture> {
    if frame.len() > 0x1f000 || frame.first() != Some(&0x32) {
        return None;
    }
    // AV1 leb128 permits at most eight bytes. Checked arithmetic also refuses
    // over-wide lengths; a bounded output buffer never justifies truncation.
    let mut at = 1;
    let mut size = 0u64;
    let mut ended = false;
    for i in 0..8 {
        let n = *frame.get(at)?;
        at += 1;
        size |= u64::from(n & 127).checked_shl(i * 7)?;
        if n & 128 == 0 {
            ended = true;
            break;
        }
    }
    if !ended || size == 0 || usize::try_from(size).ok()?.checked_add(at)? != frame.len() {
        return None;
    }
    let mut b = Bits {
        data: frame.get(at..)?,
        at: 0,
    };
    // Reduced still => KEY/show_frame/error_resilient/refresh0xff and no refs.
    // seq_force_screen_content_tools is inferred SELECT in reduced still mode.
    if b.bits(1)? != 1 {
        return None;
    } // disable_cdf_update
    b.zero(1)?; // allow_screen_content_tools=0 (no integer_mv/intrabc branches).
    b.zero(1)?; // render_and_frame_size_different=0, frame size fixed320x128.
    if b.bits(1)? != 1 {
        return None;
    } // uniform_tile_spacing_flag
    b.zero(2)?; // no additional tile columns/rows: exactly one5x2-SB tile.
    let base_q_idx = b.bits(8)?;
    let y = b.delta_q()?;
    let u_dc = b.delta_q()?;
    let u_ac = b.delta_q()?;
    let quant_delta = [y, u_dc, u_ac, u_dc, u_ac]; // separate_uv_delta_q=0.
    b.zero(1)?; // using_qmatrix
    b.zero(1)?; // segmentation_enabled
    if base_q_idx > 0 {
        b.zero(1)?;
    } // delta_q_present; delta_lf is then inferred0.
    let lossless = base_q_idx == 0 && quant_delta == [0; 5];
    let mut picture = Picture {
        tile_offset: 0,
        tile_bytes: 0,
        base_q_idx,
        quant_delta,
        filter_level: [0; 4],
        sharpness: 0,
        mode_ref_delta_enabled: false,
        mode_ref_delta_update: false,
        ref_deltas: [1, 0, 0, 0, -1, 0, -1, -1],
        mode_deltas: [0; 2],
        tx_mode: 0,
        reduced_tx_set: false,
    };
    if !lossless {
        picture.filter_level[0] = b.bits(6)?;
        picture.filter_level[1] = b.bits(6)?;
        if picture.filter_level[0] != 0 || picture.filter_level[1] != 0 {
            picture.filter_level[2] = b.bits(6)?;
            picture.filter_level[3] = b.bits(6)?;
        }
        picture.sharpness = b.bits(3)?;
        picture.mode_ref_delta_enabled = b.bits(1)? != 0;
        if picture.mode_ref_delta_enabled {
            picture.mode_ref_delta_update = b.bits(1)? != 0;
            if picture.mode_ref_delta_update {
                for n in &mut picture.ref_deltas {
                    if b.bits(1)? != 0 {
                        *n = b.signed()?;
                    }
                }
                for n in &mut picture.mode_deltas {
                    if b.bits(1)? != 0 {
                        *n = b.signed()?;
                    }
                }
            }
        }
        // CDEF/restoration disabled in the fixed sequence. Lossless implies
        // ONLY_4X4; otherwise read_tx_mode selects LARGEST or SELECT.
        picture.tx_mode = if b.bits(1)? == 0 { 1 } else { 2 };
    }
    // Intra => no ref-select/skip/global-motion. No film grain in sequence.
    b.zero(1)?; // reduced_tx_set=0, as the instruction template specifies.
    while b.at % 8 != 0 {
        b.zero(1)?;
    }
    let offset = at.checked_add(b.at / 8)?;
    let bytes = frame.len().checked_sub(offset)?;
    if bytes == 0 {
        return None;
    }
    picture.tile_offset = u32::try_from(offset).ok()?;
    picture.tile_bytes = u32::try_from(bytes).ok()?;
    Some(picture)
}
