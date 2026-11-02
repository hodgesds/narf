//! Retained unchanged-bandwidth Gen12 internal primary. MIT Linux b90c984d:
//! gen8_ggtt_pte_encode/xelp_ggtt_pte_flags, intel_display_regs.h,
//! intel_display_device.c XE_D_DISPLAY/XE_LPD_FEATURES and adlp_allowed_dbufs.
//! This owner preserves a driver-established linear console resource image;
//! The primary shadow journal admits only explicitly staged linear/X views;
//! clocks, DBUF/DDB/WM, cursor and QGV/MBUS resources stay unchanged.
use super::*;
use crate::intel_gpu_gt::Gen12Platform;
use crate::intel_gpu_gtt::PteFormat;

#[derive(Debug)]
pub(super) struct Owner {
    family: Gen12Platform,
    image: Vec<(u64, u32, u32)>,
    geometry: Geometry,
    plane: [u32; 3],
    pending_plane: Option<[u32; 3]>,
}
fn read(io: &impl Platform, register: u64) -> Result<u32, FsError> {
    if !io.access_ok() {
        return Err(FsError::NoDevice);
    }
    let value = io.read32(register);
    if value == u32::MAX || !io.access_ok() {
        Err(FsError::NoDevice)
    } else {
        Ok(value)
    }
}
impl Owner {
    pub(super) fn capture(
        io: &impl Platform,
        console: &ActiveScanout,
        family: Gen12Platform,
        bar_len: u64,
    ) -> Result<Self, FsError> {
        let geometry = scanout_geometry(console);
        let size = u64::from(geometry.pitch) * u64::from(geometry.height);
        crate::intel_gpu_gtt::check_console_scanout_range(bar_len, console.gtt_offset.into(), size)
            .map_err(|_| FsError::Unsupported)?;
        let min_width = if crate::intel_gpu_scanout::gen12_alignment(family) == 16384 {
            4
        } else {
            6
        };
        if !(min_width..=5120).contains(&geometry.width)
            || geometry.height == 0
            || geometry.height > 4320
            || geometry.pitch % 64 != 0
            || geometry.pitch < geometry.width.saturating_mul(4)
            || geometry.pitch / 64 > 0xfff
            || geometry.pitch > crate::intel_gpu_scanout::gen12_max_stride(family)
            || console.gtt_offset != 0x1000000
            || read(io, 0x7019c)? != console.gtt_offset
            || read(io, 0x701ac)? != console.gtt_offset
            || read(io, 0x70188)? != geometry.pitch / 64
            || read(io, 0x70190)? != (geometry.height - 1) << 16 | (geometry.width - 1)
            || read(io, 0x6001c)? != (geometry.width - 1) << 16 | (geometry.height - 1)
            || read(io, 0x7018c)? != 0
            || read(io, 0x701a4)? != 0
        {
            return Err(FsError::NoDevice);
        }
        let plane = read(io, 0x70180)?;
        let route = read(io, 0x60400)?;
        let port = read(io, 0x64000)?;
        let lanes = (route >> 1) & 7;
        // TGL_TRANS_DDI_SELECT_PORT(A)=1<<27; SST,8bpc, no port sync,
        // MST transport, HDCP, scrambling or alternate eDP input selection.
        let route_mask = (1 << 31)
            | (15 << 27)
            | (7 << 24)
            | (7 << 20)
            | (1 << 15)
            | (7 << 12)
            | (3 << 10)
            | (1 << 9)
            | (1 << 8)
            | 0xf1;
        // The owned Gen12 modeset writes exactly this linear XR24 control.
        // Do not adopt rotation, reflection, async or compressed fetch modes.
        if plane != crate::intel_gpu_pipes::gen12_xrgb_control(family)
            || read(io, 0x701c0)? != 0
            || read(io, 0x701c4)? != 0
            || read(io, 0x701c8)? != 0
            || route & route_mask != 0x8a000000
            || ![0, 1, 3].contains(&lanes)
            || port & ((1 << 31) | (1 << 7) | 14) != (1 << 31) | (lanes << 1)
            || read(io, 0x70008)? & 0xc0e00000 != 0xc0000000
            || read(io, 0xc7200)? & 0xb800000f != 0x80000008
            || read(io, 0xc7204)? & 1 == 0
            || read(io, 0x68180)? & (1 << 31) != 0
            || read(io, 0x68280)? & (1 << 31) != 0
            || read(io, 0x46070)? & 0xc0000000 != 0xc0000000
            || read(io, 0x70240)? & (1 << 31) == 0
        {
            return Err(FsError::NoDevice);
        }
        let ddb = read(io, 0x7027c)?;
        if ddb & 0x1fff != 0 || (ddb >> 16) & 0x1fff >= 2048 {
            return Err(FsError::NoDevice);
        }
        let mut image = Vec::new();
        for register in [
            0x60400, 0x60000, 0x60004, 0x60008, 0x6000c, 0x60010, 0x60014, 0x6001c, 0x70008,
            0x7018c, 0x70190, 0x701c0, 0x701c4, 0x701c8, 0x701cc, 0x46000, 0x70240, 0x70244,
            0x70248, 0x7024c, 0x70250, 0x70254, 0x70258, 0x7025c, 0x70268, 0x7027c, 0x45004,
            0x7003c,
        ] {
            image.push((register, u32::MAX, read(io, register)?));
        }
        for register in [0x45008, 0x44fe8] {
            let value = read(io, register)? & 0xc0ff0000;
            if value & 0xc0000000 != 0xc0000000 {
                return Err(FsError::NoDevice);
            }
            image.push((register, 0xc0ff0000, value));
        }
        if matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        ) {
            // adlp_allowed_dbufs: PipeA may use S1/S2 with MBUS unjoined.
            // A joined four-slice allocation requires the separate owner.
            if read(io, 0x4438c)? & (1 << 31) != 0 {
                return Err(FsError::NoDevice);
            }
            image.push((0x4438c, u32::MAX, read(io, 0x4438c)?));
        }
        image.push((0x64000, (1 << 31) | 14, port & ((1 << 31) | 14)));
        image.push((0x46070, 0xc00000ff, read(io, 0x46070)? & 0xc00000ff));
        if matches!(
            family,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
        ) {
            image.push((0x42084, 1 << 30, read(io, 0x42084)? & (1 << 30)));
        }
        let owner = Self {
            family,
            image,
            geometry,
            plane: [plane, geometry.pitch / 64, 0],
            pending_plane: None,
        };
        owner.check_console_mapping(io, console)?;
        owner.check(io)?;
        Ok(owner)
    }
    pub(super) fn check(&self, io: &impl Platform) -> Result<(), FsError> {
        self.check_owned(io, false, false)
    }
    pub(super) fn check_owned(
        &self,
        io: &impl Platform,
        owned_dsb: bool,
        owned_cursor: bool,
    ) -> Result<(), FsError> {
        if io.gen12_family() != Some(self.family) || !io.internal_primary_claimed() {
            return Err(FsError::NoDevice);
        }
        for &(r, mask, expected) in &self.image {
            if read(io, r)? & mask != expected {
                return Err(FsError::NoDevice);
            }
        }
        self.check_plane(io)?;
        // These independent DMA consumers cannot be adopted merely because
        // the primary's live SURF happens to match a driver-owned buffer.
        let generation = match self.family {
            Gen12Platform::TigerLake => Generation::TigerLake,
            Gen12Platform::AlderLakeS | Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => {
                Generation::AlderLake
            }
        };
        fetchers_with_cursor(io, generation, owned_dsb, owned_cursor)?;
        for pipe in 1..4 {
            if read(io, 0x70008 + pipe * 0x1000)? & 0xc0000000 != 0 {
                return Err(FsError::NoDevice);
            }
        }
        if read(io, 0xc7200)? & 0xb800000f != 0x80000008
            || read(io, 0xc7204)? & 1 == 0
            || read(io, 0x68180)? & (1 << 31) != 0
            || read(io, 0x68280)? & (1 << 31) != 0
        {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    fn check_plane(&self, io: &impl Platform) -> Result<(), FsError> {
        for (i, r) in [0x70180, 0x70188, 0x701a4].into_iter().enumerate() {
            let actual = read(io, r)?;
            if actual != self.plane[i] && self.pending_plane.is_none_or(|p| actual != p[i]) {
                return Err(FsError::NoDevice);
            }
        }
        Ok(())
    }
    /// Journal only source-qualified shadow values before the first possible
    /// DSB write. Mixed old/new fields after partial DMA remain OWNED, never a
    /// new baseline; only Presenter latch proof can commit or retire them.
    pub(super) fn stage_view(
        &mut self,
        io: &impl Platform,
        view: crate::intel_gpu_scanout::View,
    ) -> Result<(), FsError> {
        if self.pending_plane.is_some() {
            return Err(FsError::Busy);
        }
        self.check_plane(io)?;
        if view.layout == crate::intel_gpu_scanout::Layout::Tile4 {
            return Err(FsError::Unsupported);
        }
        if view.layout == crate::intel_gpu_scanout::Layout::X {
            check_no_dpt(io, self.family)?;
        }
        let (_, offset, _) = view
            .footprint_aligned(
                self.geometry,
                crate::intel_gpu_scanout::gen12_alignment(self.family),
            )
            .map_err(scanout_error)?;
        self.pending_plane = Some([
            crate::intel_gpu_pipes::gen12_xrgb_control(self.family) | view.tiled(),
            view.stride(self.geometry),
            offset,
        ]);
        Ok(())
    }
    /// Caller has the independent fresh primary latch and joint DSB proof.
    pub(super) fn complete_view(&mut self, io: &impl Platform) -> Result<(), FsError> {
        if let Some(target) = self.pending_plane {
            for (r, v) in [0x70180, 0x70188, 0x701a4].into_iter().zip(target) {
                if read(io, r)? != v {
                    return Err(FsError::NoDevice);
                }
            }
            self.plane = target;
            self.pending_plane = None;
        }
        self.check_plane(io)
    }
    /// Only the caller's strict before-exposure rollback reaches this path.
    pub(super) fn rollback_view(&mut self, io: &impl Platform) -> Result<(), FsError> {
        for (r, v) in [0x70180, 0x70188, 0x701a4].into_iter().zip(self.plane) {
            if read(io, r)? != v {
                return Err(FsError::NoDevice);
            }
        }
        self.pending_plane = None;
        Ok(())
    }
    pub(super) fn check_console_mapping(
        &self,
        io: &impl Platform,
        console: &ActiveScanout,
    ) -> Result<(), FsError> {
        if console.phys_base % 4096 != 0 {
            return Err(FsError::NoDevice);
        }
        let pages = (u64::from(console.stride_bytes) * u64::from(console.height)).div_ceil(4096);
        for page in 0..pages {
            let address = console
                .phys_base
                .checked_add(page * 4096)
                .ok_or(FsError::NoDevice)?;
            // Gen12 GGTT system PTEs are address|PRESENT. PAT indices belong
            // to PPGTT, not this display mapping; no MTL PAT read is used.
            let expected = crate::intel_gpu_gtt::encode_display_pte(PteFormat::Gen12, address, 0)
                .map_err(|_| FsError::NoDevice)?;
            let r = GGTT_ARRAY_BASE + (u64::from(console.gtt_offset) / 4096 + page) * 8;
            if read(io, r)? != expected as u32 || read(io, r + 4)? != (expected >> 32) as u32 {
                return Err(FsError::NoDevice);
            }
        }
        Ok(())
    }
}

fn check_no_dpt(io: &impl Platform, family: Gen12Platform) -> Result<(), FsError> {
    // Display12 has no DPT. Display13's source global bit is NOT the
    // display14 per-plane chicken at0x7026c bit19.
    if matches!(
        family,
        Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN
    ) && read(io, 0x42084)? & (1 << 30) == 0
    {
        return Err(FsError::Unsupported);
    }
    Ok(())
}
pub(super) fn view_profile(
    io: &impl Platform,
    geometry: Geometry,
    timing: crate::intel_gpu_dsb::Timing,
    family: Gen12Platform,
    layout: crate::intel_gpu_scanout::Layout,
) -> Result<(), FsError> {
    if !io.console_access_ok() {
        return Err(FsError::NoDevice);
    }
    let min_width = if crate::intel_gpu_scanout::gen12_alignment(family) == 16384 {
        4
    } else {
        6
    };
    if geometry.pitch > crate::intel_gpu_scanout::gen12_max_stride(family)
        || !(min_width..=5120).contains(&geometry.width)
        || geometry.height > 4320
        || layout == crate::intel_gpu_scanout::Layout::Tile4
    {
        return Err(FsError::Unsupported);
    }
    crate::intel_gpu_scanout::View {
        origin: Default::default(),
        layout,
    }
    .footprint_aligned(geometry, crate::intel_gpu_scanout::gen12_alignment(family))
    .map_err(scanout_error)?;
    if layout == crate::intel_gpu_scanout::Layout::X {
        check_no_dpt(io, family)?;
    }
    // Resource capture/check is separately retained by the KMS owner. Do not
    // recapture an off-cursor baseline while its independent owner is live.
    if !timing.valid()
        || geometry.width != u32::from(timing.width)
        || geometry.height != u32::from(timing.height)
    {
        return Err(FsError::Unsupported);
    }
    Ok(())
}
