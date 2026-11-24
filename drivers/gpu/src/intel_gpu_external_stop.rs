//! Checked retirement of one already-owned Gen12, Gen11 or Gen9 SST link.
//! No allocator, timing change, shared DDB repartition or inferred stop on
//! GT reset. MIT Linux b90c984d intel_display.c352/503,
//! intel_ddi.c680/3099/3125. Display 9-11 differ where
//! `intel_ddi_post_disable_dp` does: the transcoder clock (3-bit field at
//! bits 31:29) stops before the DDI buffer, and `DP_TP_CTL` is port-based.
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_dp::DpConnection,
    intel_gpu_modeset::Framebuffer,
    intel_gpu_pipes::{Pipe, TRANS_DDI_FUNC_CTL_OFFSET},
};
use narf_filesystem::FsError;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase {
    Settling,
    Live,
    Plane,
    Pipe,
    Function,
    Buffer,
    Transport,
    Clock,
    Stopped,
    Quarantined,
}
#[derive(Debug)]
pub(crate) struct Session<L> {
    pub(crate) conn: DpConnection,
    pub(crate) fb: Framebuffer,
    pub(crate) alloc: L,
    pub(crate) serial: u64,
    pub(crate) bar: u64,
    phase: Phase,
    deadline: u64,
    original: Option<Original>,
}
#[derive(Copy, Clone, Debug)]
struct Original {
    ctl: u32,
    stride: u32,
    surf: u32,
    function: u32,
    buffer: u32,
    transport: u32,
    clock: u32,
    conf: u32,
    image: [(u64, u32); 14],
}
impl<L> Session<L> {
    pub(crate) fn adopt(
        io: &impl MmioWindow,
        conn: DpConnection,
        fb: Framebuffer,
        lease: L,
        serial: u64,
        bar: u64,
    ) -> Self {
        let original = Original::capture(io, &conn, &fb).ok();
        let phase = match original {
            Some(old) if live_witness(io, &conn, &old).unwrap_or(false) => Phase::Live,
            Some(_) => Phase::Settling,
            None => Phase::Quarantined,
        };
        Self {
            conn,
            fb,
            alloc: lease,
            serial,
            bar,
            phase,
            deadline: 0,
            original,
        }
    }
    pub(crate) fn request_stop(&mut self) {
        if self.running() {
            self.phase = Phase::Plane;
        }
    }
    pub(crate) fn running(&self) -> bool {
        matches!(self.phase, Phase::Live | Phase::Settling)
    }
    pub(crate) fn stopped(&self) -> bool {
        self.phase == Phase::Stopped
    }
    pub(crate) fn live(&self) -> bool {
        self.phase == Phase::Live
    }
    pub(crate) fn quarantine(&mut self) {
        if !self.stopped() {
            self.phase = Phase::Quarantined;
        }
    }
    /// One bounded owner step. Resources stay in `self` on every error.
    pub(crate) fn step(&mut self, io: &impl MmioWindow, now: u64) -> Result<bool, FsError> {
        let out = self.step_inner(io, now);
        if out.is_err() {
            self.phase = Phase::Quarantined;
        }
        out
    }
    /// No-write route proof before sink-side AUX power or local stop writes.
    pub(crate) fn preflight(&mut self, io: &impl MmioWindow) -> Result<(), FsError> {
        let result = self.check_current(io);
        if result.is_err() {
            self.phase = Phase::Quarantined;
        }
        result
    }
    fn check_current(&self, io: &impl MmioWindow) -> Result<(), FsError> {
        if self.stopped() {
            return Ok(());
        }
        if self.phase == Phase::Quarantined {
            return Err(FsError::NoDevice);
        }
        if !io.display_access_ok()
            || crate::intel_gpu_aux::SourceFamily::of(io) != Some(self.conn.family)
        {
            return Err(FsError::NoDevice);
        }
        let old = self.original.ok_or(FsError::NoDevice)?;
        let plane = self.conn.pipe.base() + 0x180;
        let trans = self.conn.pipe.transcoder();
        let conf = trans.conf_base() + 8;
        let func = trans.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        let buf = self.conn.ddi.base();
        let tp = transport_reg(&self.conn);
        let clk = 0x46140 + self.conn.pipe as u64 * 4;
        let (clock_mask, _) = clock_field(&self.conn);
        let pre_tgl = pre_tgl(&self.conn);
        idle_companions(io, &self.conn)?;
        for (register, value) in old.image {
            if read(io, register)? != value {
                return Err(FsError::NoDevice);
            }
        }
        // Revalidate every earlier postcondition before advancing. Inherited
        // writes or another owner cannot turn a partial stop into a new grant.
        let plane_off = !matches!(self.phase, Phase::Settling | Phase::Live | Phase::Plane);
        let function_off = matches!(self.phase, Phase::Buffer | Phase::Transport | Phase::Clock);
        let buffer_off = if pre_tgl {
            self.phase == Phase::Transport
        } else {
            matches!(self.phase, Phase::Transport | Phase::Clock)
        };
        let clock_off = pre_tgl && matches!(self.phase, Phase::Buffer | Phase::Transport);
        let conf_expected = if plane_off {
            old.conf & !(1 << 31)
        } else {
            old.conf
        };
        let conf_value = read(io, conf)?;
        if read(io, plane + 8)? != old.stride
            || read(io, plane + 0x1c)? != old.surf
            || read(io, plane)? != old.ctl & if plane_off { !(1 << 31) } else { u32::MAX }
            || read(io, func)?
                != old.function
                    & if function_off {
                        !((1 << 31) | (15 << 27) | (7 << 24))
                    } else {
                        u32::MAX
                    }
            || read(io, buf)? & !(1 << 7)
                != old.buffer & !(1 << 7) & if buffer_off { !(1 << 31) } else { u32::MAX }
            || read(io, tp)? != old.transport & if buffer_off { !(1 << 31) } else { u32::MAX }
            || read(io, clk)? != old.clock & if clock_off { !clock_mask } else { u32::MAX }
            || conf_value & !(1 << 30) != conf_expected & !(1 << 30)
            || (matches!(
                self.phase,
                Phase::Function | Phase::Buffer | Phase::Transport | Phase::Clock
            ) && conf_value & (1 << 30) != 0)
        {
            return Err(FsError::NoDevice);
        }
        if self.phase == Phase::Live && !live_witness(io, &self.conn, &old)? {
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    fn step_inner(&mut self, io: &impl MmioWindow, now: u64) -> Result<bool, FsError> {
        if self.stopped() {
            return Ok(true);
        }
        self.check_current(io)?;
        let old = self.original.ok_or(FsError::NoDevice)?;
        let plane = self.conn.pipe.base() + 0x180;
        let trans = self.conn.pipe.transcoder();
        let conf = trans.conf_base() + 8;
        let func = trans.base() + TRANS_DDI_FUNC_CTL_OFFSET;
        let buf = self.conn.ddi.base();
        let tp = transport_reg(&self.conn);
        let clk = 0x46140 + self.conn.pipe as u64 * 4;
        let (clock_mask, _) = clock_field(&self.conn);
        let pre_tgl = pre_tgl(&self.conn);
        if self.phase == Phase::Settling {
            if live_witness(io, &self.conn, &old)? {
                self.phase = Phase::Live;
            } else if self.deadline == 0 {
                self.deadline = now.saturating_add(100_000_000);
            } else if now >= self.deadline {
                return Err(FsError::TimedOut);
            }
            return Ok(false);
        }
        if self.phase == Phase::Live {
            return Ok(false);
        }
        match self.phase {
            Phase::Plane => {
                if read(io, plane)? != old.ctl
                    || read(io, func)? != old.function
                    || read(io, buf)? & !(1 << 7) != old.buffer & !(1 << 7)
                {
                    return Err(FsError::NoDevice);
                }
                checked(io, plane, old.ctl & !(1 << 31))?;
                checked(io, plane + 0x1c, old.surf)?; // latch disable using retained SURF
                let v = read(io, conf)?;
                io.write32(conf, v & !(1 << 31));
                if read(io, conf)? & (1 << 31) != 0 {
                    return Err(FsError::NoDevice);
                }
                self.deadline = now.saturating_add(100_000_000);
                self.phase = Phase::Pipe;
            }
            Phase::Pipe => {
                let v = read(io, conf)?;
                if v & ((1 << 31) | (1 << 30)) != 0 {
                    if now >= self.deadline {
                        return Err(FsError::TimedOut);
                    }
                    return Ok(false);
                }
                if read(io, plane)? & (1 << 31) != 0 {
                    return Err(FsError::NoDevice);
                }
                self.phase = Phase::Function;
            }
            Phase::Function => {
                if read(io, func)? != old.function {
                    return Err(FsError::NoDevice);
                }
                checked(
                    io,
                    func,
                    old.function & !((1 << 31) | (15 << 27) | (7 << 24)),
                )?;
                // Display 9-11 stop the transcoder clock before the buffer.
                self.phase = if pre_tgl { Phase::Clock } else { Phase::Buffer };
            }
            Phase::Buffer => {
                let value = read(io, buf)?;
                if value & !(1 << 7) != old.buffer & !(1 << 7) {
                    return Err(FsError::NoDevice);
                }
                io.write32(buf, value & !(1 << 31));
                if read(io, buf)? & (1 << 31) != 0 {
                    return Err(FsError::NoDevice);
                }
                // The source disables transport/FEC before its idle wait.
                if read(io, tp)? != old.transport {
                    return Err(FsError::NoDevice);
                }
                checked(io, tp, old.transport & !(1 << 31))?;
                self.deadline = now.saturating_add(10_000_000);
                self.phase = Phase::Transport;
            }
            Phase::Transport => {
                let v = read(io, buf)?;
                if v & (1 << 31) != 0 || v & (1 << 7) == 0 {
                    if now >= self.deadline {
                        return Err(FsError::TimedOut);
                    }
                    return Ok(false);
                }
                if pre_tgl {
                    final_proof(io, conf, plane, buf, tp)?;
                    self.phase = Phase::Stopped;
                    return Ok(true);
                }
                self.phase = Phase::Clock;
            }
            Phase::Clock => {
                if read(io, clk)? != old.clock {
                    return Err(FsError::NoDevice);
                }
                checked(io, clk, old.clock & !clock_mask)?;
                if pre_tgl {
                    self.phase = Phase::Buffer;
                    return Ok(false);
                }
                final_proof(io, conf, plane, buf, tp)?;
                self.phase = Phase::Stopped;
                return Ok(true);
            }
            _ => return Err(FsError::NoDevice),
        }
        Ok(false)
    }
}
/// Display 9-11 sources (no Gen12 family).
fn pre_tgl(c: &DpConnection) -> bool {
    c.family.gen12().is_none()
}
/// `DP_TP_CTL`: per transcoder on display 12 (`TGL_DP_TP_CTL`), per port
/// below it (DDI base + 0x40), as `dp_tp_ctl_reg` picks.
fn transport_reg(c: &DpConnection) -> u64 {
    if pre_tgl(c) {
        c.ddi.base() + 0x40
    } else {
        c.pipe.transcoder().base() + 0x540
    }
}
/// `TRANS_CLK_SEL` port field (mask, value for `c.ddi`): display 12's
/// `TGL_TRANS_CLK_SEL_PORT` at bits 31:28, display 9-11's
/// `TRANS_CLK_SEL_PORT` at bits 31:29; both encode port + 1.
fn clock_field(c: &DpConnection) -> (u32, u32) {
    let port = u32::from(c.ddi as u8) + 1;
    if pre_tgl(c) {
        (7 << 29, port << 29)
    } else {
        (15 << 28, port << 28)
    }
}
/// Independent final local proof before publication can change.
fn final_proof(
    io: &impl MmioWindow,
    conf: u64,
    plane: u64,
    buf: u64,
    tp: u64,
) -> Result<(), FsError> {
    if read(io, conf)? & ((1 << 31) | (1 << 30)) != 0
        || read(io, plane)? & (1 << 31) != 0
        || read(io, buf)? & ((1 << 31) | (1 << 7)) != (1 << 7)
        || read(io, tp)? & (1 << 31) != 0
    {
        return Err(FsError::NoDevice);
    }
    Ok(())
}
fn read(io: &impl MmioWindow, r: u64) -> Result<u32, FsError> {
    if !io.display_access_ok() {
        return Err(FsError::NoDevice);
    }
    let v = io.read32(r);
    if v == u32::MAX || !io.display_access_ok() {
        Err(FsError::NoDevice)
    } else {
        Ok(v)
    }
}
fn checked(io: &impl MmioWindow, r: u64, v: u32) -> Result<(), FsError> {
    io.write32(r, v);
    if read(io, r)? == v {
        Ok(())
    } else {
        Err(FsError::NoDevice)
    }
}
impl Original {
    fn capture(io: &impl MmioWindow, c: &DpConnection, fb: &Framebuffer) -> Result<Self, FsError> {
        // The stop proof is the DDI B one.
        if crate::intel_gpu_aux::SourceFamily::of(io) != Some(c.family)
            || c.ddi != crate::intel_gpu_ddi::Ddi::B
            || c.family.gen12() == Some(crate::intel_gpu_gt::Gen12Platform::AlderLakeS)
            || !matches!(c.pipe, Pipe::A | Pipe::B | Pipe::C)
        {
            return Err(FsError::Unsupported);
        }
        let plane = c.pipe.base() + 0x180;
        let trans = c.pipe.transcoder();
        if c.mode.h_active == 0 || c.mode.v_active == 0 {
            return Err(FsError::Unsupported);
        }
        idle_companions(io, c)?;
        let mut image = [(0, 0); 14];
        for (entry, register) in image.iter_mut().zip([
            plane + 0x0c,
            plane + 0x10,
            plane + 0x24,
            plane + 0x40,
            plane + 0x44,
            plane + 0x48,
            plane + 0x4c,
            trans.base(),
            trans.base() + 4,
            trans.base() + 8,
            trans.base() + 0x0c,
            trans.base() + 0x10,
            trans.base() + 0x14,
            trans.base() + 0x1c,
        ]) {
            *entry = (register, read(io, register)?);
        }
        let o = Self {
            ctl: read(io, plane)?,
            stride: read(io, plane + 8)?,
            surf: read(io, plane + 0x1c)?,
            function: read(io, trans.base() + 0x400)?,
            buffer: read(io, c.ddi.base())?,
            transport: read(io, transport_reg(c))?,
            clock: read(io, 0x46140 + c.pipe as u64 * 4)?,
            conf: read(io, trans.conf_base() + 8)?,
            image,
        };
        let route = crate::intel_gpu_pipes::build_trans_ddi_func_ctl(
            c.ddi as u8,
            crate::intel_gpu_pipes::TRANS_DDI_MODE_DP_SST,
            c.trained.lanes,
        );
        let (route, control) = match c.family.gen12() {
            Some(family) => (route, crate::intel_gpu_pipes::gen12_xrgb_control(family)),
            None => (
                crate::intel_gpu_pipes::with_pre_tgl_port(route, c.ddi as u8),
                crate::intel_gpu_pipes::PLANE_CTL_ENABLE
                    | crate::intel_gpu_pipes::PixelFormat::Argb8888.encode_for_plane_ctl(),
            ),
        };
        let (clock_mask, clock_port) = clock_field(c);
        if ![1, 2, 4].contains(&c.trained.lanes)
            || fb.stride_bytes % 64 != 0
            || fb.stride_bytes < u32::from(c.mode.h_active) * 4
            || fb.phys_addr > u64::from(u32::MAX)
            || read(io, plane + 0x0c)? != 0
            || read(io, plane + 0x10)?
                != (u32::from(c.mode.v_active) - 1) << 16 | (u32::from(c.mode.h_active) - 1)
            || read(io, trans.base() + 0x1c)?
                != (u32::from(c.mode.h_active) - 1) << 16 | (u32::from(c.mode.v_active) - 1)
            || o.ctl != control
            || o.stride != fb.stride_bytes / 64
            || u64::from(o.surf) != fb.phys_addr
            || o.function != route
            || o.buffer & ((1 << 31) | (1 << 7) | 14)
                != (1 << 31) | (u32::from(c.trained.lanes) - 1) << 1
            || o.transport & ((1 << 30) | (1 << 27)) != 0
            || o.conf & 0x80e00000 != 0x80000000
            || read(io, plane + 0x24)? != 0
            || read(io, plane + 0x40)? != 0
            || read(io, plane + 0x44)? != 0
            || read(io, plane + 0x48)? != 0
            || o.clock & clock_mask != clock_port
        {
            return Err(FsError::Unsupported);
        }
        Ok(o)
    }
}
fn live_witness(io: &impl MmioWindow, c: &DpConnection, old: &Original) -> Result<bool, FsError> {
    Ok(read(io, c.pipe.base() + 8)? & 0xc0000000 == 0xc0000000
        && read(io, c.pipe.base() + 0x1ac)? == old.surf)
}
// Local fetchers only: other live pipes retain their own authority/resources.
// MIT intel_cursor_regs.h, intel_dsb_regs.h, skl_universal_plane_regs.h,
// intel_vdsc_regs.h and intel_display_regs.h, same pinned revision.
fn idle_companions(io: &impl MmioWindow, c: &DpConnection) -> Result<(), FsError> {
    let base = c.pipe.base();
    if read(io, 0x43208)? & (1 << 31) != 0
        || read(io, base + 0x80)? & 0x27 != 0
        || read(io, 0x420c0 + c.pipe as u64 * 4)? & (1 << 23) != 0
    {
        return Err(FsError::Unsupported);
    }
    use crate::intel_gpu_aux::SourceFamily;
    // TRANS_DDI_FUNC_CTL2 exists from display 11.
    if !matches!(c.family, SourceFamily::Gen9 { .. }) && read(io, c.pipe.trans_base() + 0x404)? != 0
    {
        return Err(FsError::Unsupported);
    }
    // Universal planes per pipe: display 12 per family, display 11's 7,
    // display 9's 3 on Pipes A/B and 2 on Pipe C.
    let planes = match c.family {
        SourceFamily::Gen12(family) => crate::intel_gpu_pipes::gen12_plane_count(family),
        SourceFamily::Gen11(_) => 7,
        SourceFamily::Gen9 { .. } if c.pipe == Pipe::C => 2,
        SourceFamily::Gen9 { .. } => 3,
    };
    for plane in 2..=planes {
        if read(io, base + 0x80 + plane * 0x100)? & (1 << 31) != 0 {
            return Err(FsError::Unsupported);
        }
    }
    // DSB engines exist from display 12.
    if c.family.gen12().is_some() {
        for dsb in 0..3u64 {
            if read(io, base + 0xb08 + dsb * 0x100)? & ((1 << 31) | 1) != 0 {
                return Err(FsError::Unsupported);
            }
        }
    }
    // The pipe's DSS (VDSC/joiner) control, from display 11: per pipe on
    // display 12; on display 11 Pipe A's is the transcoder one at 0x67400
    // (`dss_ctl1_reg`, `is_pipe_dsc`). Display 9 has none.
    let dss = match c.family {
        SourceFamily::Gen12(_) => Some(0x78000 + c.pipe as u64 * 0x200),
        SourceFamily::Gen11(_) if c.pipe == Pipe::A => Some(0x67400),
        SourceFamily::Gen11(_) => Some(0x78000 + c.pipe as u64 * 0x200),
        SourceFamily::Gen9 { .. } => None,
    };
    if let Some(dss) = dss {
        if read(io, dss)? & 0xf0f00000 != 0 || read(io, dss + 4)? & 0xc0008000 != 0 {
            return Err(FsError::Unsupported);
        }
    }
    Ok(())
}
/// Publication and serial share one lock in production. A stale stop can
/// withdraw only the exact image it published, never a newer/internal owner.
pub(crate) fn withdraw<T>(active: &mut (u64, Option<T>), serial: u64) -> bool {
    if serial != 0 && active.0 == serial && active.1.is_some() {
        *active = (0, None);
        true
    } else {
        false
    }
}
#[cfg(feature = "kernel-test")]
mod tests {
    include!("intel_gpu_external_stop_tests.rs");
}
