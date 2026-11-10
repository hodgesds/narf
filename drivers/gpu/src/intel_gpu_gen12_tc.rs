//! Tiger Lake / Alder Lake-P Dekel Type-C PHY and its per-port PLL.
//!
//! Reference: Linux intel_dpll_mgr.c (icl_calc_mg_pll_state,
//! dkl_pll_write, mg_pll_enable), intel_dkl_phy.c, intel_tc.c and
//! intel_ddi.c. HIP bank selection and the following access are one
//! transaction. A TC port never programs a combo DPLL or BUF_TRANS.
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gt::Gen12Platform;
use crate::intel_gpu_modeset::ModesetError;
use crate::intel_gpu_pll::LinkRate;
use core::sync::atomic::{compiler_fence, Ordering};

static HIP: narf_lib::mutex::Mutex<()> = narf_lib::mutex::Mutex::new(());
struct ColdOwner {
    bar: u64,
    ports: u8,
    aux_owned: u8,
}
static COLD: narf_lib::mutex::Mutex<alloc::vec::Vec<ColdOwner>> =
    narf_lib::mutex::Mutex::new(alloc::vec::Vec::new());

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DklPllState {
    pub div0: u32,
    pub div1: u32,
    pub ssc: u32,
    pub bias: u32,
    pub tdc: u32,
    pub core: u32,
    pub hsclk: u32,
}

/// Integer form of icl_calc_mg_pll_state for DP's fixed 8.1 GHz DCO.
pub fn pll_state(rate: LinkRate, ref_khz: u32) -> Option<DklPllState> {
    let clock = match rate {
        LinkRate::DpRbr => 162_000,
        LinkRate::DpHbr => 270_000,
        LinkRate::DpHbr2 => 540_000,
        LinkRate::DpHbr3 => 810_000,
        _ => return None,
    };
    let (ndiv, trim) = match ref_khz {
        19_200 => (1, 28),
        24_000 => (1, 25),
        38_400 => (2, 28),
        _ => return None,
    };
    let mut divisors = None;
    for (div1, hs) in [(7, 3), (5, 2), (3, 1), (2, 0)] {
        for div2 in (1..=10).rev() {
            if div1 * div2 * clock * 5 == 8_100_000 {
                divisors = Some((div2, hs));
                break;
            }
        }
        if divisors.is_some() {
            break;
        }
    }
    let (div2, hs) = divisors?;
    let denominator = ref_khz * 2;
    let integer = 8_100_000 / denominator;
    let remainder = 8_100_000 % denominator;
    let fraction = (u64::from(remainder) * (1 << 22) / u64::from(denominator)) as u32;
    let target = (2_000_000_000u64 / (132 * u64::from(ref_khz)) + 5) / 10;
    Some(DklPllState {
        div0: (8 << 16) | (4 << 12) | (2 << 8) | integer,
        div1: (trim << 16) | target as u32,
        ssc: (ndiv << 29) | (4 << 11),
        bias: if fraction != 0 {
            (1 << 30) | (fraction << 8)
        } else {
            0
        },
        tdc: if remainder != 0 {
            200_000_000 / 2_430_000
        } else {
            0
        },
        core: (if div2 >= 2 { 10 } else { 5 }) << 8,
        hsclk: (if div2 >= 2 { 1 << 14 } else { 0 }) | (hs << 12) | (div2 << 8),
    })
}

/// One source-qualified TC PHY. The display's port owner must retain TC
/// power/ownership around its use; every operation checks current MMIO
/// authority and the exact family captured at creation.
#[derive(Copy, Clone, Debug)]
pub struct DklPort {
    pub ddi: Ddi,
    pub tc: u8,
    family: Gen12Platform,
}

impl DklPort {
    pub fn new(io: &(impl MmioWindow + ?Sized), ddi: Ddi) -> Result<Self, ModesetError> {
        let family = io
            .gen12_display_family()
            .ok_or(ModesetError::UnsupportedGeneration)?;
        let tc = (ddi as u8)
            .checked_sub(3)
            .ok_or(ModesetError::UnsupportedGeneration)?;
        let count = match family {
            Gen12Platform::TigerLake => 6,
            Gen12Platform::AlderLakeP => 4,
            _ => return Err(ModesetError::UnsupportedGeneration),
        };
        if tc >= count {
            return Err(ModesetError::UnsupportedGeneration);
        }
        Ok(Self { ddi, tc, family })
    }

    fn check(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
        if io.gen12_display_family() != Some(self.family) || !io.display_access_ok() {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        Ok(())
    }

    fn read(self, io: &(impl MmioWindow + ?Sized), off: u64) -> Result<u32, ModesetError> {
        self.check(io)?;
        let value = io.read32(off);
        if value == u32::MAX {
            return Err(ModesetError::PhyBusFailure);
        }
        self.check(io)?;
        Ok(value)
    }

    fn rmw(
        self,
        io: &(impl MmioWindow + ?Sized),
        off: u64,
        clear: u32,
        set: u32,
    ) -> Result<(), ModesetError> {
        let old = self.read(io, off)?;
        io.write32(off, (old & !clear) | set);
        compiler_fence(Ordering::SeqCst);
        self.check(io)
    }

    fn reg(
        self,
        io: &(impl MmioWindow + ?Sized),
        address: u32,
        clear: u32,
        set: u32,
    ) -> Result<(), ModesetError> {
        let _hip = HIP.try_lock().ok_or(ModesetError::PhyBusFailure)?;
        self.check(io)?;
        io.write32(
            0x1010A0 + u64::from(self.tc / 4) * 4,
            (address >> 12) << (8 * (self.tc % 4)),
        );
        compiler_fence(Ordering::SeqCst);
        self.rmw(
            io,
            0x168000 + u64::from(self.tc) * 0x1000 + u64::from(address & 0xFFF),
            clear,
            set,
        )
    }

    pub fn pll_enable_register(self) -> u64 {
        match self.family {
            Gen12Platform::AlderLakeP => 0x46038 + u64::from(self.tc) * 8,
            _ => 0x46030 + u64::from(self.tc) * 4,
        }
    }

    fn fia(self, io: &(impl MmioWindow + ?Sized)) -> Result<(u64, u8), ModesetError> {
        let modular =
            self.family == Gen12Platform::AlderLakeP || self.read(io, 0x1638A0)? & (1 << 4) != 0;
        let (fia, idx) = if modular {
            (self.tc / 2, self.tc % 2)
        } else {
            (0, self.tc)
        };
        Ok(([0x163000, 0x16E000, 0x16F000][fia as usize], idx))
    }

    /// Begin a DP-alt session before the first AUX access. Cold references
    /// are counted per physical BAR and retained on an uncertain failure.
    pub fn connect(
        self,
        io: &(impl MmioWindow + ?Sized),
        bar: u64,
        width: u8,
    ) -> Result<(), ModesetError> {
        if !matches!(width, 1 | 2 | 4) {
            return Err(ModesetError::PhyBusFailure);
        }
        self.check(io)?;
        let mut cold = COLD.try_lock().ok_or(ModesetError::PhyBusFailure)?;
        let pos = match cold.iter().position(|owner| owner.bar == bar) {
            Some(pos) => pos,
            None => {
                cold.push(ColdOwner {
                    bar,
                    ports: 0,
                    aux_owned: 0,
                });
                cold.len() - 1
            }
        };
        let bit = 1 << self.tc;
        if cold[pos].ports & bit != 0 {
            return Err(ModesetError::PhyBusFailure);
        }
        let first = cold[pos].ports == 0;
        cold[pos].ports |= bit;
        if first {
            let reply = crate::intel_gpu_pcode::pcode_read(io, 0x26, 0, 0, 0, 0)
                .map_err(|_| ModesetError::PowerWellTimeout)?;
            if reply.0 & 1 != 0 {
                return Err(ModesetError::PowerWellTimeout);
            }
        }
        // From here on, any failure retains a cold reference. Reuse is
        // refused until the owner has proved a local stop and disconnected.
        cold[pos].ports |= bit;
        let aux_idx = 3 + u32::from(self.tc);
        let aux_request = 2 << (aux_idx * 2);
        if self.read(io, 0x45444)? & aux_request == 0 {
            cold[pos].aux_owned |= bit;
            self.rmw(io, 0x45444, 0, aux_request)?;
        }
        self.wait(io, 0x45444, 1 << (aux_idx * 2), true)?;
        let (fia, idx) = self.fia(io)?;
        if self.family == Gen12Platform::TigerLake {
            self.wait_timeout(io, fia + 0x890, 1 << idx, true, 500)?;
            self.rmw(io, fia + 0x894, 0, 1 << idx)?;
            let live = self.read(io, fia + 0x8A0)?;
            let assigned = ((live >> (idx * 8)) & 0xF).count_ones();
            if live & (1 << (idx * 8 + 5)) == 0 || assigned < u32::from(width) {
                return Err(ModesetError::PhyBusFailure);
            }
        } else {
            self.wait_timeout(io, 0x161500 + u64::from(self.tc) * 4, 1 << 2, true, 500)?;
            self.rmw(io, self.ddi.base(), 0, 1 << 6)?;
            let live = self.read(io, 0x44470)?;
            let pin = (self.read(io, fia + 0x880)? >> (idx * 4)) & 15;
            let lanes = match pin {
                3 | 5 => 4,
                4 | 6 => 2,
                _ => 0,
            };
            if live & (1 << (16 + self.tc)) == 0 || lanes < width {
                return Err(ModesetError::PhyBusFailure);
            }
        }
        self.rmw(
            io,
            fia + 0x8C0,
            15 << (idx * 4),
            ((1u32 << width) - 1) << (idx * 4),
        )
    }

    /// Release only after the DDI is observed idle and its PLL is off.
    /// A failed acknowledgement keeps the cold reference and its registry bit.
    pub fn disconnect(self, io: &(impl MmioWindow + ?Sized), bar: u64) -> Result<(), ModesetError> {
        if self.read(io, self.ddi.base())? & ((1 << 31) | (1 << 7)) != 1 << 7
            || self.read(io, self.pll_enable_register())? & ((1 << 31) | (1 << 30)) != 0
        {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        let mut cold = COLD.try_lock().ok_or(ModesetError::PhyBusFailure)?;
        let pos = cold
            .iter()
            .position(|owner| owner.bar == bar && owner.ports & (1 << self.tc) != 0)
            .ok_or(ModesetError::PipelineStopUnavailable)?;
        if self.family == Gen12Platform::TigerLake {
            let (fia, idx) = self.fia(io)?;
            self.rmw(io, fia + 0x894, 1 << idx, 0)?;
        } else {
            self.rmw(io, self.ddi.base(), 1 << 6, 0)?;
        }
        let aux_idx = 3 + u32::from(self.tc);
        if cold[pos].aux_owned & (1 << self.tc) != 0 {
            self.rmw(io, 0x45444, 2 << (aux_idx * 2), 0)?;
            self.wait(io, 0x45444, 1 << (aux_idx * 2), false)?;
        }
        if cold[pos].ports == 1 << self.tc {
            crate::intel_gpu_pcode::pcode_read(io, 0x26, 0, 0, 1, 0)
                .map_err(|_| ModesetError::PowerWellTimeout)?;
        }
        cold[pos].ports &= !(1 << self.tc);
        cold[pos].aux_owned &= !(1 << self.tc);
        Ok(())
    }

    fn wait(
        self,
        io: &(impl MmioWindow + ?Sized),
        off: u64,
        mask: u32,
        set: bool,
    ) -> Result<(), ModesetError> {
        self.wait_timeout(io, off, mask, set, 1)
    }

    fn wait_timeout(
        self,
        io: &(impl MmioWindow + ?Sized),
        off: u64,
        mask: u32,
        set: bool,
        ms: u64,
    ) -> Result<(), ModesetError> {
        let mut lost = false;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read(io, off) {
                Ok(v) => {
                    if set {
                        v & mask == mask
                    } else {
                        v & mask == 0
                    }
                }
                Err(_) => {
                    lost = true;
                    true
                }
            },
            narf_time::Deadline::after_ms(ms),
        );
        if !done || lost {
            return Err(ModesetError::PllLockTimeout);
        }
        Ok(())
    }

    pub fn enable(
        self,
        io: &(impl MmioWindow + ?Sized),
        rate: LinkRate,
        ref_khz: u32,
    ) -> Result<(), ModesetError> {
        let state = pll_state(rate, ref_khz).ok_or(ModesetError::PllLockTimeout)?;
        let (fia, idx) = self.fia(io)?;
        let owned = if self.family == Gen12Platform::TigerLake {
            self.read(io, fia + 0x894)? & (1 << idx) != 0
        } else {
            self.read(io, self.ddi.base())? & (1 << 6) != 0
        };
        if !owned {
            return Err(ModesetError::PhyBusFailure);
        }
        let off = self.pll_enable_register();
        if self.read(io, off)? & (1 << 31) != 0 {
            self.disable(io)?;
        }
        self.rmw(io, off, 0, 1 << 27)?;
        self.wait(io, off, 1 << 26, true)?;
        for (address, mask, value) in [
            (0x212C, 7 << 8, 1 << 8),
            (0x20D8, 0xFF << 8, state.core),
            (
                0x20D4,
                (1 << 16) | (3 << 14) | (3 << 12) | (15 << 8),
                state.hsclk,
            ),
            (
                0x2200,
                (31 << 16) | (15 << 12) | (15 << 8) | 255,
                state.div0,
            ),
            (0x2204, (31 << 16) | 255, state.div1),
            (
                0x2210,
                (7 << 29) | (255 << 16) | (7 << 11) | (1 << 9),
                state.ssc,
            ),
            (0x2214, (1 << 30) | (0x3FFFFF << 8), state.bias),
            (0x2218, 0xFFFF, state.tdc),
        ] {
            self.reg(io, address, mask, value)?;
        }
        self.rmw(io, off, 0, 1 << 31)?;
        self.wait(io, off, 1 << 30, true)
    }

    pub fn route_clock(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
        self.rmw(
            io,
            0x46100 + u64::from(self.ddi as u8) * 4,
            0xF << 28,
            8 << 28,
        )?;
        self.rmw(io, crate::intel_gpu_pll::DPCLKA_CFGCR0, self.clock_off(), 0)
    }

    pub(crate) fn start_training(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: crate::intel_gpu_pipes::Transcoder,
        rate: LinkRate,
        lanes: u8,
        retune: bool,
    ) -> Result<(), ModesetError> {
        let (clock, select) = self.transcoder_clock(trans)?;
        let tp = trans.base() + 0x540;
        if retune {
            self.rmw(io, self.ddi.base(), 1 << 31, 0)?;
            self.wait_timeout(io, self.ddi.base(), 1 << 7, true, 10)?;
            self.rmw(io, tp, 1 << 31, 0)?;
            self.disable(io)?;
            self.enable(
                io,
                rate,
                crate::intel_gpu_pll::refclk_khz(self.read(io, crate::intel_gpu_pll::DSSM)?),
            )?;
            self.route_clock(io)?;
        }
        self.configure_lanes(io, lanes)?;
        self.signal_levels(io, rate, &[(0, 0); 4])?;
        self.rmw(io, clock, 0xF << 28, select)?;
        self.rmw(
            io,
            tp,
            (7 << 8) | (1 << 7),
            (1 << 31) | (1 << 18) | (1 << 7),
        )?;
        self.rmw(
            io,
            self.ddi.base(),
            7 << 1,
            (1 << 31) | (u32::from(lanes) - 1) << 1,
        )?;
        self.wait_timeout(io, self.ddi.base(), 1 << 7, false, 10)
    }

    pub(crate) fn stop_transport(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: crate::intel_gpu_pipes::Transcoder,
    ) -> Result<(), ModesetError> {
        let (clock, _) = self.transcoder_clock(trans)?;
        self.rmw(io, trans.base() + 0x540, 1 << 31, 0)?;
        self.rmw(io, clock, 0xF << 28, 0)
    }

    fn transcoder_clock(
        self,
        trans: crate::intel_gpu_pipes::Transcoder,
    ) -> Result<(u64, u32), ModesetError> {
        if trans == crate::intel_gpu_pipes::Transcoder::Edp {
            return Err(ModesetError::UnsupportedGeneration);
        }
        // DISPLAY_VER 12 selects the port; display 13 selects the PHY.
        // TC1 is PORT_D on TGL and PHY_F on ADL-P (intel_port_to_phy).
        let select = match self.family {
            Gen12Platform::TigerLake => 4 + self.tc,
            Gen12Platform::AlderLakeP => 6 + self.tc,
            _ => return Err(ModesetError::UnsupportedGeneration),
        };
        Ok((
            0x46140 + u64::from(trans as u8) * 4,
            u32::from(select) << 28,
        ))
    }

    pub(crate) fn training_update(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: crate::intel_gpu_pipes::Transcoder,
        state: &crate::intel_gpu_modeset::training::State,
        change: crate::intel_gpu_modeset::training::Change,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_modeset::training::Change;
        match change {
            Change::Configure => Ok(()),
            Change::Levels if !state.dirty => self.signal_levels(io, state.rate, &state.levels),
            Change::Levels => Ok(()),
            Change::Pattern => {
                if state.pattern == 1 && state.dirty {
                    self.start_training(io, trans, state.rate, state.lanes, true)?;
                }
                self.rmw(
                    io,
                    trans.base() + 0x540,
                    (7 << 8) | (1 << 7),
                    state
                        .pattern_bits()
                        .map_err(|_| ModesetError::PhyBusFailure)?,
                )
            }
        }
    }

    fn clock_off(self) -> u32 {
        1 << if self.tc < 3 {
            self.tc + 12
        } else {
            self.tc - 3 + 21
        }
    }

    pub fn disable(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), ModesetError> {
        if self.read(io, self.ddi.base())? & (1 << 31) != 0 {
            return Err(ModesetError::PipelineStopUnavailable);
        }
        self.rmw(io, crate::intel_gpu_pll::DPCLKA_CFGCR0, 0, self.clock_off())?;
        self.rmw(io, 0x46100 + u64::from(self.ddi as u8) * 4, 0xF << 28, 0)?;
        let off = self.pll_enable_register();
        self.rmw(io, off, 1 << 31, 0)?;
        self.wait(io, off, 1 << 30, false)?;
        self.rmw(io, off, 1 << 27, 0)?;
        self.wait(io, off, 1 << 26, false)
    }

    /// DPPATC + WA_14018221282: masked readback/rewrite on display 12/13.
    pub fn configure_lanes(
        self,
        io: &(impl MmioWindow + ?Sized),
        width: u8,
    ) -> Result<(), ModesetError> {
        if !matches!(width, 1 | 2 | 4) {
            return Err(ModesetError::PhyBusFailure);
        }
        for lane in 0..2 {
            self.reg(
                io,
                lane * 0x1000 + 0xA0,
                0xC0,
                if width == 1 { 1 << 6 } else { 1 << 7 },
            )?;
            self.reg(
                io,
                lane * 0x1000 + 0xA0,
                0xC0,
                if width == 1 { 1 << 6 } else { 1 << 7 },
            )?;
        }
        Ok(())
    }

    pub fn signal_levels(
        self,
        io: &(impl MmioWindow + ?Sized),
        rate: LinkRate,
        levels: &[(u8, u8); 4],
    ) -> Result<(), ModesetError> {
        let high = matches!(rate, LinkRate::DpHbr2 | LinkRate::DpHbr3);
        let de = match (self.family, high) {
            (Gen12Platform::AlderLakeP, true) => [0, 4, 10, 24, 0, 6, 20, 0, 9, 0],
            (Gen12Platform::AlderLakeP, false) => [1, 6, 11, 23, 0, 8, 20, 0, 11, 0],
            (_, true) => [0, 5, 11, 25, 0, 8, 20, 0, 11, 0],
            _ => [0, 5, 11, 24, 0, 8, 20, 0, 11, 0],
        };
        let swing = [7, 5, 2, 0, 5, 2, 0, 2, 0, 0];
        for lane in 0..2 {
            self.reg(io, lane * 0x1000 + 0xD00, u32::MAX, 0)?;
            for tx in 0..2 {
                let (vs, pe) = levels[(lane * 2 + tx) as usize];
                let idx = crate::intel_gpu_xelpg::preset_index(vs, pe);
                self.reg(
                    io,
                    lane * 0x1000 + 0x2C0 + tx * 4,
                    (31 << 13) | (31 << 8) | 7,
                    (de[idx] << 8) | swing[idx],
                )?;
            }
            let mask = (1 << 2)
                | if self.family == Gen12Platform::AlderLakeP {
                    (1 << 12) | 0x78
                } else {
                    0
                };
            let loadgen = if self.family == Gen12Platform::AlderLakeP && rate == LinkRate::DpRbr {
                1 << 12
            } else {
                0
            };
            self.reg(io, lane * 0x1000 + 0x2C8, mask, loadgen)?;
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Model {
        family: Gen12Platform,
        regs: RefCell<BTreeMap<u64, u32>>,
        phy: RefCell<BTreeMap<(u64, u32), u32>>,
        hip: Cell<u32>,
        writes: RefCell<Vec<(u64, u32)>>,
        lost: Cell<bool>,
        no_lock: Cell<bool>,
    }
    impl Model {
        fn new(family: Gen12Platform) -> Self {
            Self {
                family,
                regs: Default::default(),
                phy: Default::default(),
                hip: Cell::new(0),
                writes: Default::default(),
                lost: Cell::new(false),
                no_lock: Cell::new(false),
            }
        }
    }
    impl MmioWindow for Model {
        fn gen12_display_family(&self) -> Option<Gen12Platform> {
            Some(self.family)
        }
        fn display_access_ok(&self) -> bool {
            !self.lost.get()
        }
        fn read32(&self, off: u64) -> u32 {
            if self.lost.get() {
                return u32::MAX;
            }
            let raw = self.regs.borrow().get(&off).copied().unwrap_or(0);
            match off {
                0x138124 | 0x138128 => 0,
                0x1638A0 => 0x3F3F, // modular FIA, two live four-lane DP-alt ports
                0x163890 => 3,
                0x163880 => 0x33, // pin C on TC1/TC2
                0x161500 | 0x161504 => 1 << 2,
                0x44470 => 3 << 16,
                0x64300 | 0x64400 => {
                    (raw & !(1 << 7)) | if raw & (1 << 31) == 0 { 1 << 7 } else { 0 }
                }
                0x45444 => (raw & 0xAAAAAAAA) | ((raw & 0xAAAAAAAA) >> 1),
                0x46030 | 0x46034 | 0x46038 | 0x46040 => {
                    (raw & !((1 << 26) | (1 << 30)))
                        | ((raw & (1 << 27)) >> 1)
                        | if !self.no_lock.get() {
                            (raw & (1 << 31)) >> 1
                        } else {
                            0
                        }
                }
                0x168000..=0x168FFF => self
                    .phy
                    .borrow()
                    .get(&(off, self.hip.get() & 15))
                    .copied()
                    .unwrap_or(0),
                _ => raw,
            }
        }
        fn write32(&self, off: u64, value: u32) {
            self.writes.borrow_mut().push((off, value));
            if off == 0x1010A0 {
                self.hip.set(value);
            }
            if (0x168000..=0x168FFF).contains(&off) {
                self.phy
                    .borrow_mut()
                    .insert((off, self.hip.get() & 15), value);
            } else {
                self.regs.borrow_mut().insert(off, value);
            }
        }
    }

    fn smoke_gen12_tc_dkl_literal_pll_vectors_and_platform_map() -> TestResult {
        for (refclk, div0, div1, bias, ssc) in [
            (19_200, 0x000842D2, 0x001C004F, 0x7C000000, 0x20002000),
            (24_000, 0x000842A8, 0x0019003F, 0x70000000, 0x20002000),
            (38_400, 0x00084269, 0x001C0027, 0x5E000000, 0x40002000),
        ] {
            let state = pll_state(LinkRate::DpHbr2, refclk).unwrap();
            if (
                state.div0,
                state.div1,
                state.bias,
                state.ssc,
                state.hsclk,
                state.core,
                state.tdc,
            ) != (div0, div1, bias, ssc, 0x1100, 0x500, 82)
            {
                return TestResult::Fail("Dekel PLL differs from literal source vectors");
            }
        }
        let tgl = Model::new(Gen12Platform::TigerLake);
        let adlp = Model::new(Gen12Platform::AlderLakeP);
        if DklPort::new(&tgl, Ddi::D).unwrap().pll_enable_register() != 0x46030
            || DklPort::new(&adlp, Ddi::D).unwrap().pll_enable_register() != 0x46038
            || DklPort::new(&adlp, Ddi::G).unwrap().pll_enable_register() != 0x46050
            || DklPort::new(&adlp, Ddi::H).is_ok()
            || DklPort::new(&Model::new(Gen12Platform::AlderLakeS), Ddi::D).is_ok()
        {
            return TestResult::Fail("Dekel port/PLL qualification must be platform-specific");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_tc",
        smoke_gen12_tc_dkl_literal_pll_vectors_and_platform_map
    );

    fn smoke_gen12_tc_dkl_banked_pll_connect_signal_and_disconnect() -> TestResult {
        let io = Model::new(Gen12Platform::TigerLake);
        let port = DklPort::new(&io, Ddi::D).unwrap();
        io.phy.borrow_mut().insert((0x168200, 0), 0xABCD);
        if port.connect(&io, 0xC0DE0000, 2).is_err()
            || port.enable(&io, LinkRate::DpHbr2, 38_400).is_err()
            || port.route_clock(&io).is_err()
            || port.configure_lanes(&io, 2).is_err()
            || port
                .signal_levels(&io, LinkRate::DpHbr2, &[(0, 0); 4])
                .is_err()
        {
            return TestResult::Fail("Dekel connect/PLL/clock/TX sequence");
        }
        if io.phy.borrow().get(&(0x168200, 0)) != Some(&0xABCD)
            || io.phy.borrow().get(&(0x168200, 2)) != Some(&0x84269)
            || io.read32(0x4610C) & (0xF << 28) != 8 << 28
            || io
                .writes
                .borrow()
                .iter()
                .any(|(off, _)| *off == 0x46010 || *off == 0x164000)
        {
            return TestResult::Fail(
                "TC must use banked Dekel PLL and its own clock, preserving combo PLL",
            );
        }
        if port.disable(&io).is_err()
            || port.disconnect(&io, 0xC0DE0000).is_err()
            || io.read32(0x163894) & 1 != 0
            || io.read32(0x45444) & (3 << 6) != 0
        {
            return TestResult::Fail("Dekel stop must release PHY/AUX/cold after idle proof");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_tc",
        smoke_gen12_tc_dkl_banked_pll_connect_signal_and_disconnect
    );

    fn smoke_gen12_tc_dkl_live_or_lost_port_refuses_clock_shutdown() -> TestResult {
        let io = Model::new(Gen12Platform::AlderLakeP);
        let port = DklPort::new(&io, Ddi::D).unwrap();
        io.regs.borrow_mut().insert(0x64300, 1 << 31);
        if port.disable(&io).is_ok() || !io.writes.borrow().is_empty() {
            return TestResult::Fail("live DDI must refuse PLL shutdown before writes");
        }
        io.lost.set(true);
        if port.enable(&io, LinkRate::DpHbr2, 38_400).is_ok() || !io.writes.borrow().is_empty() {
            return TestResult::Fail("lost MMIO authority must prevent PLL programming");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_tc",
        smoke_gen12_tc_dkl_live_or_lost_port_refuses_clock_shutdown
    );

    fn smoke_gen12_tc_cold_reference_survives_other_port_disconnect() -> TestResult {
        let io = Model::new(Gen12Platform::TigerLake);
        let first = DklPort::new(&io, Ddi::D).unwrap();
        let second = DklPort::new(&io, Ddi::E).unwrap();
        let bar = 0xC0DE2000;
        if first.connect(&io, bar, 2).is_err() || second.connect(&io, bar, 2).is_err() {
            return TestResult::Fail("two Type-C ports must share a device cold reference");
        }
        let commands = || {
            io.writes
                .borrow()
                .iter()
                .filter(|(off, value)| *off == 0x138124 && value & 0xFF == 0x26)
                .count()
        };
        if commands() != 1
            || first.disable(&io).is_err()
            || first.disconnect(&io, bar).is_err()
            || commands() != 1
        {
            return TestResult::Fail(
                "first disconnect must preserve the second port's cold reference",
            );
        }
        if second.disable(&io).is_err() || second.disconnect(&io, bar).is_err() || commands() != 2 {
            return TestResult::Fail("last disconnect must release the shared cold reference");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_tc",
        smoke_gen12_tc_cold_reference_survives_other_port_disconnect
    );

    fn smoke_gen12_tc_training_programs_source_before_sink_pattern() -> TestResult {
        use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
        use crate::intel_gpu_modeset::training::{State, TrainingAux};
        use crate::intel_gpu_pipes::Transcoder;
        struct Sink<'a>(&'a Model);
        impl AuxChannel for Sink<'_> {
            fn transact<'a>(
                &mut self,
                request: &AuxRequest<'_>,
                reply: &'a mut [u8],
            ) -> Result<AuxResponse<'a>, AuxError> {
                if request.cmd == AuxCommand::NativeWrite && request.address == 0x102 {
                    let bits = match request.data[0] & 7 {
                        0 => 3,
                        1 => 0,
                        2 => 1,
                        3 => 4,
                        7 => 5,
                        _ => return Err(AuxError::Nacked),
                    };
                    if self.0.read32(0x64300) & (1 << 31) == 0
                        || (self.0.read32(0x61540) >> 8) & 7 != bits
                    {
                        return Err(AuxError::Nacked);
                    }
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
        }
        for (family, clock, drive, bar) in [
            (Gen12Platform::TigerLake, 0x4000_0000, 0x802, 0xC0DE3000),
            (Gen12Platform::AlderLakeP, 0x6000_0000, 0x602, 0xC0DE4000),
        ] {
            let io = Model::new(family);
            let port = DklPort::new(&io, Ddi::D).unwrap();
            if port.connect(&io, bar, 2).is_err()
                || port.enable(&io, LinkRate::DpHbr2, 38_400).is_err()
                || port.route_clock(&io).is_err()
                || port
                    .start_training(&io, Transcoder::B, LinkRate::DpHbr2, 2, false)
                    .is_err()
            {
                return TestResult::Fail("source must enable its DDI before sink CR/EQ");
            }
            if io.read32(0x46144) != clock {
                return TestResult::Fail("source must route the platform's port/PHY clock");
            }
            let mut aux = TrainingAux::new(
                Sink(&io),
                State::new(LinkRate::DpHbr2, 2),
                |state: &State, change| {
                    port.training_update(&io, Transcoder::B, state, change)
                        .map_err(|_| AuxError::Nacked)
                },
            );
            if aux.dpcd_write(0x103, &[0x09, 0]).is_err()
                || io.phy.borrow().get(&(0x1682C0, 0)) != Some(&drive)
            {
                return TestResult::Fail("source drive must follow sink's per-lane request");
            }
            for pattern in [1, 2, 3, 7, 0] {
                if aux.dpcd_write(0x102, &[pattern]).is_err() {
                    return TestResult::Fail("source pattern must precede sink pattern");
                }
            }
            io.write32(0x64300, io.read32(0x64300) & !(1 << 31));
            if port.stop_transport(&io, Transcoder::B).is_err()
                || port.disable(&io).is_err()
                || port.disconnect(&io, bar).is_err()
            {
                return TestResult::Fail("trained source must stop and release");
            }
            if io.read32(0x46144) != 0 {
                return TestResult::Fail("stop must remove the transcoder clock route");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_tc",
        smoke_gen12_tc_training_programs_source_before_sink_pattern
    );
}
