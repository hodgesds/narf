// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Checked native BE factory read, retaining the source wire widths/order.
//! No infallible Io adapter or failed-read sentinel is used. Erased EFUSE
//! data words may be all ones; control/readiness words may not.
use super::*;
use crate::rtw89::{cold_8922a::Regs, power};
use alloc::vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Error {
    Io(power::Error),
    Format(BeEfuseError),
    Mac,
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Io(e)
    }
}
impl From<BeEfuseError> for Error {
    fn from(e: BeEfuseError) -> Self {
        Self::Format(e)
    }
}
fn change8(io: &mut impl Regs, a: u32, clear: u8, set: u8) -> Result<(), Error> {
    let old = io.read8(a)?;
    io.write8(a, (old & !clear) | set)?;
    Ok(())
}
fn change16(io: &mut impl Regs, a: u32, clear: u16, set: u16) -> Result<(), Error> {
    let old = io.read16(a)?;
    io.write16(a, (old & !clear) | set)?;
    Ok(())
}
fn change32(io: &mut impl Regs, a: u32, clear: u32, set: u32) -> Result<(), Error> {
    let old = io.read32(a)?;
    io.write32(a, (old & !clear) | set)?;
    Ok(())
}
fn power_cut(io: &mut impl Regs, cav: bool, enable: bool) -> Result<(), Error> {
    if enable {
        change8(io, PMC_DBG_CTRL2, 0, SYSON_DIS_PMCR_BE_WRMSK)?;
        if !cav {
            change16(io, SYS_ISO_CTRL, 0, PWC_EV2EF_S)?;
            io.delay_us(1000)?;
            change16(io, SYS_ISO_CTRL, 0, PWC_EV2EF_B)?;
            change16(io, SYS_ISO_CTRL, ISO_EB2CORE, 0)?;
        }
        change32(io, EFUSE_CTRL_2_V1, 0, EF_BURST)?;
    } else {
        if !cav {
            change16(io, SYS_ISO_CTRL, 0, ISO_EB2CORE)?;
            change16(io, SYS_ISO_CTRL, PWC_EV2EF_B, 0)?;
            io.delay_us(1000)?;
            change16(io, SYS_ISO_CTRL, PWC_EV2EF_S, 0)?;
        }
        change8(io, PMC_DBG_CTRL2, SYSON_DIS_PMCR_BE_WRMSK, 0)?;
        change32(io, EFUSE_CTRL_2_V1, EF_BURST, 0)?;
    }
    Ok(())
}
fn convert(io: &mut impl Regs, idle: bool) -> Result<(), Error> {
    if idle {
        change32(io, WL_BT_PWR_CTRL, 0, BT_DISN_EN)?;
        return Ok(());
    }
    change32(io, WL_BT_PWR_CTRL, BT_DISN_EN, 0)?;
    // Linux warns and continues on power-state timeout; actual access failure
    // still propagates and permanently latches the native register port.
    let mut fault = None;
    let _ = narf_scheduler::responsive_spin_until(
        || match io.read32(IC_PWR_STATE) {
            Ok(v) => v & WHOLE_SYS_PWR_STE_MASK == SYS_ACT << 16,
            Err(e) => {
                fault = Some(e);
                true
            }
        },
        narf_time::Deadline::after_us(5000),
    );
    fault.map_or(Ok(()), |e| Err(e.into()))
}
fn dump(io: &mut impl Regs, cav: bool, address: u32, out: &mut [u8]) -> Result<(), Error> {
    if address % 4 != 0 || out.len() % 4 != 0 {
        return Err(BeEfuseError::Unaligned.into());
    }
    if out.is_empty() {
        return Ok(());
    }
    convert(io, false)?;
    power_cut(io, cav, true)?;
    for (i, word) in out.chunks_exact_mut(4).enumerate() {
        let addr = address
            .checked_add((i * 4) as u32)
            .ok_or(BeEfuseError::Truncated)?;
        if addr & !EF_ADDR_MASK != 0 {
            return Err(BeEfuseError::Truncated.into());
        }
        io.write32(EFUSE_CTRL, addr & EF_ADDR_MASK)?;
        io.poll32(EFUSE_CTRL, EF_RDY, EF_RDY, 1_000_000)?;
        word.copy_from_slice(&io.read32(EFUSE_CTRL_1_V1)?.to_le_bytes());
    }
    power_cut(io, cav, false)?;
    convert(io, true)
}
pub(in crate::rtw89) struct Snapshot {
    pub(in crate::rtw89) factory: BeFactory,
    pub(in crate::rtw89) rf: alloc::vec::Vec<u8>,
    pub(in crate::rtw89) hci: alloc::vec::Vec<u8>,
    pub(in crate::rtw89) calibration: crate::rtw89::factory_be::Calibration,
}
pub(in crate::rtw89) fn read(io: &mut impl Regs, cut: u8) -> Result<BeFactory, Error> {
    read_all(io, cut).map(|snapshot| snapshot.factory)
}
pub(in crate::rtw89) fn read_all(io: &mut impl Regs, cut: u8) -> Result<Snapshot, Error> {
    // mac.c::rtw89_mac_power_switch reads ECV immediately after power-on.
    // efuse_be.c installs a valid ECV in hal.cv; erased ECV leaves the raw
    // SYS_CFG1 cut intact. Later EFUSE power-cut sequencing uses that actual
    // corrected cut, not the earlier value used by pwr_on_func.
    let mut ecv = [0; 4];
    dump(io, cut == 0, FV_OFFSET_BE_V1 & !3, &mut ecv)?;
    let version = (ecv[(FV_OFFSET_BE_V1 & 3) as usize] & CV_MASK) >> 4;
    let cv = (version != CV_INV).then_some(version);
    // efuse_be.c:359 uses the aligned16-bit register, never an unaligned dword.
    let _autoload = io.read16(SYS_WL_EFUSE_CTRL)? & AUTOLOAD_SUS as u16;
    let cav = cv.unwrap_or(cut) == 0;
    let mut physical = vec![0u8; chip_8922a::PHYSICAL_EFUSE_SIZE];
    dump(io, cav, 0, &mut physical)?;
    let mut hci = vec![0u8; 0x4800];
    parse_logical_block(
        &physical,
        &chip_8922a::EFUSE_BLOCKS[2],
        EfuseBlockKind::HciDigPcieSdio,
        chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
        &mut hci,
    )?;
    let mut rf = vec![0u8; 0x240];
    parse_logical_block(
        &physical,
        &chip_8922a::EFUSE_BLOCKS[1],
        EfuseBlockKind::Rf,
        chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
        &mut rf,
    )?;
    let mut mac = [0; 6];
    for (i, word) in mac.chunks_exact_mut(2).enumerate() {
        word.copy_from_slice(&io.read16(MAC_ADDR_PCIE + (i * 2) as u32)?.to_le_bytes())
    }
    if !crate::rtw89::efuse::mac_is_valid(mac) {
        return Err(Error::Mac);
    }
    let mut phycap = [0; chip_8922a::PHYCAP_SIZE];
    dump(io, cav, chip_8922a::PHYCAP_ADDR, &mut phycap)?;
    let mut thermal = [0; 4];
    dump(io, cav, THERMAL_K_OFFSET_BE, &mut thermal)?;
    let raw = u16::from_le_bytes(thermal[..2].try_into().unwrap());
    let thermal_k = if raw & THERMAL_K_VALID != 0 {
        None
    } else {
        let k = (raw & THERMAL_K_VAL) as i16;
        Some(if raw & THERMAL_K_SIGN != 0 { -k } else { k })
    };
    let mut secure_bytes = [0; SEC_BE_SIZE];
    dump(io, cav, SEC_BE_START, &mut secure_bytes)?;
    let selection = u16::from_le_bytes(secure_bytes[2..4].try_into().unwrap());
    let mut secure = SecureInfo {
        secure_boot: false,
        sb_sel_mgn: None,
        mss_dev_type: None,
        mss_cust_idx: 0,
        mss_key_num: 0,
    };
    if selection != SB_CRYP_SEL_DEFAULT {
        if let Some(mgn) = SB_SEL_MGN.get(sb_cryp_sel_idx(selection) as usize) {
            secure.sb_sel_mgn = Some(*mgn);
            if let Ok((kind, cust, key)) = recognize_mss_v1(secure_bytes[0], secure_bytes[1]) {
                secure.mss_dev_type = Some(kind);
                secure.mss_cust_idx = cust;
                secure.mss_key_num = key;
                secure.secure_boot = true;
            }
        }
    }
    let calibration =
        crate::rtw89::factory_be::Calibration::from_logical(&rf).ok_or(BeEfuseError::Truncated)?;
    let factory = BeFactory {
        mac,
        rfe_type: rf[RF_RFE_TYPE_OFF],
        xtal_cap: rf[RF_XTAL_K_OFF],
        country: [rf[RF_COUNTRY_OFF], rf[RF_COUNTRY_OFF + 1]],
        phycap,
        cv,
        thermal_k,
        secure,
    };
    Ok(Snapshot {
        factory,
        rf,
        hci,
        calibration,
    })
}

pub(in crate::rtw89) struct Native<'a> {
    region: &'a MmioRegion,
    cap: &'a Cap<BusDeviceCap, Write>,
    fault: Option<power::Error>,
    cancelled: Option<&'a core::sync::atomic::AtomicBool>,
}
impl<'a> Native<'a> {
    /// # Safety
    /// Exact exclusive RTL8922A BAR/cap after the checked closed power stage;
    /// both BBs/WCPU remain held, MAC0 fully on with packet gates closed, MAC1
    /// fully off. No reset, DMA, firmware or other register producer may race.
    pub(in crate::rtw89) unsafe fn new(
        region: &'a MmioRegion,
        cap: &'a Cap<BusDeviceCap, Write>,
    ) -> Self {
        Self {
            region,
            cap,
            fault: None,
            cancelled: None,
        }
    }
    pub(in crate::rtw89) fn cancel_with(
        mut self,
        flag: &'a core::sync::atomic::AtomicBool,
    ) -> Self {
        self.cancelled = Some(flag);
        self
    }
    fn cancellation(&mut self) -> Result<(), power::Error> {
        if self
            .cancelled
            .is_some_and(|flag| flag.load(core::sync::atomic::Ordering::Acquire))
        {
            return self.latch(Err(power::Error::Access));
        }
        Ok(())
    }
    fn latch<T>(&mut self, result: Result<T, power::Error>) -> Result<T, power::Error> {
        if let Some(e) = self.fault {
            return Err(e);
        }
        if let Err(e) = result {
            self.fault = Some(e)
        }
        result
    }
    fn access<T>(
        &mut self,
        a: u32,
        w: u32,
        write: bool,
        op: impl FnOnce(&MmioRegion, u64) -> T,
    ) -> Result<T, power::Error> {
        self.cancellation()?;
        if let Some(e) = self.fault {
            return Err(e);
        }
        let result = crate::rtw88::pci_park::invoke(self.cap, || {
            let permitted = match w {
                1 => a == PMC_DBG_CTRL2,
                2 => {
                    a == SYS_ISO_CTRL
                        || !write
                            && (a == SYS_WL_EFUSE_CTRL
                                || [MAC_ADDR_PCIE, MAC_ADDR_PCIE + 2, MAC_ADDR_PCIE + 4]
                                    .contains(&a))
                }
                4 => {
                    [EFUSE_CTRL, EFUSE_CTRL_2_V1, WL_BT_PWR_CTRL].contains(&a)
                        || !write
                            && [EFUSE_CTRL_1_V1, IC_PWR_STATE, 0x24, 0x84, 0x88, 0x10000]
                                .contains(&a)
                }
                _ => false,
            };
            if !permitted
                || a & (w - 1) != 0
                || u64::from(a)
                    .checked_add(u64::from(w))
                    .is_none_or(|end| end > self.region.len)
            {
                return Err(power::Error::Access);
            }
            Ok(op(self.region, u64::from(a)))
        })
        .map_err(|_| power::Error::Access)
        .and_then(core::convert::identity);
        self.latch(result)
    }
    fn closed(&mut self) -> Result<(), power::Error> {
        self.current()?;
        if self.read32(0x24)? & 0x1f00_001f != 0x1f00_0000
            || self.read32(0x84)? & 0x0303_0303 != 0x0201_0000
            || self.read32(0x88)? & 0x802 != 0x802
            || self.read32(0x10000)? & 0x3000_0000 != 0
        {
            return self.latch(Err(power::Error::Access));
        }
        Ok(())
    }
}
impl Regs for Native<'_> {
    fn binding(&self) -> crate::rtw89::cold_8922a::Binding {
        crate::rtw89::cold_8922a::Binding::observe(self.region, self.cap)
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.cancellation()?;
        let result =
            crate::rtw88::pci_park::invoke(self.cap, || ()).map_err(|_| power::Error::Access);
        self.latch(result)
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        let result = self
            .access(a, 1, false, |r, o| {
                // SAFETY: current capability, source register, width and extent checked.
                unsafe { r.read8(o) }
            })
            .and_then(|v| (v != u8::MAX).then_some(v).ok_or(power::Error::Gone));
        self.latch(result)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        let result = self.access(a, 2, false, |r, o| {
            // SAFETY: current capability, aligned source word and extent checked.
            unsafe { r.read16(o) }
        });
        let result = result.and_then(|value| {
            if a == SYS_ISO_CTRL && value == u16::MAX {
                Err(power::Error::Gone)
            } else {
                Ok(value)
            }
        });
        self.latch(result)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        let result = self
            .access(a, 4, false, |r, o| {
                // SAFETY: current capability, aligned source register and extent checked.
                unsafe { r.read32(o) }
            })
            .and_then(|v| {
                if a == EFUSE_CTRL_1_V1 || v != u32::MAX {
                    Ok(v)
                } else {
                    Err(power::Error::Gone)
                }
            });
        self.latch(result)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.closed()?;
        self.access(a, 1, true, |r, o| {
            // SAFETY: original current source register, alignment and extent checked.
            unsafe { r.write8(o, v) }
        })?;
        self.closed()
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.closed()?;
        self.access(a, 2, true, |r, o| {
            // SAFETY: original current source word, alignment and extent checked.
            unsafe { r.write16(o, v) }
        })?;
        self.closed()
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.closed()?;
        self.access(a, 4, true, |r, o| {
            // SAFETY: original current source dword, alignment and extent checked.
            unsafe { r.write32(o, v) }
        })?;
        self.closed()
    }
    fn poll32(&mut self, a: u32, m: u32, v: u32, us: u64) -> Result<(), power::Error> {
        self.current()?;
        if m == 0 || v & !m != 0 || !(1..=1_000_000).contains(&us) {
            return self.latch(Err(power::Error::Access));
        }
        let mut error = None;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read32(a) {
                Ok(x) => x & m == v,
                Err(e) => {
                    error = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        let result = error.map_or(
            if done {
                Ok(())
            } else {
                Err(power::Error::Timeout)
            },
            Err,
        );
        self.latch(result)
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.current()?;
        if us > 1000 {
            return self.latch(Err(power::Error::Access));
        }
        let mut error = None;
        let _ = narf_scheduler::responsive_spin_until(
            || match self.current() {
                Ok(()) => false,
                Err(e) => {
                    error = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        error.map_or(Ok(()), Err)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "efuse_be_checked_tests.rs"]
mod tests;
