//! Chip/cut-specific PCIe power lifecycle, ported from Linux rtw88/mac.c.
//! The command data in power_tables comes from each chip's actual
//! card-enable/card-disable flows, rather than a cross-chip reset guess.

use super::power_tables::*;
use super::regs::*;
use narf_bus::MmioRegion;
use narf_time::Deadline;

pub const REGISTER_WINDOW_MIN: u64 = 0x1104;
const SYS_CFG1: u64 = 0xf0;
const RPWM: u64 = 0x3d9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerError {
    Timeout,
    DeviceGone,
    UnsupportedChip,
    UnknownCut,
    BadCommand,
    StateReadback,
    Access,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Command {
    pub offset: u16,
    pub cut: u8,
    pub op: u8,
    pub mask: u8,
    pub value: u8,
}

pub(super) trait Io {
    fn permission(&mut self) -> bool {
        true
    }
    fn read8(&mut self, addr: u64) -> u8;
    fn write8(&mut self, addr: u64, value: u8);
    fn read16(&mut self, addr: u64) -> u16;
    fn read32(&mut self, addr: u64) -> u32;
    fn write32(&mut self, addr: u64, value: u32);
    fn delay_us(&mut self, us: u64) {
        narf_scheduler::responsive_spin_until(|| false, Deadline::after_us(us));
    }
    fn poll8(&mut self, addr: u64, mask: u8, target: u8) -> bool {
        narf_scheduler::responsive_spin_until(
            || self.read8(addr) & mask == target & mask,
            Deadline::after_ms(1000),
        )
    }
}
struct Mmio<'a>(&'a MmioRegion);
impl Io for Mmio<'_> {
    fn read8(&mut self, a: u64) -> u8 {
        // SAFETY: power_on's exclusive BAR2 contract.
        unsafe { self.0.read8(a) }
    }
    fn write8(&mut self, a: u64, v: u8) {
        // SAFETY: same; Linux command offset or known control.
        unsafe { self.0.write8(a, v) }
    }
    fn read16(&mut self, a: u64) -> u16 {
        // SAFETY: same.
        unsafe { self.0.read16(a) }
    }
    fn read32(&mut self, a: u64) -> u32 {
        // SAFETY: same.
        unsafe { self.0.read32(a) }
    }
    fn write32(&mut self, a: u64, v: u32) {
        // SAFETY: same.
        unsafe { self.0.write32(a, v) }
    }
}

fn commands(io: &mut impl Io, cut: u8, rows: &[Command]) -> Result<(), PowerError> {
    for row in rows {
        if !io.permission() {
            return Err(PowerError::Access);
        }
        if row.op == 4 {
            return Ok(());
        }
        if row.cut & cut == 0 {
            continue;
        }
        let addr = row.offset as u64;
        match row.op {
            0 => {}
            1 => {
                let value = io.read8(addr);
                io.write8(addr, (value & !row.mask) | (row.value & row.mask));
            }
            2 => {
                if !io.poll8(addr, row.mask, row.value) {
                    if !io.permission() {
                        return Err(PowerError::Access);
                    }
                    // Linux retries PCI polling after toggling PFM_WOWL.
                    let value = io.read8(REG_SYS_PW_CTRL);
                    io.write8(REG_SYS_PW_CTRL, value | (1 << 3));
                    io.write8(REG_SYS_PW_CTRL, value & !(1 << 3));
                    if !io.poll8(addr, row.mask, row.value) {
                        if !io.permission() {
                            return Err(PowerError::Access);
                        }
                        return Err(PowerError::Timeout);
                    }
                }
            }
            3 => io.delay_us(addr * if row.value == 0 { 1 } else { 1000 }),
            _ => return Err(PowerError::BadCommand),
        }
        if !io.permission() {
            return Err(PowerError::Access);
        }
    }
    Err(PowerError::BadCommand)
}

fn pre_system(io: &mut impl Io) {
    io.write8(REG_RSV_CTRL, 0);
    for (addr, set, clear) in [
        (0x74, 1 << 8, 0),
        (0x64, (1 << 29) | (1 << 28), 0),
        (0x4c, 0, (1 << 26) | (1 << 25)),
        (0x40, 1 << 2, 0),
    ] {
        let value = io.read32(addr);
        io.write32(addr, (value & !clear) | set);
    }
    let value = io.read8(REG_SYS_FUNC_EN);
    io.write8(REG_SYS_FUNC_EN, value & !3);
    let value = io.read8(0x1f);
    io.write8(0x1f, value & !7);
    let value = io.read32(0xec);
    io.write32(0xec, value & !(7 << 24));
}

fn switch(
    io: &mut impl Io,
    cut: u8,
    first: &[Command],
    second: &[Command],
) -> Result<(), PowerError> {
    let rpwm = io.read8(RPWM);
    if io.read16(REG_MCUFW_CTRL) == 0xc078 {
        io.write8(RPWM, (rpwm ^ 0x80) & 0x80);
    }
    commands(io, cut, first)?;
    commands(io, cut, second)
}

pub(super) fn power_on_with(io: &mut impl Io, did: u16) -> Result<(), PowerError> {
    power_on_mode(io, did, false)
}
/// Operating recovery must observe an actual active-to-off transition. An
/// already-off CR cannot supply that receipt. The caller has proved that
/// the original native DMA/IRQ producers have retired before entering here.
pub(super) fn reset_with(io: &mut impl Io, did: u16) -> Result<(), PowerError> {
    power_on_mode(io, did, true)
}
fn power_on_mode(io: &mut impl Io, did: u16, reset: bool) -> Result<(), PowerError> {
    if !io.permission() {
        return Err(PowerError::Access);
    }
    let (on1, on2, off1, off2, sys_func) = match did {
        RTL_DEV_8821CE => (
            TRANS_CARDDIS_TO_CARDEMU_8821C,
            TRANS_CARDEMU_TO_ACT_8821C,
            TRANS_ACT_TO_CARDEMU_8821C,
            TRANS_CARDEMU_TO_CARDDIS_8821C,
            0xd8,
        ),
        RTL_DEV_8822BE => (
            TRANS_CARDDIS_TO_CARDEMU_8822B,
            TRANS_CARDEMU_TO_ACT_8822B,
            TRANS_ACT_TO_CARDEMU_8822B,
            TRANS_CARDEMU_TO_CARDDIS_8822B,
            0xdc,
        ),
        RTL_DEV_8822CE => (
            TRANS_CARDDIS_TO_CARDEMU_8822C,
            TRANS_CARDEMU_TO_ACT_8822C,
            TRANS_ACT_TO_CARDEMU_8822C,
            TRANS_CARDEMU_TO_CARDDIS_8822C,
            0xd8,
        ),
        _ => return Err(PowerError::UnsupportedChip),
    };
    let cfg = io.read32(SYS_CFG1);
    if cfg == u32::MAX {
        return Err(PowerError::DeviceGone);
    }
    let cut = (cfg >> 12) & 0xf;
    if cut > 6 {
        return Err(PowerError::UnknownCut);
    }
    let cut_mask = 1u8 << (cut + 1);
    if reset && io.read8(REG_CR) == 0xea {
        return Err(PowerError::StateReadback);
    }
    pre_system(io);
    // Linux cycles an already-powered card through the real disable flow
    // before replaying enable; it does not clear arbitrary PMU/CR bytes.
    if reset || io.read8(REG_CR) != 0xea {
        switch(io, cut_mask, off1, off2)?;
        if reset && io.read8(REG_CR) != 0xea {
            return Err(PowerError::StateReadback);
        }
        pre_system(io);
    }
    switch(io, cut_mask, on1, on2)?;
    if reset && matches!(io.read8(REG_CR), 0xea | 0xff) {
        return Err(PowerError::StateReadback);
    }
    let value = io.read32(0x1080);
    io.write32(0x1080, value | (1 << 16) | (1 << 8));
    let value = io.read8(REG_SYS_FUNC_EN + 1);
    io.write8(REG_SYS_FUNC_EN + 1, value | sys_func);
    let value = io.read8(0x1103);
    io.write8(0x1103, (value & 0xf0) | 0x0c);
    let value = io.read32(REG_MCUFW_CTRL);
    if value & (1 << 20) != 0 {
        io.write32(REG_MCUFW_CTRL, value & !(1 << 20));
        let value = io.read32(0x40);
        io.write32(0x40, value & !(1 << 19));
    }
    if !io.permission() {
        return Err(PowerError::Access);
    }
    Ok(())
}

/// Run Linux's chip/cut-filtered PCI power-off/enable and system setup.
///
/// # Safety
/// Caller owns BAR2 exclusively through REGISTER_WINDOW_MIN. The device may
/// reset, so no firmware/packet DMA or interrupt handlers may be active.
pub unsafe fn power_on(mmio: &MmioRegion, did: u16) -> Result<(), PowerError> {
    power_on_with(&mut Mmio(mmio), did)
}
/// Fixed original native source, never a caller-provided validator. Denial
/// sticks for the entire one-shot transition, including source loss in a wait.
pub(super) struct RecoveryIo<'a> {
    mmio: &'a MmioRegion,
    device: &'a narf_bus::BusDevice,
    cap: &'a narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    claim: &'a super::functions::ResetClaim,
    denied: bool,
}
impl RecoveryIo<'_> {
    fn access<T>(&mut self, op: impl FnOnce(&MmioRegion) -> T) -> Option<T> {
        if self.denied {
            return None;
        }
        let result = super::pci_park::invoke(self.cap, || {
            self.claim.current()?;
            let command = narf_bus::pci::read_command(self.cap, self.device).map_err(|_| ())?;
            use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
            if command == u16::MAX
                || command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != MEM_SPACE | INTX_DISABLE
            {
                return Err(());
            }
            Ok(op(self.mmio))
        });
        match result {
            Ok(Ok(value)) => Some(value),
            _ => {
                self.denied = true;
                None
            }
        }
    }
}
impl<'a> RecoveryIo<'a> {
    /// # Safety
    /// Exact exclusively reserved original BAR, following actual retirement.
    pub(super) unsafe fn new(
        mmio: &'a MmioRegion,
        device: &'a narf_bus::BusDevice,
        cap: &'a narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        claim: &'a super::functions::ResetClaim,
    ) -> Self {
        Self {
            mmio,
            device,
            cap,
            claim,
            denied: false,
        }
    }
}
impl super::efuse::EfuseIo for RecoveryIo<'_> {
    fn read8(&mut self, a: u64) -> u8 {
        Io::read8(self, a)
    }
    fn read32(&mut self, a: u64) -> u32 {
        Io::read32(self, a)
    }
    fn write8(&mut self, a: u64, v: u8) {
        Io::write8(self, a, v);
    }
    fn write32(&mut self, a: u64, v: u32) {
        Io::write32(self, a, v);
    }
}
impl Io for RecoveryIo<'_> {
    fn permission(&mut self) -> bool {
        self.access(|_| ()).is_some()
    }
    fn read8(&mut self, a: u64) -> u8 {
        self.access(|mmio| {
            // SAFETY: retained exact-function BAR, native current source inside access.
            unsafe { mmio.read8(a) }
        })
        .unwrap_or(u8::MAX)
    }
    fn read16(&mut self, a: u64) -> u16 {
        self.access(|mmio| {
            // SAFETY: same original bounded BAR and current source.
            unsafe { mmio.read16(a) }
        })
        .unwrap_or(u16::MAX)
    }
    fn read32(&mut self, a: u64) -> u32 {
        self.access(|mmio| {
            // SAFETY: same original bounded BAR and current source.
            unsafe { mmio.read32(a) }
        })
        .unwrap_or(u32::MAX)
    }
    fn write8(&mut self, a: u64, v: u8) {
        self.access(|mmio| {
            // SAFETY: same exclusive original BAR; denied sources never reach write.
            unsafe { mmio.write8(a, v) }
        });
    }
    fn write32(&mut self, a: u64, v: u32) {
        self.access(|mmio| {
            // SAFETY: same exclusive original BAR and current source.
            unsafe { mmio.write32(a, v) }
        });
    }
    fn delay_us(&mut self, us: u64) {
        narf_scheduler::responsive_spin_until(|| !self.permission(), Deadline::after_us(us));
    }
    fn poll8(&mut self, a: u64, mask: u8, target: u8) -> bool {
        let done = narf_scheduler::responsive_spin_until(
            || {
                if !self.permission() {
                    return true;
                }
                self.read8(a) & mask == target & mask
            },
            Deadline::after_ms(1000),
        );
        done && self.permission()
    }
}
#[cfg(feature = "kernel-test")]
#[path = "power_reset_tests.rs"]
pub(super) mod reset_tests;
