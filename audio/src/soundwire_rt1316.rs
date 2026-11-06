//! Realtek RT1316 SoundWire smart amplifier: attach-time init,
//! SDCA power-state amp enable/disable and mute.
//!
//! Grounding: Linux `sound/soc/codecs/rt1316-sdw.c`
//! (`rt1316_io_init`, `rt1316_blind_write`, `rt1316_classd_event`,
//! `rt1316_pde24_event`, `rt1316_read_prop`, `rt1316_sdw_dai`) and
//! `rt1316-sdw.h` (SDCA function/entity/control numbers), plus
//! `include/linux/soundwire/sdw_registers.h` (the `SDW_SDCA_CTL`
//! macro, `SDW_SCP_ADDRPAGE1/2`, `SDW_REG_NO_PAGE` /
//! `SDW_REG_OPTIONAL_PAGE` / `SDW_REG_MAX`),
//! `drivers/soundwire/bus.c` (`sdw_fill_msg` paging rules) and
//! `drivers/soundwire/amd_manager.c` (`amd_program_scp_addr`),
//! torvalds/linux master `f66469d`. Every register address and
//! value below is transcribed from those files; nothing is invented.
//!
//! The amp's audio registers are plain 16-bit SoundWire addresses,
//! but its power/mute controls are SDCA controls with 32-bit
//! addresses, so every access at or above 0x8000 goes out paged:
//! the RT1316 declares `paging_support`, so Linux pages all such
//! accesses (`sdw_fill_msg`: below 0x8000 direct; 0x8000..0xffff
//! paged when the slave supports paging; at or above 0x10000
//! paged mandatorily). A paged transfer programs `SCP_ADDRPAGE1`
//! (address bits [30:23]) and `SCP_ADDRPAGE2` (bits [22:15]) on the
//! same device, then transfers the low 15 bits with bit 15 set
//! (`amd_program_scp_addr`).
//!
//! Boundaries, stated plainly:
//! - The BQ filter parameters (`realtek,bq-params`, applied by
//!   Linux from device-tree/firmware) have no in-tree values and
//!   are not programmed here; the blind-write table is the whole
//!   static init.
//! - The IV-sense channel select (UDMPU cluster control) keeps its
//!   reset default (`L,R`); no caller changes it yet.
//! - SDCA reads are not implemented: every control this module
//!   touches is write-only in the Linux sequences used.

use crate::soundwire::{regs, Bus, SdwError, Transport, BROADCAST_DEV_NUM, MAX_DEV_NUM};

/// SDCA function number for the smart amp (`FUNC_NUM_SMART_AMP`).
const FUNC_SMART_AMP: u32 = 0x04;
/// SDCA entity: power-domain element 23 (`RT1316_SDCA_ENT_PDE23`).
const ENT_PDE23: u32 = 0x31;
/// SDCA entity: power-domain element 27 (`RT1316_SDCA_ENT_PDE27`).
const ENT_PDE27: u32 = 0x32;
/// SDCA entity: power-domain element 22 (`RT1316_SDCA_ENT_PDE22`).
const ENT_PDE22: u32 = 0x33;
/// SDCA entity: power-domain element 24 (`RT1316_SDCA_ENT_PDE24`).
const ENT_PDE24: u32 = 0x34;
/// SDCA entity: extension unit 24 (`RT1316_SDCA_ENT_XU24`).
const ENT_XU24: u32 = 0x24;
/// SDCA entity: function unit 21, the DAC mute/volume
/// (`RT1316_SDCA_ENT_FU21`).
const ENT_FU21: u32 = 0x03;
/// SDCA control: requested power state
/// (`RT1316_SDCA_CTL_REQ_POWER_STATE`).
const CTL_REQ_POWER_STATE: u32 = 0x01;
/// SDCA control: bypass (`RT1316_SDCA_CTL_BYPASS`).
const CTL_BYPASS: u32 = 0x01;
/// SDCA control: function-unit mute (`RT1316_SDCA_CTL_FU_MUTE`).
const CTL_FU_MUTE: u32 = 0x01;
/// SDCA channel: left (`CH_L`).
const CH_L: u32 = 0x01;
/// SDCA channel: right (`CH_R`).
const CH_R: u32 = 0x02;

/// Requested power state: full power (`ps0` in the Linux events).
const POWER_PS0: u8 = 0x0;
/// Requested power state: off (`ps3` in the Linux events).
const POWER_PS3: u8 = 0x3;
/// Function-unit mute value: muted.
const MUTE_ON: u8 = 0x01;
/// Function-unit mute value: unmuted.
const MUTE_OFF: u8 = 0x00;

/// First address that needs paging (`SDW_REG_NO_PAGE`).
const REG_NO_PAGE: u32 = 0x8000;
/// First address above the legal range (`SDW_REG_MAX`).
const REG_MAX: u32 = 0x4800_0000;

/// Encode a SoundWire Device Class (SDCA) control address, the
/// `SDW_SDCA_CTL(fun, ent, ctl, ch)` macro from Linux
/// `include/linux/soundwire/sdw_registers.h`: bit 30 set, function
/// in bits [24:22], entity bit 6 in bit 21, control-selector high
/// bits in [20:19], control-number high bits in [17:15], entity
/// low 6 bits in [12:7], control-selector low 4 bits in [6:3],
/// control-number low 3 bits in [2:0], channel split across
/// bits [17:15] (high) and [2:0] (low).
pub const fn sdca_ctl(func: u32, ent: u32, ctl: u32, ch: u32) -> u32 {
    (1 << 30)
        | ((func & 0x7) << 22)
        | ((ent & 0x40) << 15)
        | ((ent & 0x3f) << 7)
        | ((ctl & 0x30) << 15)
        | ((ctl & 0x0f) << 3)
        | ((ch & 0x38) << 12)
        | (ch & 0x07)
}

/// Write one byte to a paged address (`addr >= 0x8000`): program
/// `SCP_ADDRPAGE1` (address bits [30:23]) and `SCP_ADDRPAGE2`
/// (bits [22:15]) on the same device, then write the low 15 bits
/// with bit 15 set — Linux's `amd_program_scp_addr`. Addresses
/// below 0x8000 never page (use [`Bus::write_reg`] for those) and
/// addresses at or above `SDW_REG_MAX` are illegal; paging the
/// enumeration or broadcast address is rejected, like Linux's
/// `sdw_fill_msg`.
pub fn paged_write<T: Transport>(
    bus: &Bus<T>,
    dev: u8,
    addr: u32,
    value: u8,
) -> Result<(), SdwError> {
    if dev == BROADCAST_DEV_NUM || !(1..=MAX_DEV_NUM).contains(&dev) {
        return Err(SdwError::InvalidDevice);
    }
    if !(REG_NO_PAGE..REG_MAX).contains(&addr) {
        return Err(SdwError::InvalidAddress);
    }
    let page1 = ((addr >> 23) & 0xFF) as u8;
    let page2 = ((addr >> 15) & 0xFF) as u8;
    bus.write_reg(dev, regs::SCP_ADDRPAGE1, page1)?;
    bus.write_reg(dev, regs::SCP_ADDRPAGE2, page2)?;
    bus.write_reg(dev, (addr & 0x7FFF) | 0x8000, value)
}

/// Write one byte to an RT1316 register: plain addresses below
/// 0x8000 go out directly; addresses at or above 0x8000 go out
/// paged (the RT1316 declares paging support, so Linux pages
/// every such access, including plain 16-bit registers, whose
/// pages are both zero).
fn reg_write<T: Transport>(bus: &Bus<T>, dev: u8, addr: u32, value: u8) -> Result<(), SdwError> {
    if addr < REG_NO_PAGE {
        bus.write_reg(dev, addr, value)
    } else {
        paged_write(bus, dev, addr, value)
    }
}

/// The attach-time blind-write table from Linux `rt1316_io_init`
/// (`rt1316_blind_write`), transcribed verbatim in order. The
/// single SDCA entry (XU24 bypass) is encoded with [`sdca_ctl`];
/// the rest are plain 16-bit registers.
pub const BLIND_WRITE: &[(u32, u8)] = &[
    (0xc710, 0x17),
    (0xc711, 0x80),
    (0xc712, 0x26),
    (0xc713, 0x06),
    (0xc714, 0x80),
    (0xc715, 0x06),
    (0xc702, 0x0a),
    (0xc703, 0x0a),
    (0xc001, 0x45),
    (0xc003, 0x00),
    (0xc004, 0x11),
    (0xc005, 0x00),
    (0xc006, 0x00),
    (0xc106, 0x00),
    (0xc007, 0x11),
    (0xc008, 0x11),
    (0xc009, 0x00),
    (0x2f0a, 0x00),
    (0xd101, 0xf0),
    (0xd103, 0x9b),
    (0x2f36, 0x8e),
    (0x3206, 0x80),
    (0x3211, 0x0b),
    (0x3216, 0x06),
    (0xc614, 0x20),
    (0xc615, 0x0a),
    (0xc616, 0x02),
    (0xc617, 0x00),
    (0xc60b, 0x10),
    (0xc60e, 0x05),
    (0xc102, 0x00),
    (0xc090, 0xb0),
    (0xc00f, 0x01),
    (0xc09c, 0x7b),
    (0xc602, 0x07),
    (0xc603, 0x07),
    (0xc0a3, 0x71),
    (0xc00b, 0x30),
    (0xc093, 0x80),
    (0xc09d, 0x80),
    (0xc0b0, 0x77),
    (0xc010, 0xa5),
    (0xc050, 0x83),
    (0x2f55, 0x03),
    (0x3217, 0xb5),
    (0x3202, 0x02),
    (sdca_ctl(FUNC_SMART_AMP, ENT_XU24, CTL_BYPASS, 0), 0x00),
    (0x2232, 0x80),
    (0xc0b0, 0x77),
    (0xc011, 0x00),
    (0xc020, 0x00),
    (0xc023, 0x00),
    (0x3101, 0x00),
    (0x3004, 0xa0),
    (0x3005, 0xb1),
    (0xc007, 0x11),
    (0xc008, 0x11),
    (0xc009, 0x00),
    (0xc022, 0xd6),
    (0xc025, 0xd6),
    (0xd001, 0x03),
    (0xd002, 0xbf),
    (0xd003, 0x03),
    (0xd004, 0xbf),
];

/// Attach-time amp init (`rt1316_io_init`): software reset, then
/// the blind-write table. Runs at attach (Linux `update_status` →
/// `io_init`); the ACP binding calls it for every enumerated
/// RT1316.
pub fn io_init<T: Transport>(bus: &Bus<T>, dev: u8) -> Result<(), SdwError> {
    // Software reset.
    reg_write(bus, dev, 0xc000, 0x02)?;
    // Initial settings - blind write.
    for &(addr, value) in BLIND_WRITE {
        reg_write(bus, dev, addr, value)?;
    }
    Ok(())
}

fn pde_power<T: Transport>(bus: &Bus<T>, dev: u8, ent: u32, state: u8) -> Result<(), SdwError> {
    paged_write(
        bus,
        dev,
        sdca_ctl(FUNC_SMART_AMP, ent, CTL_REQ_POWER_STATE, 0),
        state,
    )
}

fn fu_mute<T: Transport>(bus: &Bus<T>, dev: u8, ch: u32, muted: u8) -> Result<(), SdwError> {
    paged_write(
        bus,
        dev,
        sdca_ctl(FUNC_SMART_AMP, ENT_FU21, CTL_FU_MUTE, ch),
        muted,
    )
}

/// Power the Class-D amp up (`rt1316_classd_event` POST_PMU +
/// `rt1316_pde24_event` POST_PMU): PDE23/27/22 then PDE24 to full
/// power (PS0), then unmute both channels. Power states first,
/// unmute last: no sound leaves the amp before it is powered.
pub fn amp_enable<T: Transport>(bus: &Bus<T>, dev: u8) -> Result<(), SdwError> {
    pde_power(bus, dev, ENT_PDE23, POWER_PS0)?;
    pde_power(bus, dev, ENT_PDE27, POWER_PS0)?;
    pde_power(bus, dev, ENT_PDE22, POWER_PS0)?;
    pde_power(bus, dev, ENT_PDE24, POWER_PS0)?;
    fu_mute(bus, dev, CH_L, MUTE_OFF)?;
    fu_mute(bus, dev, CH_R, MUTE_OFF)
}

/// Power the Class-D amp down (`rt1316_classd_event` PRE_PMD +
/// `rt1316_pde24_event` PRE_PMD): mute both channels first, then
/// PDE23/27/22 and PDE24 to off (PS3).
pub fn amp_disable<T: Transport>(bus: &Bus<T>, dev: u8) -> Result<(), SdwError> {
    fu_mute(bus, dev, CH_L, MUTE_ON)?;
    fu_mute(bus, dev, CH_R, MUTE_ON)?;
    pde_power(bus, dev, ENT_PDE23, POWER_PS3)?;
    pde_power(bus, dev, ENT_PDE27, POWER_PS3)?;
    pde_power(bus, dev, ENT_PDE22, POWER_PS3)?;
    pde_power(bus, dev, ENT_PDE24, POWER_PS3)
}

/// Set the DAC mute on both channels (`rt1316_sto_dac` switch):
/// the same SDCA function-unit mute controls the DAPM "DAC" switch
/// drives, without touching the power states.
pub fn set_mute<T: Transport>(bus: &Bus<T>, dev: u8, muted: bool) -> Result<(), SdwError> {
    let value = if muted { MUTE_ON } else { MUTE_OFF };
    fu_mute(bus, dev, CH_L, value)?;
    fu_mute(bus, dev, CH_R, value)
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    /// One transfer on the model bus, recorded for framing assertions.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct Xfer {
        dev: u8,
        addr: u32,
        write: Option<u8>,
    }

    fn w(dev: u8, addr: u32, value: u8) -> Xfer {
        Xfer {
            dev,
            addr,
            write: Some(value),
        }
    }

    /// A modelled RT1316: plain registers in a map; every write is
    /// logged. Reads return the stored byte or zero. The model does
    /// not interpret paging — the test asserts the page-register
    /// writes appear in the log, exactly as the bus conversation
    /// requires.
    #[derive(Debug)]
    struct FakeTransport {
        regs: IrqSafeSpinLock<BTreeMap<u32, u8>>,
        log: IrqSafeSpinLock<Vec<Xfer>>,
    }

    impl FakeTransport {
        fn new() -> Self {
            Self {
                regs: IrqSafeSpinLock::new(BTreeMap::new()),
                log: IrqSafeSpinLock::new(Vec::new()),
            }
        }
        fn log(&self) -> Vec<Xfer> {
            self.log.lock().clone()
        }
    }

    impl Transport for FakeTransport {
        fn xfer(&self, dev: u8, addr: u32, write: Option<u8>) -> Result<Option<u8>, SdwError> {
            {
                let mut log = self.log.lock();
                if log.len() < 4096 {
                    log.push(Xfer { dev, addr, write });
                }
            }
            match write {
                Some(value) => {
                    self.regs.lock().insert(addr, value);
                    Ok(None)
                }
                None => Ok(Some(self.regs.lock().get(&addr).copied().unwrap_or(0))),
            }
        }
        fn bus_reset(&self) -> Result<(), SdwError> {
            Ok(())
        }
        fn frame_shape(&self) -> (u32, u32) {
            (50, 10)
        }
    }

    fn sdca_ctl_addresses() -> TestResult {
        // The `SDW_SDCA_CTL` macro, evaluated by hand for each
        // control this module drives: bit 30 set, function 0x04 in
        // bits [24:22], entity in [12:7], control in [6:3].
        if sdca_ctl(FUNC_SMART_AMP, ENT_PDE23, CTL_REQ_POWER_STATE, 0) != 0x4100_1888
            || sdca_ctl(FUNC_SMART_AMP, ENT_PDE27, CTL_REQ_POWER_STATE, 0) != 0x4100_1908
            || sdca_ctl(FUNC_SMART_AMP, ENT_PDE22, CTL_REQ_POWER_STATE, 0) != 0x4100_1988
            || sdca_ctl(FUNC_SMART_AMP, ENT_PDE24, CTL_REQ_POWER_STATE, 0) != 0x4100_1a08
            || sdca_ctl(FUNC_SMART_AMP, ENT_FU21, CTL_FU_MUTE, CH_L) != 0x4100_0189
            || sdca_ctl(FUNC_SMART_AMP, ENT_FU21, CTL_FU_MUTE, CH_R) != 0x4100_018a
            || sdca_ctl(FUNC_SMART_AMP, ENT_XU24, CTL_BYPASS, 0) != 0x4100_1208
        {
            return TestResult::Fail("SDCA control address mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt1316", sdca_ctl_addresses);

    fn paged_write_framing() -> TestResult {
        let bus = Bus::new(FakeTransport::new());
        // An SDCA address pages as ADDRPAGE1 (bits [30:23]),
        // ADDRPAGE2 (bits [22:15]), then the low 15 bits with
        // bit 15 set.
        if paged_write(&bus, 1, 0x4100_1888, 0x00) != Ok(()) {
            return TestResult::Fail("paged SDCA write failed");
        }
        // A plain register at or above 0x8000 pages too (pages 0,0).
        if paged_write(&bus, 1, 0xc710, 0x17) != Ok(()) {
            return TestResult::Fail("paged plain write failed");
        }
        // The paged path rejects what Linux's `sdw_fill_msg`
        // rejects: below the paging floor, at/above the address
        // ceiling, and the enumeration/broadcast devices.
        if paged_write(&bus, 1, 0x7fff, 0x00) != Err(SdwError::InvalidAddress) {
            return TestResult::Fail("sub-page address must be rejected");
        }
        if paged_write(&bus, 1, 0x4800_0000, 0x00) != Err(SdwError::InvalidAddress) {
            return TestResult::Fail("over-ceiling address must be rejected");
        }
        if paged_write(&bus, 0, 0x4100_1888, 0x00) != Err(SdwError::InvalidDevice) {
            return TestResult::Fail("enumeration device must be rejected");
        }
        if paged_write(&bus, BROADCAST_DEV_NUM, 0x4100_1888, 0x00) != Err(SdwError::InvalidDevice) {
            return TestResult::Fail("broadcast device must be rejected");
        }
        let expected = [
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9888, 0x00),
            w(1, 0x0048, 0x00),
            w(1, 0x0049, 0x00),
            w(1, 0xc710, 0x17),
        ];
        if bus.transport().log() != expected {
            return TestResult::Fail("paged write framing mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt1316", paged_write_framing);

    fn io_init_conversation() -> TestResult {
        let bus = Bus::new(FakeTransport::new());
        if io_init(&bus, 1) != Ok(()) {
            return TestResult::Fail("io_init failed");
        }
        // Final register state, transcribed from the Linux table
        // independently of the implementation's `BLIND_WRITE`:
        // every plain entry holds its table value; the software
        // reset landed at 0xc000; the SDCA XU24 bypass landed at
        // its paged on-wire address 0x9208; the page registers
        // hold the last programmed pages (0,0 — the final entry
        // 0xd004 is a plain paged register).
        let expected_state: &[(u32, u8)] = &[
            (0xc000, 0x02),
            (0xc710, 0x17),
            (0xc711, 0x80),
            (0xc712, 0x26),
            (0xc713, 0x06),
            (0xc714, 0x80),
            (0xc715, 0x06),
            (0xc702, 0x0a),
            (0xc703, 0x0a),
            (0xc001, 0x45),
            (0xc003, 0x00),
            (0xc004, 0x11),
            (0xc005, 0x00),
            (0xc006, 0x00),
            (0xc106, 0x00),
            (0xc007, 0x11),
            (0xc008, 0x11),
            (0xc009, 0x00),
            (0x2f0a, 0x00),
            (0xd101, 0xf0),
            (0xd103, 0x9b),
            (0x2f36, 0x8e),
            (0x3206, 0x80),
            (0x3211, 0x0b),
            (0x3216, 0x06),
            (0xc614, 0x20),
            (0xc615, 0x0a),
            (0xc616, 0x02),
            (0xc617, 0x00),
            (0xc60b, 0x10),
            (0xc60e, 0x05),
            (0xc102, 0x00),
            (0xc090, 0xb0),
            (0xc00f, 0x01),
            (0xc09c, 0x7b),
            (0xc602, 0x07),
            (0xc603, 0x07),
            (0xc0a3, 0x71),
            (0xc00b, 0x30),
            (0xc093, 0x80),
            (0xc09d, 0x80),
            (0xc0b0, 0x77),
            (0xc010, 0xa5),
            (0xc050, 0x83),
            (0x2f55, 0x03),
            (0x3217, 0xb5),
            (0x3202, 0x02),
            (0x9208, 0x00),
            (0x2232, 0x80),
            (0xc011, 0x00),
            (0xc020, 0x00),
            (0xc023, 0x00),
            (0x3101, 0x00),
            (0x3004, 0xa0),
            (0x3005, 0xb1),
            (0xc022, 0xd6),
            (0xc025, 0xd6),
            (0xd001, 0x03),
            (0xd002, 0xbf),
            (0xd003, 0x03),
            (0xd004, 0xbf),
            (0x0048, 0x00),
            (0x0049, 0x00),
        ];
        let regs = bus.transport().regs.lock();
        for &(addr, value) in expected_state {
            if regs.get(&addr).copied().unwrap_or(0xFF) != value {
                return TestResult::Fail("io_init register state mismatch");
            }
        }
        drop(regs);
        // Transfer count, counted by hand from the table: the
        // software reset (3, paged) + 12 direct entries (1 each)
        // + 51 paged plain entries (3 each) + the SDCA entry (3)
        // = 3 + 12 + 153 + 3 = 171.
        let log = bus.transport().log();
        if log.len() != 171 {
            return TestResult::Fail("io_init transfer count mismatch");
        }
        // The SDCA entry's expansion sits at log offset 125: 3
        // (reset) + 51 (first 17 entries, paged) + 41 (next 17:
        // 5 direct + 12 paged) + 30 (next 12: 3 direct + 9 paged).
        if log[125..128] != [w(1, 0x0048, 0x82), w(1, 0x0049, 0x00), w(1, 0x9208, 0x00)] {
            return TestResult::Fail("SDCA entry expansion mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt1316", io_init_conversation);

    fn amp_enable_disable_conversations() -> TestResult {
        let bus = Bus::new(FakeTransport::new());
        if amp_enable(&bus, 1) != Ok(()) {
            return TestResult::Fail("amp_enable failed");
        }
        // Power states first (PDE23/27/22/24 to PS0), unmute last.
        let expected_enable = [
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9888, 0x00),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9908, 0x00),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9988, 0x00),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9a08, 0x00),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x8189, 0x00),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x818a, 0x00),
        ];
        if bus.transport().log() != expected_enable {
            return TestResult::Fail("amp_enable conversation mismatch");
        }
        let bus = Bus::new(FakeTransport::new());
        if amp_disable(&bus, 1) != Ok(()) {
            return TestResult::Fail("amp_disable failed");
        }
        // Mute first, then power states to PS3.
        let expected_disable = [
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x8189, 0x01),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x818a, 0x01),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9888, 0x03),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9908, 0x03),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9988, 0x03),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x9a08, 0x03),
        ];
        if bus.transport().log() != expected_disable {
            return TestResult::Fail("amp_disable conversation mismatch");
        }
        // Mute alone touches only the two function-unit controls.
        let bus = Bus::new(FakeTransport::new());
        if set_mute(&bus, 1, true) != Ok(()) || set_mute(&bus, 1, false) != Ok(()) {
            return TestResult::Fail("set_mute failed");
        }
        let expected_mute = [
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x8189, 0x01),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x818a, 0x01),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x8189, 0x00),
            w(1, 0x0048, 0x82),
            w(1, 0x0049, 0x00),
            w(1, 0x818a, 0x00),
        ];
        if bus.transport().log() != expected_mute {
            return TestResult::Fail("set_mute conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire-rt1316", amp_enable_disable_conversations);
}
