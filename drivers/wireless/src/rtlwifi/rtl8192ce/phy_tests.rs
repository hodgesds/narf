// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE BB/RF, TX power, channel and calibration tests
//! (software models only; no device, RF acceptance or emission measurement
//! is implied).

use super::channel::{self, ChannelType, Operating};
use super::phy::{self, Path};
use super::txpower::{self, Efuse};
use super::version::{RfType, Version};
use super::{init, iqk};
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use crate::rtlwifi::prepare::Error;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

const V88C: u8 = 0x10;
const V92C: u8 = 0x11;
const V88C_UMC_A: u8 = 0x30;
const V92C_UMC_B: u8 = 0x71;

/// BB register file, a two-path RF model behind the LSSI/HSSI ports and an
/// EFUSE byte port.
pub(super) struct State {
    pub regs: Vec<u8>,
    pub rf: [[u32; 64]; 2],
    /// RF writes in order: (path, addr, data).
    pub rf_writes: Vec<(usize, u8, u32)>,
    pub w32: Vec<(u16, u32)>,
    pub w8: Vec<(u16, u8)>,
    pub efuse: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct Fake(pub Arc<IrqSafeSpinLock<State>>);

impl Fake {
    pub fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(State {
            regs: vec![0; 0x1000],
            rf: [[0; 64]; 2],
            rf_writes: Vec::new(),
            w32: Vec::new(),
            w8: Vec::new(),
            efuse: vec![0xff; 512],
        })))
    }
    fn r32(&self, at: u16) -> u32 {
        self.read32(at).unwrap_or(0)
    }
    fn wrote32(&self, at: u16) -> bool {
        self.0.lock().w32.iter().any(|(r, _)| *r == at)
    }
}

fn put32(regs: &mut [u8], at: u16, v: u32) {
    let r = usize::from(at);
    regs[r..r + 4].copy_from_slice(&v.to_le_bytes());
}

fn get32(regs: &[u8], at: u16) -> u32 {
    let r = usize::from(at);
    u32::from_le_bytes([regs[r], regs[r + 1], regs[r + 2], regs[r + 3]])
}

#[async_trait::async_trait]
impl Io for Fake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        Ok(self.0.lock().regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        Ok(get32(&self.0.lock().regs, reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.w8.push((reg, value));
        g.regs[usize::from(reg)] = value;
        if reg == init::REG_EFUSE_CTRL + 3 {
            let addr = usize::from(g.regs[0x31]) | (usize::from(g.regs[0x32] & 3) << 8);
            g.regs[0x30] = g.efuse[addr];
            g.regs[0x33] = value | 0x80;
        }
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        g.regs[r..r + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let prev = get32(&g.regs, reg);
        put32(&mut g.regs, reg, value);
        g.w32.push((reg, value));
        let lssi = match reg {
            phy::RFPGA0_XA_LSSIPARAMETER => Some(0),
            phy::RFPGA0_XB_LSSIPARAMETER => Some(1),
            _ => None,
        };
        if let Some(p) = lssi {
            let addr = ((value >> 20) & 0x3f) as u8;
            g.rf[p][usize::from(addr)] = value & 0xf_ffff;
            g.rf_writes.push((p, addr, value & 0xf_ffff));
        }
        // Path A latches on a rising 0x824 edge; path B on any 0x82c edge.
        let latch = match reg {
            phy::RFPGA0_XA_HSSIPARAMETER2 if prev & phy::BLSSIREADEDGE == 0 => Some(0),
            phy::RFPGA0_XB_HSSIPARAMETER2 => Some(1),
            _ => None,
        };
        if let Some(p) = latch.filter(|_| value & phy::BLSSIREADEDGE != 0) {
            let v = g.rf[p][((value >> 23) & 0x3f) as usize];
            let (rb, pi) = if p == 0 {
                (phy::RFPGA0_XA_LSSIREADBACK, phy::TRANSCEIVEA_HSPI_READBACK)
            } else {
                (phy::RFPGA0_XB_LSSIREADBACK, phy::TRANSCEIVEB_HSPI_READBACK)
            };
            put32(&mut g.regs, rb, v);
            put32(&mut g.regs, pi, v);
        }
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), FwError> {
        Err(FwError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
}

fn ver(raw: u8) -> Version {
    match Version::qualify(raw) {
        Ok(v) => v,
        Err(_) => unreachable!("test version qualifies"),
    }
}

/// LSSI write word (`offset & 0x3f`) and the three-write HSSI read on both
/// paths.
fn smoke_rtl8192ce_rf_serial_read_write_both_paths() -> TestResult {
    let io = Fake::new();
    let r = narf_scheduler::block_on(async {
        phy::set_rf(&io, Path::A, 0x18, phy::RFREG_OFFSET_MASK, 0x1_2c07).await?;
        phy::set_rf(&io, Path::B, 0x18 | 0x40, phy::RFREG_OFFSET_MASK, 0x0_0405).await?;
        phy::set_rf(&io, Path::B, 0x18, 0x3ff, 0x6).await?;
        Ok::<_, Error>((
            phy::get_rf(&io, Path::A, 0x18, phy::RFREG_OFFSET_MASK).await?,
            phy::get_rf(&io, Path::B, 0x18, phy::RFREG_OFFSET_MASK).await?,
        ))
    });
    // 0x58 & 0x3f == 0x18; the masked write keeps bits above [9:0].
    if r != Ok((0x1_2c07, 0x0_0406)) {
        return TestResult::Fail("RF read-back through HSSI/LSSI");
    }
    let g = io.0.lock();
    if g.rf_writes.first() != Some(&(0, 0x18, 0x1_2c07)) {
        return TestResult::Fail("LSSI write word");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_rf_serial_read_write_both_paths
);

/// MAC/BB/RF configuration per RF type: serial byte, PG groups, RF paths
/// walked, UMC fixups, CCK/OFDM on.
fn smoke_rtl8192ce_bb_rf_config_per_rf_type() -> TestResult {
    for raw in [V88C, V92C, V88C_UMC_A, V92C_UMC_B] {
        let v = ver(raw);
        let io = Fake::new();
        let r = narf_scheduler::block_on(phy::configure(&io, v));
        let Ok((report, _)) = r else {
            return TestResult::Fail("configure failed");
        };
        if report.pg.pwrgroup_cnt != 4 {
            return TestResult::Fail("PHY_REG_PG groups");
        }
        let g = io.0.lock();
        let serial = if v.is_92c_serial() {
            g.w8.contains(&(0x14, 0x71)) && !g.w8.contains(&(0x4ca, 0x0a))
        } else {
            g.w8.contains(&(0x4ca, 0x0a)) && !g.w8.contains(&(0x14, 0x71))
        };
        if !serial {
            return TestResult::Fail("rtl92c_phy_mac_config serial byte");
        }
        let b_writes = g.rf_writes.iter().filter(|w| w.0 == 1).count();
        if (b_writes == 0) == v.is_92c_serial() {
            return TestResult::Fail("RF path B walked iff 2T2R");
        }
        let has = |addr: u8, data: u32| g.rf_writes.contains(&(0, addr, data));
        if (raw == V88C_UMC_A) != (has(0x1a, 0x30255) && has(0x1b, 0x50a00)) {
            return TestResult::Fail("UMC A-cut 88C RX gain fixup");
        }
        if (raw == V92C_UMC_B) != (has(0x0c, 0x894ae) && has(0x1f, 0x80201)) {
            return TestResult::Fail("UMC B-cut RF fixups");
        }
        let rfmod = get32(&g.regs, phy::RFPGA0_RFMOD);
        if rfmod & (phy::BCCKEN | phy::BOFDMEN) != phy::BCCKEN | phy::BOFDMEN
            || get32(&g.regs, phy::RFPGA0_ANALOGPARAMETER2) & (1 << 10) == 0
        {
            return TestResult::Fail("CCK/OFDM enable");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_bb_rf_config_per_rf_type
);

fn hwinfo() -> [u8; 128] {
    let mut hw = [0xffu8; 128];
    hw[0x5a..0x60].copy_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
    hw[0x60..0x66].copy_from_slice(&[0x30, 0x31, 0x32, 0x33, 0x34, 0x35]);
    hw[0x66..0x69].copy_from_slice(&[0x21, 0x21, 0x21]);
    hw[0x69..0x6c].copy_from_slice(&[0x0f, 0x0f, 0x0f]);
    hw[0x6c..0x6f].copy_from_slice(&[0x12, 0x12, 0x12]);
    hw[0x79] = 0x00;
    hw
}

/// `_rtl92ce_read_txpower_info_from_hwpg` decode and the RF6052 TXAGC
/// writes for both RF types.
fn smoke_rtl8192ce_txpower_efuse_and_txagc() -> TestResult {
    let e = match Efuse::from_hwinfo(&hwinfo()) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("decode"),
    };
    if e.cck[0][0] != 0x20
        || e.cck[0][5] != 0x21
        || e.cck[1][13] != 0x25
        || e.ht40_2s[0][0] != 0x2f
        || e.ht40_2s[1][0] != 0x31
        || e.ht20_diff[0][0] != 0xff
        || e.ht20_diff[1][0] != 0
        || e.legacy_ht_diff[0][0] != 2
        || e.thermal != txpower::EEPROM_DEFAULT_THERMALMETER
        || e.pwrgroup_ht20[0][0] != 0
    {
        return TestResult::Fail("EFUSE TX-power fields");
    }
    // 2T2R channel 1 at 20 MHz.
    let io = Fake::new();
    if txpower::set_level(&io, &e, RfType::T2R2, 4, 1, false, false).is_err() {
        return TestResult::Fail("set_level 2T");
    }
    let expect: [(u16, u32); 8] = [
        (0xe00, 0x3131_3131),
        (0xe04, 0x3131_3131),
        (0xe10, 0x2e2e_2e2e),
        (0xe1c, 0x2e2e_2e2e),
        (0x830, 0x3232_3232),
        (0x868, 0x3131_3131),
        (0x838, 0x2323_2300),
        (0x86c, 0x0020_2023),
    ];
    for (at, v) in expect {
        if io.r32(at) != v {
            return TestResult::Fail("2T TXAGC words");
        }
    }
    if io.read8(0xe09) != Ok(0x20) {
        return TestResult::Fail("CCK 1M path A");
    }
    let tail = |io: &Fake, at: u16| io.0.lock().regs[usize::from(at)..usize::from(at) + 3].to_vec();
    if tail(&io, 0xc90) != [0x28, 0x22, 0x1c] || tail(&io, 0xc98) != [0x2b, 0x25, 0x1f] {
        return TestResult::Fail("2T MCS15 tail bytes");
    }
    // 1T1R: OFDM from ht40_1s and the tail after MCS07_MCS04.
    let io = Fake::new();
    if txpower::set_level(&io, &e, RfType::T1R1, 4, 1, true, false).is_err() {
        return TestResult::Fail("set_level 1T");
    }
    if io.r32(0xe00) != 0x3232_3232 || io.r32(0xe14) != 0x3030_3030 {
        return TestResult::Fail("1T TXAGC words at 40 MHz");
    }
    if tail(&io, 0xc90) != [0x2a, 0x24, 0x1e] {
        return TestResult::Fail("1T MCS07 tail bytes");
    }
    // Scanning with regulatory 0: CCK forced to 0x3f.
    let io = Fake::new();
    if txpower::set_cck(&io, &e, [0x10, 0x10], true).is_err() || io.read8(0xe09) != Ok(0x3f) {
        return TestResult::Fail("scan CCK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_txpower_efuse_and_txagc
);

/// HT40+ wide channel, bandwidth registers, per-path `RF_CHNLBW` and the
/// UMC B-cut `RF_RX_G1` setting.
fn smoke_rtl8192ce_channel_bw40_and_umc_b_rx_g1() -> TestResult {
    if Operating::new(10, ChannelType::Ht40Plus).is_ok()
        || Operating::new(2, ChannelType::Ht40Minus).is_ok()
        || Operating::new(15, ChannelType::Ht20).is_ok()
    {
        return TestResult::Fail("invalid 40 MHz pair admitted");
    }
    let e = match Efuse::from_hwinfo(&hwinfo()) {
        Ok(e) => e,
        Err(_) => return TestResult::Fail("decode"),
    };
    for raw in [V88C, V92C_UMC_B] {
        let v = ver(raw);
        let io = Fake::new();
        let op = match Operating::new(1, ChannelType::Ht40Plus) {
            Ok(op) => op,
            Err(_) => return TestResult::Fail("HT40+"),
        };
        let mut chnlval = [0x0_0c01, 0x0_0c01];
        if narf_scheduler::block_on(channel::configure(&io, v, &e, 4, &op, &mut chnlval)).is_err() {
            return TestResult::Fail("configure");
        }
        let g = io.0.lock();
        if g.regs[0x603] & phy::BW_OPMODE_20MHZ != 0
            || g.regs[0x442] != 1 << 5
            || get32(&g.regs, 0x818) >> 26 & 3 != 2
            || get32(&g.regs, 0xd00) >> 10 & 3 != 1
            || get32(&g.regs, phy::RFPGA1_RFMOD) & 1 != 1
        {
            return TestResult::Fail("40 MHz BB registers");
        }
        if g.rf[0][0x18] != 0x0_0003 || chnlval[0] != 0x0_0003 {
            return TestResult::Fail("RF A channel 3 at 40 MHz");
        }
        let b = g.rf_writes.iter().any(|w| w.0 == 1);
        if b != v.is_92c_serial() {
            return TestResult::Fail("RF B channel written iff 2T");
        }
        let rx_g1 = g.rf_writes.iter().any(|w| w.0 == 0 && w.1 == 0x1a);
        if rx_g1 != v.is_umc_b_cut() {
            return TestResult::Fail("UMC B-cut RF_RX_G1 rewrite");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_channel_bw40_and_umc_b_rx_g1
);

/// IQK: identical runs pick candidate 0 and fill path A (and path B on
/// 2T2R only); 1T1R never touches path-B calibration registers.
fn smoke_rtl8192ce_iqk_both_rf_types() -> TestResult {
    for raw in [V88C, V92C] {
        let v = ver(raw);
        let io = Fake::new();
        {
            let mut g = io.0.lock();
            put32(&mut g.regs, 0xe94, 0x0100_0000);
            put32(&mut g.regs, 0xe9c, 0x0010_0000);
            put32(&mut g.regs, 0xea4, 0x0110_0000);
            put32(&mut g.regs, 0xeac, 0x0020_0000);
            put32(&mut g.regs, 0xeb4, 0x0100_0000);
            put32(&mut g.regs, 0xebc, 0x0010_0000);
            put32(&mut g.regs, 0xec4, 0x0110_0000);
            put32(&mut g.regs, 0xecc, 0x0020_0000);
            put32(&mut g.regs, iqk::ROFDM0_XATXIQIMBALANCE, 0x4000_0000);
            put32(&mut g.regs, iqk::ROFDM0_XBTXIQIMBALANCE, 0x4000_0000);
            put32(&mut g.regs, 0x85c, 0x1234_5678);
        }
        let Ok(rep) = narf_scheduler::block_on(iqk::calibrate(&io, v)) else {
            return TestResult::Fail("calibrate");
        };
        if rep.candidate != 0 || rep.e94 != 0x100 || rep.result[0][3] != 0x20 {
            return TestResult::Fail("candidate 0");
        }
        if io.r32(iqk::ROFDM0_XATXIQIMBALANCE) & 0x3ff != 0x100
            || io.r32(iqk::ROFDM0_XARXIQIMBALANCE) & 0x3ff != 0x110
        {
            return TestResult::Fail("path A matrix");
        }
        let b_touched = io.wrote32(0xe60) || io.wrote32(iqk::ROFDM0_XBTXIQIMBALANCE);
        if b_touched != v.is_92c_serial() {
            return TestResult::Fail("path B calibrated iff 2T");
        }
        // t = 1 reloads the ADDA backup taken at t = 0.
        if io.r32(0x85c) != 0x1234_5678 {
            return TestResult::Fail("ADDA reload");
        }
        if iqk::recover(&io, &rep).is_err() {
            return TestResult::Fail("recover");
        }
    }
    // Zero RX result on one run selects the other: Linux copies only its
    // TX pair (`j < i * 4 + 2`) into result[3] and reports "not similar".
    let mut r = [[0i64; 8]; 4];
    r[0] = [0x100, 0x10, 0, 0, 0, 0, 0, 0];
    r[1] = [0x100, 0x10, 0x110, 0x3, 0, 0, 0, 0];
    if iqk::simularity_compare(&mut r, 0, 1, false) || r[3][0] != 0x100 || r[3][2] != 0 {
        return TestResult::Fail("zero-RX candidate rule");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_iqk_both_rf_types
);

/// LCK (TX paused, RF A `0x18` BIT(15) pulse), 0x1FA PA-bias rule per RF
/// type and the "under 1.5V" `0x16` writes.
fn smoke_rtl8192ce_lck_and_pa_bias_rule() -> TestResult {
    let io = Fake::new();
    io.0.lock().rf[0][0x18] = 0x0_0c01;
    if narf_scheduler::block_on(phy::lc_calibrate(&io, ver(V92C))).is_err() {
        return TestResult::Fail("lck");
    }
    {
        let g = io.0.lock();
        if !g.w8.contains(&(phy::REG_TXPAUSE, 0xff))
            || g.regs[usize::from(phy::REG_TXPAUSE)] != 0
            || !g.rf_writes.contains(&(0, 0x18, 0x0_8c01))
        {
            return TestResult::Fail("LCK sequence");
        }
    }
    for (raw, flags) in [(V88C, 0x00u8), (V92C, 0x00), (V92C, 0x13)] {
        let v = ver(raw);
        let io = Fake::new();
        io.0.lock().efuse[0x1fa] = flags;
        let r = narf_scheduler::block_on(async {
            let f = init::efuse_read_1byte(&io, init::EFUSE_PA_BIAS)?;
            if f & 1 == 0 {
                phy::set_rf(&io, Path::A, 0x15, 0x0f, 0x05).await?;
            }
            if f & 2 == 0 && v.is_92c_serial() {
                phy::set_rf(&io, Path::B, 0x15, 0x0f, 0x05).await?;
            }
            Ok::<_, Error>(f)
        });
        if r != Ok(flags) {
            return TestResult::Fail("efuse_read_1byte");
        }
        let g = io.0.lock();
        let a = g.rf_writes.iter().any(|w| w.0 == 0 && w.1 == 0x15);
        let b = g.rf_writes.iter().any(|w| w.0 == 1 && w.1 == 0x15);
        if a != (flags & 1 == 0) || b != (flags & 2 == 0 && v.is_92c_serial()) {
            return TestResult::Fail("PA bias per path");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_lck_and_pa_bias_rule
);

/// H2C box layout/rotation, firmware-busy poison, RA mask levels per RF
/// type and the 92C IMR profile.
fn smoke_rtl8192ce_h2c_rate_mask_and_irq_profile() -> TestResult {
    use super::h2c::{self, Mailbox, Peer, WirelessMode};
    let io = Fake::new();
    let mut mb = Mailbox::new();
    let r = narf_scheduler::block_on(async {
        mb.fill(
            &io,
            h2c::H2C_SETPWRMODE,
            &h2c::pwrmode(h2c::FW_PS_DTIM_MODE),
        )
        .await?;
        mb.fill(&io, h2c::H2C_RA_MASK, &[1, 2, 3, 4, 5]).await
    });
    if r != Ok(h2c::Sent::Box(1)) || mb.next_box() != 2 {
        return TestResult::Fail("box rotation");
    }
    {
        let g = io.0.lock();
        if g.regs[0x1d0..0x1d4] != [1, 3, 1, 5] {
            return TestResult::Fail("3-byte SETPWRMODE box");
        }
        if g.regs[0x1d4..0x1d8] != [0x86, 3, 4, 5] || g.regs[0x8a..0x8c] != [1, 2] {
            return TestResult::Fail("5-byte box + extension");
        }
    }
    io.0.lock().regs[usize::from(h2c::REG_HMETFR)] = 1 << 2;
    let r = narf_scheduler::block_on(mb.fill(&io, h2c::H2C_JOINBSSRPT, &h2c::joinbss(1)));
    if r.is_ok() || !mb.failed {
        return TestResult::Fail("undrained box poisons");
    }
    let n = Peer {
        mode: WirelessMode::N24,
        supp_rates: 0xfff,
        rx_mask: [0xff, 0xff],
        sgi20: true,
        sgi40: false,
    };
    let m = h2c::rate_mask(&n, RfType::T2R2, false, 3);
    if u32::from_le_bytes([m[0], m[1], m[2], m[3]]) != 0x0f0f_f005 || m[4] != 0xa0 {
        return TestResult::Fail("2T N20 mask + SGI20");
    }
    let m = h2c::rate_mask(&n, RfType::T1R1, true, 1);
    if u32::from_le_bytes([m[0], m[1], m[2], m[3]]) != 0x000f_0000 || m[4] != 0x80 {
        return TestResult::Fail("1T N40 low level, no SGI40");
    }
    let io = Fake::new();
    put32(&mut io.0.lock().regs, h2c::REG_HISR, 0xffff_ffff);
    if h2c::enable_interrupt(&io).is_err()
        || io.r32(h2c::REG_HIMR) != 0x1b5f
        || io.r32(h2c::REG_HIMRE) != 0x300
        || h2c::recognize(&io) != Ok(0x1b5f)
        || h2c::disable_interrupt(&io).is_err()
        || io.r32(h2c::REG_HIMR) != 0
    {
        return TestResult::Fail("92C IMR profile");
    }
    if crate::rtlwifi::irq::imr_pair(0x8176) != (0x120, 0x128)
        || crate::rtlwifi::irq::imr_pair(0x8179) != (0xb0, 0xb8)
    {
        return TestResult::Fail("probe IMR pair per chip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ce",
    smoke_rtl8192ce_h2c_rate_mask_and_irq_profile
);
