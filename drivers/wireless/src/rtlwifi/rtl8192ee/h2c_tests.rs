// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE H2C/C2H, interrupt profile, DM and card-disable tests
//! (software models only; no device or firmware execution is implied).

use super::{c2h, dm, h2c};
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct State {
    regs: Vec<u8>,
    /// Ordered byte writes (dword writes are logged as one entry each).
    writes: Vec<(u16, u32)>,
    reads: Vec<u16>,
    /// HISR bits that a W1C write clears.
    w1c: bool,
}

#[derive(Clone)]
struct Fake(Arc<IrqSafeSpinLock<State>>);

impl Fake {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(State {
            regs: vec![0; 0x800],
            writes: Vec::new(),
            reads: Vec::new(),
            w1c: true,
        })))
    }
    fn set(&self, reg: u16, value: u8) {
        self.0.lock().regs[usize::from(reg)] = value;
    }
    fn set32(&self, reg: u16, value: u32) {
        let r = usize::from(reg);
        self.0.lock().regs[r..r + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn writes(&self) -> Vec<(u16, u32)> {
        self.0.lock().writes.clone()
    }
}

#[async_trait::async_trait]
impl Io for Fake {
    fn read8(&self, reg: u16) -> Result<u8, FwError> {
        let mut g = self.0.lock();
        g.reads.push(reg);
        Ok(g.regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, FwError> {
        let mut g = self.0.lock();
        g.reads.push(reg);
        let r = usize::from(reg);
        Ok(u32::from_le_bytes([
            g.regs[r],
            g.regs[r + 1],
            g.regs[r + 2],
            g.regs[r + 3],
        ]))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), FwError> {
        let mut g = self.0.lock();
        g.regs[usize::from(reg)] = value;
        g.writes.push((reg, u32::from(value)));
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), FwError> {
        let mut g = self.0.lock();
        let r = usize::from(reg);
        let stored = if g.w1c && (reg == h2c::REG_HISR || reg == h2c::REG_HISRE) {
            u32::from_le_bytes([g.regs[r], g.regs[r + 1], g.regs[r + 2], g.regs[r + 3]]) & !value
        } else {
            value
        };
        g.regs[r..r + 4].copy_from_slice(&stored.to_le_bytes());
        g.writes.push((reg, value));
        Ok(())
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), FwError> {
        for (i, b) in bytes.iter().enumerate() {
            self.write8(reg + i as u16, *b)?;
        }
        Ok(())
    }
    async fn delay_us(&self, _micros: u64) {}
}

/// `_rtl92ee_fill_h2c_command`: 7-byte commands write the extension box
/// first, short ones only the box; `last_hmeboxnum` rotates; the
/// `dot11_psmode != EACTIVE` gate drops without any hardware access.
fn smoke_rtl8192ee_h2c_box_order_rotation_and_ps_gate() -> TestResult {
    let io = Fake::new();
    let mut mb = h2c::Mailbox::default();
    let body = h2c::pwrmode(h2c::PsMode::Active);
    if narf_scheduler::block_on(mb.fill(&io, h2c::H2C_SETPWRMODE, &body)) != Ok(h2c::Sent::Written)
    {
        return TestResult::Fail("7-byte command not written");
    }
    let want: Vec<(u16, u32)> = vec![
        (0x1f0, u32::from(body[3])),
        (0x1f1, u32::from(body[4])),
        (0x1f2, u32::from(body[5])),
        (0x1f3, u32::from(body[6])),
        (0x1d0, 0x20),
        (0x1d1, u32::from(body[0])),
        (0x1d2, u32::from(body[1])),
        (0x1d3, u32::from(body[2])),
    ];
    if io.writes() != want || mb.next_box() != 1 {
        return TestResult::Fail("extension-first byte order or rotation");
    }
    if body != [0, 0x12, 4, 0, 0x0c, 0x40, 0] {
        return TestResult::Fail("ACTIVE pwrmode body");
    }
    if h2c::pwrmode(h2c::PsMode::Dtim) != [1, 0x12, 5, 0, 0, 0x40, 0] {
        return TestResult::Fail("DTIM pwrmode body (reg_max_lps_awakeintvl 5)");
    }
    if narf_scheduler::block_on(mb.fill(&io, h2c::H2C_MSRRPT, &h2c::media_status(true)))
        != Ok(h2c::Sent::Written)
        || io.writes()[8..] != [(0x1d4, 0x01), (0x1d5, 1), (0x1d6, 0), (0x1d7, 0)]
    {
        return TestResult::Fail("3-byte command into box 1");
    }
    let before = io.writes().len();
    mb.ps_active = false;
    if narf_scheduler::block_on(mb.fill(&io, h2c::H2C_RA_MASK, &[0; 7])) != Ok(h2c::Sent::Dropped)
        || io.writes().len() != before
        || mb.next_box() != 2
    {
        return TestResult::Fail("EACTIVE gate must drop without access");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_h2c_box_order_rotation_and_ps_gate
);

/// A busy box (HMETFR bit stays set) times out after 100 checks and poisons
/// the mailbox; a powered-off MAC (`REG_CR == 0xea`) is `RadioOff` with the
/// `SYS_CFG1 + 3 = 0xff` side effect; LPS enter sends only the RPWM.
fn smoke_rtl8192ee_h2c_busy_off_and_lps_order() -> TestResult {
    let io = Fake::new();
    io.set(h2c::REG_HMETFR, 1);
    let mut mb = h2c::Mailbox::default();
    if narf_scheduler::block_on(mb.fill(&io, h2c::H2C_MSRRPT, &[1, 0, 0]))
        != Err(crate::rtlwifi::prepare::Error::CommandTimeout)
        || !mb.failed
    {
        return TestResult::Fail("busy box must time out and poison");
    }
    let reads =
        io.0.lock()
            .reads
            .iter()
            .filter(|r| **r == h2c::REG_HMETFR)
            .count();
    let debug = io.0.lock().reads.iter().filter(|r| **r == 0x130).count();
    if reads != 100 || debug != 99 {
        return TestResult::Fail("HMETFR 1 + 99 re-checks with the 0x130 reads");
    }
    let off = Fake::new();
    off.set(h2c::REG_CR, 0xea);
    off.set(h2c::REG_TXDMA_STATUS, 0xea);
    let mut mb = h2c::Mailbox::default();
    if narf_scheduler::block_on(mb.fill(&off, h2c::H2C_MSRRPT, &[1, 0, 0]))
        != Err(crate::rtlwifi::prepare::Error::RadioOff)
        || off.writes() != [(0xf3, 0xff)]
    {
        return TestResult::Fail("MAC-off box");
    }
    let lps = Fake::new();
    let mut mb = h2c::Mailbox::default();
    if narf_scheduler::block_on(h2c::fwlps_enter(&lps, &mut mb)) != Ok(h2c::Sent::Dropped)
        || lps.writes() != [(h2c::REG_PCIE_HRPWM, 0x80)]
        || mb.ps_active
    {
        return TestResult::Fail("LPS enter: SETPWRMODE dropped, RPWM RF-off with toggle");
    }
    lps.set(h2c::REG_PCIE_HRPWM, 0x80);
    if narf_scheduler::block_on(h2c::fwlps_leave(&lps, &mut mb)) != Ok(h2c::Sent::Written)
        || lps.writes()[1] != (h2c::REG_PCIE_HRPWM, 0x00)
        || lps.writes()[6] != (0x1d0, u32::from(h2c::H2C_SETPWRMODE))
    {
        return TestResult::Fail("LPS leave: RPWM all-on then SETPWRMODE(ACTIVE)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_h2c_busy_off_and_lps_order
);

/// `rtl92ee_update_hal_rate_mask` for 2T2R: MCS0-15 rows per RSSI level and
/// width, NGB/NB/GB/B arfr ids, SGI by width, `!update_bw << 3`, and the
/// full-order rate decode.
fn smoke_rtl8192ee_rate_mask_2t2r_levels_and_rates() -> TestResult {
    let ht = h2c::Peer {
        legacy: 0xfff,
        ht: Some([0xff, 0xff]),
        sgi20: true,
        sgi40: false,
    };
    let m = h2c::rate_mask(&ht, false, 0, false);
    if m != [0, 0x82, 0x08, 0x05, 0xf0, 0xff, 0x0f] {
        return TestResult::Fail("HT20 init mask (0x0ffff005, NB, SGI20)");
    }
    let m40 = h2c::rate_mask(&ht, true, 0, true);
    if m40 != [0, 0x00, 0x01, 0x15, 0xf0, 0xff, 0x0f] {
        return TestResult::Fail("HT40 init mask (0x0ffff015, NGB, no SGI40)");
    }
    if h2c::rate_mask(&ht, true, 1, true)[3..] != [0x00, 0x00, 0x8f, 0x0f] {
        return TestResult::Fail("HIGH level 0x0f8f0000");
    }
    if h2c::rate_mask(&ht, false, 2, true)[3..] != [0x00, 0xf0, 0xff, 0x0f] {
        return TestResult::Fail("MIDDLE level 0x0ffff000");
    }
    let one = h2c::Peer {
        ht: Some([0xff, 0]),
        ..ht
    };
    if h2c::rate_mask(&one, false, 0, true)[3..] != [0x05, 0xf0, 0x0f, 0x00] {
        return TestResult::Fail("1SS peer limits the 2T2R row");
    }
    let g = h2c::Peer {
        legacy: 0xff5,
        ht: None,
        sgi20: true,
        sgi40: true,
    };
    let gm = h2c::rate_mask(&g, false, 0, true);
    if gm[1] != h2c::ARFR_GB || gm[3..] != [0xf5, 0x0f, 0, 0] {
        return TestResult::Fail("G mode: GB, no SGI");
    }
    let b = h2c::Peer { legacy: 0xf, ..g };
    if h2c::rate_mask(&b, false, 0, true)[1] != h2c::ARFR_B
        || h2c::rate_mask(&b, false, 0, true)[3] != 0x0d
    {
        return TestResult::Fail("B mode 0xd");
    }
    if h2c::mask_rates(&m) != Some(0x0fff_f005)
        || h2c::mask_rates(&gm) != Some(0xff5)
        || h2c::mask_rates(&[0, h2c::ARFR_GB, 0, 0, 0x10, 0, 0]).is_some()
        || h2c::mask_rates(&[0, 9, 0, 1, 0, 0, 0]).is_some()
    {
        return TestResult::Fail("mask_rates decode / refusal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_rate_mask_2t2r_levels_and_rates
);

/// `rtl92ee_enable_interrupt` writes only HIMR/HIMRE with the `sw.c` masks;
/// recognition is disable → W1C of the masked HISR/HISRE bits → enable.
fn smoke_rtl8192ee_interrupt_profile_masks_and_w1c() -> TestResult {
    if h2c::IRQ_MASK0 != 0x2000_04ff || h2c::IRQ_MASK1 != 0x100 {
        return TestResult::Fail("sw.c irq_mask values");
    }
    let io = Fake::new();
    if h2c::enable_interrupt(&io).is_err() || io.writes() != [(0xb0, 0x2000_04ff), (0xb8, 0x100)] {
        return TestResult::Fail("enable writes");
    }
    let io = Fake::new();
    io.set32(h2c::REG_HISR, 0x8000_0011);
    io.set32(h2c::REG_HISRE, 0x0000_0301);
    let Ok((a, b)) = h2c::service_interrupt(&io) else {
        return TestResult::Fail("service failed");
    };
    let want = [
        (0xb0, 0),
        (0xb8, 0),
        (0xb4, 0x11),
        (0xbc, 0x100),
        (0xb0, 0x2000_04ff),
        (0xb8, 0x100),
    ];
    if (a, b) != (0x11, 0x100) || io.writes() != want {
        return TestResult::Fail("recognition order / masks");
    }
    let gone = Fake::new();
    gone.set32(h2c::REG_HISR, u32::MAX);
    if h2c::service_interrupt(&gone).is_ok() {
        return TestResult::Fail("all-ones HISR must be terminal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_interrupt_profile_masks_and_w1c
);

/// C2H: V1 TX report fields, RA report rate/collision and its DARFRC pair;
/// a short RA report is truncated.
fn smoke_rtl8192ee_c2h_reports_and_dynamic_arfb() -> TestResult {
    let tx = [c2h::C2H_TX_REPORT, 0, 0x40, 0, 0x05, 0, 0, 0, 0x2c];
    if c2h::parse(&tx)
        != Ok(c2h::Event::TxReport {
            sn: 0x2c,
            st: 0x40,
            retry: 5,
        })
    {
        return TestResult::Fail("V1 TX report");
    }
    let ra = [c2h::C2H_RA_RPT, 0, 0x58, 0, 0, 0x01];
    if c2h::parse(&ra)
        != Ok(c2h::Event::RaReport {
            rate: c2h::DESC_RATEMCS12,
            collision: true,
        })
        || c2h::parse(&ra[..5]).is_ok()
    {
        return TestResult::Fail("RA report decode / truncation");
    }
    if c2h::dynamic_arfb(c2h::DESC_RATEMCS12, true) != (0, 0x0706_0501)
        || c2h::dynamic_arfb(c2h::DESC_RATEMCS8, false) != (0x0808_0000, 0x0b0a_0909)
        || c2h::dynamic_arfb(c2h::DESC_RATEMCS15, false) != (0x0302_0000, 0x0706_0504)
        || c2h::dynamic_arfb(0x0b, true) != (0, 0x0605_0402)
    {
        return TestResult::Fail("dynamic ARFB table");
    }
    let io = Fake::new();
    if c2h::apply_dynamic_arfb(&io, c2h::DESC_RATEMCS13, false).is_err()
        || io.writes() != [(0x430, 0x0502_0000), (0x434, 0x0908_0706)]
    {
        return TestResult::Fail("DARFRC write order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_c2h_reports_and_dynamic_arfb
);

/// `_rtl92ee_dm_ra_state_check` hysteresis and the 8192EE PHY-status PWDB.
fn smoke_rtl8192ee_dm_ra_state_and_pwdb() -> TestResult {
    use crate::rtlwifi::rate_adaptive::{STA_HIGH, STA_INIT, STA_LOW, STA_MIDDLE};
    if dm::ra_state(51, STA_INIT) != Some(STA_HIGH)
        || dm::ra_state(51, STA_MIDDLE).is_some()
        || dm::ra_state(56, STA_MIDDLE) != Some(STA_HIGH)
        || dm::ra_state(25, STA_LOW).is_some()
        || dm::ra_state(26, STA_LOW) != Some(STA_MIDDLE)
        || dm::ra_state(20, STA_HIGH) != Some(STA_LOW)
    {
        return TestResult::Fail("RA state hysteresis");
    }
    // OFDM: (0x8c >> 1 & 0x7f) - 110 = -40 dBm -> 60 %.
    let mut phy = [0u8; 8];
    phy[4] = 0x8c;
    if dm::rx_pwdb(&phy, false, false) != Some(60) {
        return TestResult::Fail("OFDM PWDB");
    }
    // CCK LNA 3, VGA 7: -24 + 16 = -8 dBm -> 92 % -> boosted to 100.
    phy[5] = (3 << 5) | 7;
    if dm::rx_pwdb(&phy, true, false) != Some(100) || dm::rx_pwdb(&phy, true, true) != Some(92) {
        return TestResult::Fail("CCK PWDB / high-power boost");
    }
    // CCK LNA 7, VGA 27: -100 + 16 = -84 -> 16 % (below the +3 band).
    phy[5] = (7 << 5) | 27;
    if dm::rx_pwdb(&phy, true, false) != Some(16) || dm::rx_pwdb(&phy[..5], true, false).is_some() {
        return TestResult::Fail("CCK low PWDB / short status");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192ee",
    smoke_rtl8192ee_dm_ra_state_and_pwdb
);
