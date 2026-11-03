//! RTL8723BU identity/EFUSE/power/firmware regressions against a register
//! model. Expectations are taken from Linux `rtl8xxxu/8723b.c` and
//! `core.c`; nothing here is a hardware receipt.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_drivers_usb::device::UsbError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::firmware_transport::{ControlIo, Error, Owner, Stage};
use super::regs::*;
use super::rtl8192e_init::{Queues, Vendor};
use super::rtl8192e_tests::physical_stream;
use super::rtl8723b_init::{parse_efuse, parse_identity, reserved_pages};

const REG_HMBOX_0: u16 = 0x01d0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Op {
    Read(u16, usize),
    Write(u16, Vec<u8>),
}

pub(super) struct Model {
    pub(super) regs: Vec<u8>,
    pub(super) ops: Vec<Op>,
    physical: Vec<u8>,
    fw_bytes: usize,
}

#[derive(Clone)]
pub(super) struct Fake(pub(super) Arc<IrqSafeSpinLock<Model>>);

/// One vendor interface, bulk IN 0x81 plus three bulk OUT endpoints.
fn configuration() -> Vec<u8> {
    let mut bytes = vec![9, 2, 46, 0, 1, 1, 0, 0x80, 250];
    bytes.extend_from_slice(&[9, 4, 0, 0, 4, 0xff, 0xff, 0xff, 0]);
    bytes.extend_from_slice(&[7, 5, 0x81, 2, 0, 2, 0]);
    for ep in 0..3 {
        bytes.extend_from_slice(&[7, 5, 2 + ep, 2, 0, 2, 0]);
    }
    bytes
}

/// A logical WiFi map carrying only `struct rtl8723bu_efuse` facts.
pub(super) fn logical_map() -> [u8; EFUSE_MAP_LEN] {
    let mut map = [0xff; EFUSE_MAP_LEN];
    map[0] = 0x29;
    map[1] = 0x81;
    for path in 0..2 {
        let base = 0x10 + path * 0x2a;
        for i in 0..6 {
            map[base + i] = 0x20 + i as u8 + path as u8;
        }
        for i in 0..5 {
            map[base + 6 + i] = 0x28 + i as u8 + path as u8;
        }
        map[base + 11] = 0xe3; // ofdm diff[0] = 3 (a), ht20 diff[0] = -2 (b)
        map[base + 12] = 0x1f; // ht20 diff[1] = -1, ht40 diff[1] = 1
        map[base + 13] = 0x07; // ofdm diff[1] = 7
        map[base + 14..base + 18].fill(0);
    }
    map[0xb8] = 0x20;
    map[0xb9] = 0xe4; // crystal cap 0x24
    map[0xba] = 0x18;
    map[0xc3] = 0x01;
    map[0x107..0x10d].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x87, 0x23, 0xb0]);
    map
}

impl Fake {
    pub(super) fn new() -> Self {
        let mut regs = vec![0; 0x10000];
        regs[0xfe66] = 0x11; // SIE: high + normal
        regs[0xfe67] = 0x01; // SIE: low
        regs[0x68] = 1 << 2; // MULTI_WIFI_FUNC_EN
        regs[0x6a] = 1 << 2; // MULTI_BT_FUNC_EN (bit 18)
                             // Passing path-A IQK readbacks (8723b.c pass windows): TX
                             // e94 0x100 / e9c 5, RX ea4 0x100 / eac 4.
        regs[0xe94..0xe98].copy_from_slice(&0x0100_0000u32.to_le_bytes());
        regs[0xe9c..0xea0].copy_from_slice(&0x0005_0000u32.to_le_bytes());
        regs[0xea4..0xea8].copy_from_slice(&0x0100_0000u32.to_le_bytes());
        regs[0xeac..0xeb0].copy_from_slice(&0x0004_0000u32.to_le_bytes());
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs,
            ops: Vec::new(),
            physical: physical_stream(&logical_map()),
            fw_bytes: 0,
        })))
    }
    pub(super) fn writes(&self, addr: u16) -> Vec<Vec<u8>> {
        self.0
            .lock()
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Write(a, v) if *a == addr => Some(v.clone()),
                _ => None,
            })
            .collect()
    }
    fn position(&self, op: &Op) -> Option<usize> {
        self.0.lock().ops.iter().position(|o| o == op)
    }
}

#[async_trait::async_trait]
impl ControlIo for Fake {
    fn inert_source_fixture(&self) -> bool {
        true
    }
    fn identity(&self) -> Option<(u16, u16)> {
        Some((0x0bda, 0xb720))
    }
    async fn configuration(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        let config = configuration();
        out[..config.len()].copy_from_slice(&config);
        Ok(config.len())
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        let mut g = self.0.lock();
        g.ops.push(Op::Read(addr, out.len()));
        let a = addr as usize;
        if addr == REG_APS_FSMCO && out.len() == 4 {
            g.regs[a + 1] &= !1; // MAC_ENABLE handshake completes
            g.regs[a + 2] |= 2; // power ready (bit 17) is read-only status
        }
        if addr == REG_MCU_FW_DL && out.len() == 4 {
            if g.regs[a] & MCU_FW_DL_ENABLE == 0 && g.fw_bytes != 0 {
                g.regs[a] |= MCU_FW_DL_CSUM_REPORT;
            }
            if g.regs[a] & MCU_FW_DL_READY != 0 {
                g.regs[a] |= MCU_WINT_INIT_READY as u8;
            }
        }
        if addr == 0x224 && out.len() == 4 {
            g.regs[0x226] &= !1; // auto-LLT completes
        }
        if addr == REG_HMTFR {
            g.regs[a] = 0; // firmware consumed every mailbox
        }
        if addr == 0x0670 && out.len() == 4 {
            g.regs[0x673] &= 0x7f; // CAM invalidate completes
        }
        out.copy_from_slice(&g.regs[a..a + out.len()]);
        Ok(out.len())
    }
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError> {
        let mut g = self.0.lock();
        g.ops.push(Op::Write(addr, data.to_vec()));
        let a = addr as usize;
        g.regs[a..a + data.len()].copy_from_slice(data);
        if (0x1000..0x2000).contains(&addr) {
            g.fw_bytes += data.len();
        }
        if addr == REG_EFUSE_CTRL + 3 && data[0] & 0x80 == 0 {
            let offset = g.regs[0x31] as usize | ((g.regs[0x32] as usize & 3) << 8);
            g.regs[0x30] = g.physical[offset];
            g.regs[0x33] |= 0x80;
        }
        Ok(data.len())
    }
    async fn delay_us(&self, _us: u64) {}
}

/// An 8723B-signed (`0x5301`) image with `payload` bytes.
pub(super) fn image(payload: usize) -> Vec<u8> {
    let mut blob = vec![0u8; 32 + payload];
    blob[0..2].copy_from_slice(&0x5301u16.to_le_bytes());
    blob[4..6].copy_from_slice(&35u16.to_le_bytes());
    blob[12..14].copy_from_slice(&(payload as u16).to_le_bytes());
    for (i, byte) in blob[32..].iter_mut().enumerate() {
        *byte = i as u8;
    }
    blob
}

fn smoke_rtl8723bu_identity_efuse_and_pages() -> TestResult {
    let all = Queues::from_sie(0x0111);
    let multi = (1 << 2) | (1 << 18);
    let id = match parse_identity(0x0004_2000, multi, 0x2000_0000, all) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("8723bu identity rejected"),
    };
    if id.cut != 2
        || id.vendor != Vendor::Smic
        || id.rom_rev != 2
        || !id.has_wifi
        || !id.has_bluetooth
        || id.has_gps
        || id.name() != "8723BU"
    {
        return TestResult::Fail("8723bu identity fields");
    }
    if parse_identity(1 << 23, 0, 0, all) != Err(Error::UnsupportedSilicon)
        || parse_identity(u32::MAX, 0, 0, all) != Err(Error::UnsupportedSilicon)
    {
        return TestResult::Fail("8723bu test-chip handling");
    }
    let map = logical_map();
    let factory = match parse_efuse(id, &map) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("8723bu efuse rejected"),
    };
    let b = factory.power[1];
    if factory.mac != [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xb0]
        || factory.crystal_cap != 0x24
        || factory.channel_plan != 0x20
        || factory.thermal != 0x18
        || factory.bt_setting != 0x01
        || factory.power[0].cck != [0x20, 0x21, 0x22, 0x23, 0x24, 0x25]
        || b.cck[0] != 0x21
        || b.ht40[0] != 0x29
        || b.ofdm_diff != [3, 7, 0, 0]
        || b.ht20_diff != [-2, -1, 0, 0]
        || b.ht40_diff != [0, 1, 0, 0]
    {
        return TestResult::Fail("8723bu efuse fields");
    }
    let mut bad = map;
    bad[0] = 0;
    let mut multicast = map;
    multicast[0x107] = 1;
    if parse_efuse(id, &bad) != Err(Error::BadEfuse)
        || parse_efuse(id, &multicast) != Err(Error::BadEfuse)
    {
        return TestResult::Fail("8723bu efuse ID/MAC validation");
    }
    // pubq = 0xf7 - 0x0c - 2 - 2 - 1 = 0xe6.
    if reserved_pages(all) != (2, 0x80e6_020c) {
        return TestResult::Fail("8723bu reserved pages");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_identity_efuse_and_pages
);

fn smoke_rtl8723bu_power_and_firmware() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8723bu);
    let payload = 4096 + 1500;
    if narf_scheduler::block_on(owner.initialize(&image(payload))).is_err() {
        return TestResult::Fail("8723bu lifecycle failed");
    }
    if owner.status().stage != Stage::RadioReady || owner.status().error.is_some() {
        return TestResult::Fail("8723bu did not reach RadioReady");
    }
    let factory = match owner.factory_8723b() {
        Some(f) => f,
        None => return TestResult::Fail("8723bu factory not retained"),
    };
    if factory.mac != [0x00, 0xe0, 0x4c, 0x87, 0x23, 0xb0]
        || !factory.identity.has_bluetooth
        || owner.queues_8723b().is_none()
        || owner.factory().is_some()
        || owner.factory_8192e().is_some()
    {
        return TestResult::Fail("8723bu retained facts");
    }
    // Multi-function WiFi cell select precedes the EFUSE read gate.
    let select = io.position(&Op::Write(REG_EFUSE_TEST, vec![0, 0, 0, 0]));
    let gate = io.position(&Op::Write(REG_EFUSE_ACCESS, vec![EFUSE_ACCESS_ENABLE]));
    if select.is_none() || gate.is_none() || select > gate {
        return TestResult::Fail("8723bu EFUSE WiFi select order");
    }
    let cr = io.writes(REG_CR);
    let cr = cr
        .iter()
        .find(|v| v.len() == 2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]));
    if cr.map(|v| v & 0x06ff) != Some(0x06ff) {
        return TestResult::Fail("8723bu CR enable set");
    }
    // 0x67 is both BT_GPS_SEL (emu_to_active) and REG_PAD_CTRL1 + 3.
    if io.writes(0x0067).last() != Some(&vec![0x20])
        // The MAC table repeats the BT control / WLAN act bytes and
        // rtl8723bu_init_phy_bb clears the S0S1 switch again.
        || io.writes(0x0765) != vec![vec![0x18]; 2]
        || io.writes(0x076e) != vec![vec![0x04]; 2]
        || io.writes(REG_S0S1_PATH_SWITCH)[..2] != [vec![0, 0, 0, 0], vec![0, 0, 0, 0]]
        || io.writes(0xfe08) != vec![vec![0x01]]
    {
        return TestResult::Fail("8723bu BT-coex power-on settings");
    }
    if io.writes(0x0214) != vec![2u32.to_le_bytes().to_vec()]
        || io.writes(0x0200) != vec![0x80e6_020cu32.to_le_bytes().to_vec()]
        || io.writes(REG_TRXFF_BNDY + 2) != vec![0x3f7fu16.to_le_bytes().to_vec()]
    {
        return TestResult::Fail("8723bu reserved pages / RX boundary");
    }
    let fw: Vec<usize> =
        io.0.lock()
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Write(a, v) if (0x1000..0x2000).contains(a) => Some(v.len()),
                _ => None,
            })
            .collect();
    if fw.iter().sum::<usize>() != payload || fw.iter().any(|&n| n > 1024) || fw[0] != 1024 {
        return TestResult::Fail("8723bu firmware writeN block size");
    }
    // init_reg_hmtfr after start; RSV_CTRL reset sequence used.
    if io.writes(REG_HMTFR) != vec![vec![0x0f]] || io.writes(0x001c).is_empty() {
        return TestResult::Fail("8723bu HMTFR init / reset_8051");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_power_and_firmware
);

fn smoke_rtl8723bu_rejects_mismatched_sie() -> TestResult {
    let io = Fake::new();
    io.0.lock().regs[0xfe67] = 0x00;
    io.0.lock().regs[0xfe66] = 0x00;
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8723bu);
    // No SIE: falls back to the three bulk-OUT endpoints.
    if narf_scheduler::block_on(owner.initialize(&image(64))).is_err() {
        return TestResult::Fail("8723bu no-SIE fallback");
    }
    let io = Fake::new();
    io.0.lock().regs[0xf0..0xf4].copy_from_slice(&(1u32 << 23).to_le_bytes());
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8723bu);
    if narf_scheduler::block_on(owner.initialize(&image(64))) != Err(Error::UnsupportedSilicon) {
        return TestResult::Fail("8723bu test silicon accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_rejects_mismatched_sie
);

fn word(v: &[u8]) -> u32 {
    u32::from_le_bytes(v.try_into().unwrap())
}

fn smoke_rtl8723bu_tables_antenna_and_lck() -> TestResult {
    use super::rtl8723b_tables::{AGC_TABLE, MAC_INIT_TABLE, PHY_INIT_TABLE, RADIO_A_INIT_TABLE};
    // Generated verbatim from 8723b.c (rows + Linux sentinel).
    if MAC_INIT_TABLE.len() != 104
        || PHY_INIT_TABLE.len() != 194
        || AGC_TABLE.len() != 132
        || RADIO_A_INIT_TABLE.len() != 109
    {
        return TestResult::Fail("8723bu table row counts");
    }
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8723bu);
    if narf_scheduler::block_on(owner.initialize(&image(256))).is_err()
        || owner.status().stage != Stage::RadioReady
    {
        return TestResult::Fail("8723bu did not reach RadioReady");
    }
    let rfe = io.writes(0x0930);
    if rfe.len() != 1 || word(&rfe[0]) & 0xff != 0x77 {
        return TestResult::Fail("8723bu antenna selection RFE source");
    }
    let lssi: Vec<u32> = io.writes(0x0840).iter().map(|v| word(v)).collect();
    let rf_rows = RADIO_A_INIT_TABLE
        .iter()
        .filter(|r| !(0xf9..=0xff).contains(&r.reg))
        .count();
    let tail = [
        0xb0 << 20 | 0xdfbe0,
        0x18 << 20 | 0x8c01,
        0xb0 << 20 | 0xdffe0,
    ];
    // + the PHY table's own 0x840 row; LC/IQ calibration follows.
    if lssi.len() <= rf_rows + 4 || lssi[rf_rows + 1..rf_rows + 4] != tail {
        return TestResult::Fail("8723bu RF table + PHY LCK writes");
    }
    if io.writes(0x0860).last().map(|v| word(v)) != Some(0x66f6_0210)
        || io.writes(0x0104) != vec![vec![0x22]]
        || io.writes(0x0424) != vec![vec![0xf8]]
        || io.writes(0x04f0) != vec![0xcdf0u16.to_le_bytes().to_vec()]
        || io.writes(0x0120) != vec![vec![0xff; 4]]
        || io.writes(0x0124) != vec![vec![0xff; 4]]
    {
        return TestResult::Fail("8723bu post-RF MAC/LLT/report/HIMR state");
    }
    // Crystal cap 0x24 into XTAL1/XTAL0 of REG_MAC_PHY_CTRL.
    let xtal = io.writes(0x002c);
    if xtal.len() != 1 || word(&xtal[0]) & 0x00ff_f000 != (0x24 << 18 | 0x24 << 12) {
        return TestResult::Fail("8723bu crystal cap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_tables_antenna_and_lck
);

fn smoke_rtl8723bu_tx_power() -> TestResult {
    use super::rtl8723b_phy::tx_power;
    let id = parse_identity(0, 0, 0, Queues::from_sie(0x0111)).unwrap();
    let factory = parse_efuse(id, &logical_map()).unwrap();
    // Path B, group 0: cck 0x21, ht40 0x29; ofdm +3, ht20 -2, ht40 +0.
    if tx_power(&factory, 1, false) != (0x21, 0x2c2c_2c2c, 0x2727_2727)
        || tx_power(&factory, 1, true) != (0x21, 0x2c2c_2c2c, 0x2929_2929)
        || tx_power(&factory, 13, false).0 != 0x25
    {
        return TestResult::Fail("8723bu tx power indices");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu/8723bu", smoke_rtl8723bu_tx_power);

fn smoke_rtl8723bu_post_tables_and_calibration() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8723bu);
    if narf_scheduler::block_on(owner.initialize(&image(256))).is_err()
        || owner.status().stage != Stage::RadioReady
    {
        return TestResult::Fail("8723bu did not reach RadioReady");
    }
    // rtl8xxxu_init_burst with the 8723bu fops values.
    if io.writes(0x04ca) != vec![0x0c14u16.to_le_bytes().to_vec()]
        || io.writes(0x0456) != vec![vec![0x5e]]
        || io.writes(0x055c) != vec![vec![0x50]]
        || io.writes(0x0638) != vec![vec![0x50]]
        || io.writes(0x0290).last().map(|v| v[0] & 0x3e) != Some(0x1e)
        || io.writes(0x04c7).last().map(|v| v[0] & 0x80) != Some(0x80)
        || io.writes(0x001c).last().map(|v| v[0] & 0x60) != Some(0x60)
    {
        return TestResult::Fail("8723bu init_burst");
    }
    // rtl8723bu_init_aggregation clears RX aggregation.
    if io.writes(0x010c).last().map(|v| v[0] & 0x04) != Some(0)
        || io.writes(0x0280).last().map(|v| word(v) & 0x8000_ff0f) != Some(0)
    {
        return TestResult::Fail("8723bu init_aggregation");
    }
    // DPDT handover to the 8051 and init_statistics.
    if io.writes(0x004e).last().map(|v| v[0] & 0x80) != Some(0x80)
        || io.writes(0x0896) != vec![0x2710u16.to_le_bytes().to_vec()]
        || io.writes(0x0898) != vec![0xffff_ff52u32.to_le_bytes().to_vec()]
        || io.writes(0x0460) != vec![vec![0, 0]]
    {
        return TestResult::Fail("8723bu DPDT / statistics");
    }
    // prepare_calibrate(1) then (0) in consecutive mailboxes.
    if io.writes(REG_HMBOX_0) != vec![vec![0x6d, 1, 0, 0]]
        || io.writes(REG_HMBOX_0 + 4) != vec![vec![0x6d, 0, 0, 0]]
    {
        return TestResult::Fail("8723bu BT/WLAN calibration H2C");
    }
    // BT grant 0x800 during IQK, the saved BT_CONTROL (0x765 = 0x18) last.
    let bt = io.writes(0x0764);
    if !bt.iter().any(|v| word(v) == 0x800) || bt.last().map(|v| word(v)) != Some(0x1800) {
        return TestResult::Fail("8723bu IQK BT control");
    }
    // LC calibration: packet-TX case pauses all queues first.
    let pause = io.writes(0x0522);
    if pause.len() < 2 || pause[0] != vec![0xff] || pause[1] != vec![0x00] {
        return TestResult::Fail("8723bu LC calibration TXPAUSE");
    }
    let lssi: Vec<u32> = io.writes(0x0840).iter().map(|v| word(v)).collect();
    let s0s1 = [0xb0 << 20 | 0xdfbe0, 0xb0 << 20 | 0xdffe0];
    if lssi.iter().filter(|&&v| v == s0s1[0]).count() != 2
        || lssi.iter().filter(|&&v| v == s0s1[1]).count() != 2
        || lssi.last() != Some(&(0x42 << 20 | 0x37cf8))
        || !lssi.contains(&(0x43 << 20 | 0x300bd))
    {
        return TestResult::Fail("8723bu LCK / IQK restore / thermal RF writes");
    }
    let radio = match owner.radio_8723b() {
        Some(r) => r,
        None => return TestResult::Fail("8723bu radio state not retained"),
    };
    if radio.iqk.candidate != 0 || radio.iqk.row[..4] != [0x100, 5, 0x100, 4] {
        return TestResult::Fail("8723bu IQK candidate/row");
    }
    if io.writes(0x0652) != vec![vec![235]] {
        return TestResult::Fail("8723bu NAV upper");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_post_tables_and_calibration
);

fn smoke_rtl8723bu_iqk_failure_is_terminal() -> TestResult {
    use super::rtl8723b_iqk::{choose, rx_ok, tx_ok};
    if !tx_ok(0, 0x0100_0000, 0x0005_0000)
        || tx_ok(1 << 28, 0x0100_0000, 0)
        || tx_ok(0, 0x0142_0000, 0)
        || tx_ok(0, 0x0110_0000, 0)
        || tx_ok(0, 0x0100_0000, 0x03f0_0000) // |-16| >= 0xf
        || !tx_ok(0, 0x0100_0000, 0x03fa_0000) // |-6| < 0xf
        || !rx_ok(0x0004_0000, 0x0100_0000)
        || rx_ok(1 << 27, 0x0100_0000)
        || rx_ok(0, 0x0132_0000)
    {
        return TestResult::Fail("8723bu IQK pass windows");
    }
    // Three dissimilar runs with an empty result[3]: Linux candidate -1.
    let mut result = [[0u32; 8]; 4];
    result[0][0] = 0x100;
    result[1][0] = 0x120;
    result[2][0] = 0x140;
    result[0][1] = 1;
    result[1][1] = 0x20;
    result[2][1] = 0x40;
    if choose(&mut result, 0).is_some() || choose(&mut result, 1).is_some() {
        return TestResult::Fail("8723bu IQK stopped early");
    }
    if choose(&mut result, 2) != Some(None) {
        return TestResult::Fail("8723bu IQK candidate -1");
    }
    let io = Fake::new();
    io.0.lock().regs[0xe94..0xe98].fill(0);
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8723bu);
    if narf_scheduler::block_on(owner.initialize(&image(256))) != Err(Error::Calibration)
        || owner.radio_8723b().is_some()
    {
        return TestResult::Fail("8723bu failed IQK not terminal");
    }
    // Linux's post-IQK restore still ran: calibration-done H2C sent.
    if io.writes(REG_HMBOX_0 + 4) != vec![vec![0x6d, 0, 0, 0]] {
        return TestResult::Fail("8723bu IQK restore skipped on failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_iqk_failure_is_terminal
);

fn ready_owner() -> Option<(Fake, Owner<Fake>)> {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8723bu);
    if narf_scheduler::block_on(owner.initialize(&image(256))).is_err()
        || owner.status().stage != Stage::RadioReady
    {
        return None;
    }
    io.0.lock().ops.clear();
    Some((io, owner))
}

/// Every H2C mailbox word written, in order (mailboxes rotate over 4).
fn h2c_words(io: &Fake) -> Vec<Vec<u8>> {
    io.0.lock()
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Write(a, v) if (REG_HMBOX_0..REG_HMBOX_0 + 16).contains(a) => Some(v.clone()),
            _ => None,
        })
        .collect()
}

fn smoke_rtl8723bu_enable_rf_bt_handover() -> TestResult {
    let Some((io, owner)) = ready_owner() else {
        return TestResult::Fail("8723bu did not reach RadioReady");
    };
    if narf_scheduler::block_on(super::rtl8723b_power::enable_rf(&owner)).is_err() {
        return TestResult::Fail("8723bu enable_rf failed");
    }
    let expected: Vec<Vec<u8>> = vec![
        vec![0x67, 0x00, 0x0d, 0x15],
        vec![0x67, 0x10, 0x0d, 0x00],
        vec![0x6e, 0, 0, 0],
        vec![0x65, 1, 0, 0],
        vec![0x60, 0x08, 0, 0],
        vec![0x61, 1, 0, 0],
        vec![0x63, 0, 0, 0],
    ];
    if h2c_words(&io) != expected {
        return TestResult::Fail("8723bu enable_rf H2C sequence");
    }
    // write_btreg's request 1 carries the BT address in the ext word; the
    // 6-byte TDMA command uses the ext word too.
    let ext_btreg = io.0.lock().ops.iter().any(|op| {
        matches!(op, Op::Write(a, v) if (0x01f0..0x0200).contains(a) && *v == vec![0x3c, 0, 0, 0])
    });
    if !ext_btreg {
        return TestResult::Fail("8723bu write_btreg address");
    }
    if io.writes(0x0790) != vec![vec![0x05]]
        || io.writes(0x0778) != vec![vec![0x01]]
        || io.writes(0x076e) != vec![vec![0x0c]]
        || io.writes(0x0948) != vec![0x80u32.to_le_bytes().to_vec()]
        || io.writes(0x06c0) != vec![0x5555_5555u32.to_le_bytes().to_vec()]
        || io.writes(0x06c8) != vec![0x00ff_ffffu32.to_le_bytes().to_vec()]
        || io.writes(0x06cc) != vec![vec![0x03]]
        || io.writes(0x0974) != vec![vec![0xff]]
        || io.writes(0x0840) != vec![(0x01u32 << 20 | 0x780).to_le_bytes().to_vec()]
    {
        return TestResult::Fail("8723bu enable_rf register state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_enable_rf_bt_handover
);

fn smoke_rtl8723bu_config_channel() -> TestResult {
    use super::rtl8192e_radio::Width;
    let Some((io, owner)) = ready_owner() else {
        return TestResult::Fail("8723bu did not reach RadioReady");
    };
    let run = |primary, width| {
        narf_scheduler::block_on(super::rtl8723b_radio::config_channel(
            &owner, primary, width,
        ))
    };
    if run(14, Width::Ht20) != Err(Error::RuntimeState)
        || run(11, Width::Ht40Above) != Err(Error::RuntimeState)
        || run(3, Width::Ht40Below) != Err(Error::RuntimeState)
        || !io.0.lock().ops.is_empty()
    {
        return TestResult::Fail("8723bu inadmissible geometry touched the device");
    }
    if run(6, Width::Ht40Above).is_err() {
        return TestResult::Fail("8723bu HT40+ failed");
    }
    let lssi: Vec<u32> = io.writes(0x0840).iter().map(|v| word(v)).collect();
    // RF_A only (1T1R): channel 8 then the 40 MHz bandwidth bits.
    if lssi.len() != 2
        || lssi[0] >> 20 != 0x18
        || lssi[0] & 0x3ff != 8
        || lssi[1] & 0xc00 != 0x400
        || io.writes(0x0483) != vec![vec![2]]
        || io.writes(0x0517) != vec![vec![0x0e]]
        || io.writes(0x0668).last().map(|v| v[0] & 0x80) != Some(0x80)
        || !io.writes(0x082c).is_empty()
    {
        return TestResult::Fail("8723bu HT40+ channel writes");
    }
    io.0.lock().ops.clear();
    if run(14, Width::NoHt20).is_err()
        || io.writes(0x0483) != vec![vec![0]]
        || io.writes(0x0517) != vec![vec![0x0a]]
        || io.writes(0x0840).last().map(|v| word(v) & 0xc00) != Some(0xc00)
    {
        return TestResult::Fail("8723bu channel 14 non-HT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_config_channel
);

fn smoke_rtl8723bu_power_off() -> TestResult {
    let Some((io, owner)) = ready_owner() else {
        return TestResult::Fail("8723bu did not reach RadioReady");
    };
    {
        let mut g = io.0.lock();
        g.regs[0x0286] |= 1 << 1; // RXDMA idle
        g.regs[0x0080] &= !MCU_FW_RAM_SEL; // running from ROM: no self reset
    }
    if narf_scheduler::block_on(super::rtl8723b_power::power_off(&owner)).is_err() {
        return TestResult::Fail("8723bu power_off failed");
    }
    let order = [
        Op::Write(0x0522, vec![0xff]),
        Op::Write(REG_CR, vec![0x00]),
        Op::Write(REG_CR, vec![0x03]),
        Op::Write(REG_MCU_FW_DL, vec![0x00]),
        Op::Write(0x001f, vec![0x00]),
    ];
    let mut last = 0;
    for op in &order {
        match io.position(op) {
            Some(p) if p >= last => last = p,
            _ => return TestResult::Fail("8723bu power_off order"),
        }
    }
    let ok = {
        let g = io.0.lock();
        g.regs[0x04ec] & 2 == 0 && g.regs[0x0005] & (1 << 3) != 0 && g.regs[0x004a] & 1 != 0
    };
    if !ok {
        return TestResult::Fail("8723bu power_off final state");
    }
    // Stuck scheduler queue: terminal before any MAC reset.
    let Some((io, owner)) = ready_owner() else {
        return TestResult::Fail("8723bu did not reach RadioReady");
    };
    {
        let mut g = io.0.lock();
        g.regs[0x0286] |= 1 << 1;
        g.regs[0x05f8] = 1;
    }
    if narf_scheduler::block_on(super::rtl8723b_power::power_off(&owner))
        != Err(Error::PowerTimeout)
        || io.position(&Op::Write(REG_MCU_FW_DL, vec![0x00])).is_some()
    {
        return TestResult::Fail("8723bu power_off stuck queue");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_power_off
);

fn smoke_rtl8723bu_packet_signal_and_ra() -> TestResult {
    use super::rtl8192e_ra::{Peer, Ra};
    use super::rtl8723b_packet::{rssi_setting, signal};
    // rtl8723b_cck_rssi: LNA [7:5], VGA [4:0].
    let cck = |agc: u8| signal(&[0, 0, 0, 0, 0, agc], 0);
    if cck(6 << 5 | 3) != Some(-40)
        || cck(4 << 5 | 1) != Some(-16)
        || cck(1 << 5) != Some(6)
        || cck(2) != Some(12)
        || cck(7 << 5 | 9) != Some(0)
        || signal(&[0, 0, 0, 0, 100, 0], 4) != Some(-60)
        || signal(&[0; 5], 0).is_some()
    {
        return TestResult::Fail("8723bu signal");
    }
    if rssi_setting(0, 42) != [0x42, 0, 0, 42] {
        return TestResult::Fail("8723bu 4-byte RSSI setting");
    }
    // 1T1R: a 2SS peer is refused rather than narrowed.
    let two_ss = Peer {
        legacy: 0xfff,
        mcs: [0xff, 0xff],
        ht: true,
        sgi: false,
    };
    let one_ss = Peer {
        mcs: [0xff, 0],
        ..two_ss
    };
    if Ra::new(two_ss, 0x0fff_ffff, 1, false).is_ok() {
        return TestResult::Fail("8723bu admitted a 2SS peer");
    }
    let mut ra = match Ra::new(one_ss, 0x000f_ffff, 1, false) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("8723bu 1SS peer refused"),
    };
    let Some((io, owner)) = ready_owner() else {
        return TestResult::Fail("8723bu did not reach RadioReady");
    };
    if narf_scheduler::block_on(owner.ra_watchdog_8723b(&mut ra, -40)).is_err() {
        return TestResult::Fail("8723bu RA watchdog failed");
    }
    let words = h2c_words(&io);
    let ext =
        io.0.lock()
            .ops
            .iter()
            .any(|op| matches!(op, Op::Write(a, _) if (0x01f0..0x0200).contains(a)));
    if words.first().map(|w| w[0]) != Some(0x42) || ext && words.len() == 1 {
        return TestResult::Fail("8723bu RSSI report not 4 bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8723bu",
    smoke_rtl8723bu_packet_signal_and_ra
);
