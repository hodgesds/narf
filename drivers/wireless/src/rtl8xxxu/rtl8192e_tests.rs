//! RTL8192EU identity/EFUSE/power/firmware/H2C regressions against a
//! register model. Expectations are taken from Linux `rtl8xxxu/8192e.c` and
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
use super::rtl8192e_init::{
    self as init, h2c_words, parse_efuse, parse_identity, queue_map, reserved_pages, Queues, Vendor,
};
use super::rtl8192e_phy::{channel_group, tx_power, XAB_RF_SW_CTRL};
use super::rtl8192e_tables::{
    AGC_STD_TABLE, PHY_INIT_TABLE, RADIO_A_INIT_TABLE, RADIO_B_INIT_TABLE,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Op {
    Read(u16, usize),
    Write(u16, Vec<u8>),
}

pub(super) struct Model {
    pub(super) regs: Vec<u8>,
    pub(super) ops: Vec<Op>,
    physical: Vec<u8>,
    config: Vec<u8>,
    fw_bytes: usize,
    pub(super) mailbox_stuck: bool,
    /// RF register file per path, fed by LSSI writes, read back through the
    /// HSSI address latched in `0x824`/`0x82c`.
    pub(super) rf: [[u32; 256]; 2],
    /// RF address latched by the read request (`rtl8xxxu_read_rfreg`).
    rf_latch: [usize; 2],
    /// Whether the last `0x824` write dropped the edge-read strobe.
    edge_low: bool,
}

#[derive(Clone)]
pub(super) struct Fake(pub(super) Arc<IrqSafeSpinLock<Model>>);

/// Configuration descriptor: one vendor interface, bulk IN 0x81 plus
/// `outs` bulk OUT endpoints.
fn configuration(outs: u8) -> Vec<u8> {
    let total = 9 + 9 + 7 * (outs as usize + 1);
    let mut bytes = vec![9, 2, total as u8, 0, 1, 1, 0, 0x80, 250];
    bytes.extend_from_slice(&[9, 4, 0, 0, outs + 1, 0xff, 0xff, 0xff, 0]);
    bytes.extend_from_slice(&[7, 5, 0x81, 2, 0, 2, 0]);
    for ep in 0..outs {
        bytes.extend_from_slice(&[7, 5, 2 + ep, 2, 0, 2, 0]);
    }
    bytes
}

/// A logical map carrying only Linux-layout facts the parser reads.
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
        map[base + 11] = 0xe2; // ht20 diff[0] = -2 (high nibble)
        map[base + 12] = 0x1f; // ht20 diff[1] = -1, ht40 diff[1] = 1
        map[base + 13] = 0x07; // ofdm diff[1] = 7
        map[base + 14] = 0x00;
        map[base + 15] = 0x00;
        map[base + 16] = 0x00;
        map[base + 17] = 0x00;
    }
    map[0xb8] = 0x20;
    map[0xb9] = 0xd5; // crystal cap 0x15
    map[0xba] = 0x1a;
    map[0xd7..0xdd].copy_from_slice(&[0x00, 0xe0, 0x4c, 0x81, 0x92, 0xe0]);
    map
}

/// PG-encode every non-blank 8-byte section (ext headers above section 15).
pub(super) fn physical_stream(map: &[u8; EFUSE_MAP_LEN]) -> Vec<u8> {
    let mut out = Vec::new();
    for section in 0..EFUSE_MAP_LEN / 8 {
        let bytes = &map[section * 8..section * 8 + 8];
        if bytes.iter().all(|&b| b == 0xff) {
            continue;
        }
        if section < 16 {
            out.push((section as u8) << 4);
        } else {
            out.push(((section as u8 & 7) << 5) | 0x0f);
            out.push(((section >> 3) as u8) << 4);
        }
        out.extend_from_slice(bytes);
    }
    out.resize(512, 0xff);
    out
}

impl Fake {
    pub(super) fn new() -> Self {
        let mut regs = vec![0; 0x10000];
        regs[REG_APS_FSMCO as usize + 2] = 2; // power ready, bit 17
        regs[0xfe66] = 0x11; // SIE: high + normal
        regs[0xfe67] = 0x01; // SIE: low
                             // IQK result registers: every check passes with x=0x100, y=0x10
                             // (TX) and x=0x100, y=4 (RX) on both paths.
        for (reg, value) in [
            (0xe94usize, 0x0100_0000u32),
            (0xe9c, 0x0010_0000),
            (0xea4, 0x0100_0000),
            (0xeac, 0x0004_0000),
            (0xeb4, 0x0100_0000),
            (0xebc, 0x0010_0000),
            (0xec4, 0x0100_0000),
            (0xecc, 0x0004_0000),
        ] {
            regs[reg..reg + 4].copy_from_slice(&value.to_le_bytes());
        }
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs,
            ops: Vec::new(),
            physical: physical_stream(&logical_map()),
            config: configuration(3),
            fw_bytes: 0,
            mailbox_stuck: false,
            rf: [[0; 256]; 2],
            rf_latch: [0; 2],
            edge_low: false,
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
    /// Writes of exactly `len` bytes to `addr` (the 8-bit MAC table shares
    /// many addresses with later 16/32-bit writes).
    pub(super) fn writes_len(&self, addr: u16, len: usize) -> Vec<Vec<u8>> {
        let mut out = self.writes(addr);
        out.retain(|v| v.len() == len);
        out
    }
}

#[async_trait::async_trait]
impl ControlIo for Fake {
    fn inert_source_fixture(&self) -> bool {
        true
    }
    fn identity(&self) -> Option<(u16, u16)> {
        Some((0x0bda, 0x818b))
    }
    async fn configuration(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        let g = self.0.lock();
        out[..g.config.len()].copy_from_slice(&g.config);
        Ok(g.config.len())
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        let mut g = self.0.lock();
        g.ops.push(Op::Read(addr, out.len()));
        let a = addr as usize;
        if addr == REG_APS_FSMCO && out.len() == 4 {
            g.regs[a + 1] &= !1; // MAC_ENABLE handshake completes
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
        if addr == REG_HMTFR && g.mailbox_stuck {
            g.regs[a] = 0x0f;
        }
        if matches!(addr, 0x8a0 | 0x8a4 | 0x8b8 | 0x8bc) && out.len() == 4 {
            let path = (addr & 4 != 0) as usize;
            let value = g.rf[path][g.rf_latch[path]];
            g.regs[a..a + 4].copy_from_slice(&value.to_le_bytes());
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
        if matches!(addr, 0x840 | 0x844) && data.len() == 4 {
            let word = u32::from_le_bytes(data.try_into().unwrap());
            g.rf[(addr == 0x844) as usize][(word >> 20) as usize & 0xff] = word & 0xfffff;
        }
        if matches!(addr, 0x824 | 0x82c) && data.len() == 4 {
            let word = u32::from_le_bytes(data.try_into().unwrap());
            let edge = word & (1 << 31) != 0;
            let latch = (word >> 23) as usize & 0xff;
            if addr == 0x82c && edge {
                g.rf_latch[1] = latch;
            } else if addr == 0x824 {
                // Path A's request directly follows the strobe-low write;
                // the strobe-high restore carries the old address.
                if g.edge_low && edge {
                    g.rf_latch[0] = latch;
                }
                g.edge_low = !edge;
            }
        }
        if addr == 0x670 && data.len() == 4 {
            g.regs[0x673] &= 0x7f; // CAM command completes
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

fn image(payload: usize) -> Vec<u8> {
    let mut blob = vec![0u8; 32 + payload];
    blob[0..2].copy_from_slice(&0x92e1u16.to_le_bytes());
    blob[4..6].copy_from_slice(&35u16.to_le_bytes());
    blob[12..14].copy_from_slice(&(payload as u16).to_le_bytes());
    for (i, byte) in blob[32..].iter_mut().enumerate() {
        *byte = i as u8;
    }
    blob
}

fn smoke_rtl8192eu_identity_and_queues() -> TestResult {
    let all = Queues::from_sie(0x0111);
    // 1T2R bonding (HPON_FSM bit 22) is the RTL8191EU.
    let id = match parse_identity(0x0004_1000, 1 << 22, 0x3000_0000, all) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("8192eu identity rejected"),
    };
    if id.cut != 1
        || id.tx_paths != 1
        || id.name() != "8191EU"
        || id.vendor != Vendor::Smic
        || id.rom_rev != 3
    {
        return TestResult::Fail("8192eu identity fields");
    }
    if parse_identity(0, 0, 0, all).map(|i| i.tx_paths) != Ok(2)
        || parse_identity(1 << 23, 0, 0, all) != Err(Error::UnsupportedSilicon)
        || parse_identity(u32::MAX, 0, 0, all) != Err(Error::UnsupportedSilicon)
    {
        return TestResult::Fail("8192eu bonding/test-chip handling");
    }
    if Queues::from_out_endpoints(0).is_ok()
        || Queues::from_out_endpoints(7).is_ok()
        || Queues::from_out_endpoints(2).map(|q| (q.high, q.normal, q.low))
            != Ok((true, true, false))
    {
        return TestResult::Fail("8192eu no-SIE endpoint fallback");
    }
    // Three queues: BE/BK low, VI normal, VO/MG/HI high.
    let map = match queue_map(all) {
        Ok(map) => map,
        Err(_) => return TestResult::Fail("8192eu 3-queue map"),
    };
    let want = 3 << 4 | 2 << 6 | 1 << 8 | 1 << 10 | 3 << 12 | 3 << 14;
    if map.trxdma != want || map.be != 2 || map.bk != 2 || map.vi != 1 || map.vo != 1 {
        return TestResult::Fail("8192eu 3-queue TRXDMA/pipes");
    }
    let two = Queues::from_out_endpoints(2).unwrap();
    let map2 = queue_map(two).unwrap();
    if map2.trxdma != (3 << 4 | 3 << 6 | 2 << 8 | 2 << 10 | 3 << 12 | 3 << 14) || map2.be != 1 {
        return TestResult::Fail("8192eu 2-queue TRXDMA/pipes");
    }
    // pubq = 0xf3 - 8 - 0xc - 0 - 1 = 0xde.
    if reserved_pages(all) != (0, 0x80de_0c08) {
        return TestResult::Fail("8192eu reserved pages");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_identity_and_queues
);

fn smoke_rtl8192eu_efuse_parse() -> TestResult {
    let id = parse_identity(0, 0, 0, Queues::from_sie(0x0111)).unwrap();
    let map = logical_map();
    let factory = match parse_efuse(id, &map) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("8192eu efuse rejected"),
    };
    let b = factory.power[1];
    if factory.mac != [0x00, 0xe0, 0x4c, 0x81, 0x92, 0xe0]
        || factory.crystal_cap != 0x15
        || factory.channel_plan != 0x20
        || factory.thermal != 0x1a
        || factory.power[0].cck != [0x20, 0x21, 0x22, 0x23, 0x24, 0x25]
        || b.cck[0] != 0x21
        || b.ht40[0] != 0x29
        || b.ht20_diff != [-2, -1, 0, 0]
        || b.ht40_diff != [0, 1, 0, 0]
        || b.ofdm_diff != [0, 7, 0, 0]
    {
        return TestResult::Fail("8192eu efuse layout");
    }
    let mut bad = map;
    bad[0] = 0x28;
    if parse_efuse(id, &bad) != Err(Error::BadEfuse) {
        return TestResult::Fail("8192eu efuse ID not checked");
    }
    let mut bad = map;
    bad[0xd7] = 0x01;
    if parse_efuse(id, &bad) != Err(Error::BadEfuse) {
        return TestResult::Fail("8192eu multicast MAC admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_efuse_parse
);

fn smoke_rtl8192eu_efuse_pg_decode() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    let map = match narf_scheduler::block_on(init::read_efuse(&owner)) {
        Ok(map) => map,
        Err(_) => return TestResult::Fail("8192eu efuse read failed"),
    };
    if map != logical_map() {
        return TestResult::Fail("8192eu PG decode differs from logical map");
    }
    let gate = io.writes(REG_EFUSE_ACCESS);
    if gate != [vec![EFUSE_ACCESS_ENABLE], vec![EFUSE_ACCESS_DISABLE]] {
        return TestResult::Fail("8192eu efuse access gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_efuse_pg_decode
);

fn smoke_rtl8192eu_h2c_mailbox() -> TestResult {
    if h2c_words(&[0x40, 1, 2, 3]) != Ok((None, 0x0302_0140))
        || h2c_words(&[0x40, 1, 2, 3, 4, 5, 6]) != Ok((Some(0x0006_0504), 0x0302_0140))
        || h2c_words(&[]).is_ok()
        || h2c_words(&[0; 9]).is_ok()
    {
        return TestResult::Fail("8192eu H2C word encoding");
    }
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    for _ in 0..5 {
        if narf_scheduler::block_on(init::h2c(&owner, &[0x40, 1, 2, 3, 4, 5, 6])).is_err() {
            return TestResult::Fail("8192eu H2C send");
        }
    }
    // Ext word precedes data; mailboxes rotate 0,1,2,3,0.
    let writes: Vec<u16> =
        io.0.lock()
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Write(a, _) => Some(*a),
                _ => None,
            })
            .collect();
    if writes
        != [
            0x1f0, 0x1d0, 0x1f4, 0x1d4, 0x1f8, 0x1d8, 0x1fc, 0x1dc, 0x1f0, 0x1d0,
        ]
    {
        return TestResult::Fail("8192eu H2C mailbox order");
    }
    io.0.lock().mailbox_stuck = true;
    let before = io.0.lock().ops.len();
    if narf_scheduler::block_on(init::h2c(&owner, &[0x01, 0])) != Err(Error::MailboxBusy) {
        return TestResult::Fail("8192eu busy mailbox not reported");
    }
    if io.0.lock().ops[before..]
        .iter()
        .any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("8192eu wrote a busy mailbox");
    }
    let other = Owner::new(Fake::new(), ChipFamily::Rtl8188eu);
    if narf_scheduler::block_on(init::h2c(&other, &[0x01, 0])) != Err(Error::UnsupportedChip) {
        return TestResult::Fail("gen2 H2C admitted on RTL8188EU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_h2c_mailbox
);

fn smoke_rtl8192eu_power_and_firmware() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    let blob = image(300);
    let info = match narf_scheduler::block_on(owner.initialize_device(&blob)) {
        Ok(info) => info,
        Err(_) => return TestResult::Fail("8192eu device lifecycle failed"),
    };
    if info.signature != 0x92e1 || owner.status().stage != Stage::RadioReady {
        return TestResult::Fail("8192eu radio stage");
    }
    let factory = match owner.factory_8192e() {
        Some(f) => f,
        None => return TestResult::Fail("8192eu factory not retained"),
    };
    if factory.mac != [0x00, 0xe0, 0x4c, 0x81, 0x92, 0xe0] || factory.identity.tx_paths != 2 {
        return TestResult::Fail("8192eu retained factory");
    }
    // LDO path: SYS_CFG bit 24 clear raises the 1.2 V rail, then LDO_SW 0x83.
    // The MAC table's {0x014, 0x75} row and the post-calibration LDPC fix
    // follow the power-on write.
    if io.writes(0x14) != [vec![0x00, 0x00, 0x50, 0x00], vec![0x75], vec![0x75]]
        || io.writes(0x7c) != [vec![0x83]]
    {
        return TestResult::Fail("8192eu LDO sequence");
    }
    let cr = io.writes(REG_CR);
    if cr.len() != 2 || cr[0] != [0, 0] || u16::from_le_bytes([cr[1][0], cr[1][1]]) != 0x06ff {
        return TestResult::Fail("8192eu CR enable mask");
    }
    if io.writes(0x200) != [0x80de_0c08u32.to_le_bytes().to_vec()]
        || io.writes(REG_TRXFF_BNDY + 2) != [vec![0xff, 0x3c]]
    {
        return TestResult::Fail("8192eu reserved pages/TRXFF boundary");
    }
    let chunks: Vec<(u16, usize)> =
        io.0.lock()
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::Write(a, v) if (0x1000..0x2000).contains(a) => Some((*a, v.len())),
                _ => None,
            })
            .collect();
    if chunks != [(0x1000, 128), (0x1080, 128), (0x1100, 44)] {
        return TestResult::Fail("8192eu writeN block size");
    }
    // rtl8xxxu_reset_8051 toggles RSV_CTRL+1 bit 0 around the CPU reset.
    if io.writes(0x1d).len() != 2 {
        return TestResult::Fail("8192eu generic 8051 reset");
    }
    if !io.writes(REG_HMTFR).is_empty() {
        return TestResult::Fail("8192eu fops has no init_reg_hmtfr");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_power_and_firmware
);

fn smoke_rtl8192eu_rejects_mismatched_sie() -> TestResult {
    let io = Fake::new();
    io.0.lock().config = configuration(2);
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(64))) != Err(Error::BadEndpoints)
        || owner.factory_8192e().is_some()
    {
        return TestResult::Fail("8192eu SIE queue without endpoint admitted");
    }
    if io.0.lock().fw_bytes != 0 {
        return TestResult::Fail("8192eu downloaded after endpoint mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_rejects_mismatched_sie
);

fn smoke_rtl8192eu_tables_and_rf() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(64))).is_err() {
        return TestResult::Fail("8192eu lifecycle failed");
    }
    let ops = io.0.lock().ops.clone();
    let rf = |lssi: u16| -> Vec<u32> {
        ops.iter()
            .filter_map(|op| match op {
                Op::Write(a, v) if *a == lssi && v.len() == 4 => {
                    Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
                }
                _ => None,
            })
            .collect()
    };
    let expect = |table: &[super::phy_tables::RfRow]| -> Vec<u32> {
        table
            .iter()
            .take_while(|r| !(r.reg == 0xff && r.val == u32::MAX))
            .filter(|r| !(0xf9..=0xfe).contains(&r.reg))
            .map(|r| (r.reg as u32) << 20 | (r.val & 0xfffff))
            .collect()
    };
    // The PHY table itself writes 0x00010000 to both LSSI parms first.
    let (a, b) = (rf(0x840), rf(0x844));
    if a.first() != Some(&0x0001_0000)
        || b.first() != Some(&0x0001_0000)
        || !a[1..].starts_with(&expect(RADIO_A_INIT_TABLE))
        || !b[1..].starts_with(&expect(RADIO_B_INIT_TABLE))
    {
        return TestResult::Fail("8192eu RF table rows/path routing");
    }
    // Every RF write is bracketed by the FPGA0_POWER_SAVE bit-17 toggle
    // (plus the PHY table's own 0x818 row).
    if io.writes(0x818).len() != 1 + 2 * (a.len() - 1 + b.len() - 1) {
        return TestResult::Fail("8192eu RF power-save bracket");
    }
    // First PHY/AGC rows are applied as 32-bit writes in table order.
    let first_phy = PHY_INIT_TABLE[0];
    let first_agc = AGC_STD_TABLE[0];
    let pos = |reg: u16, val: u32| {
        ops.iter()
            .position(|op| matches!(op, Op::Write(a, v) if *a == reg && *v == val.to_le_bytes()))
    };
    match (
        pos(first_phy.reg, first_phy.val),
        pos(first_agc.reg, first_agc.val),
    ) {
        (Some(p), Some(a)) if p < a => {}
        _ => return TestResult::Fail("8192eu PHY/AGC table order"),
    }
    if io.writes(0x24).last() != Some(&0x000f_81fbu32.to_le_bytes().to_vec()) {
        return TestResult::Fail("8192eu AFE_XTAL_CTRL");
    }
    // crystal cap 0x15 into XTAL1/XTAL0 of REG_MAC_PHY_CTRL.
    let cap = 0x15u32 << 18 | 0x15 << 12;
    if io.writes(0x2c) != [cap.to_le_bytes().to_vec()] {
        return TestResult::Fail("8192eu crystal cap");
    }
    if !io
        .writes(0x870)
        .contains(&XAB_RF_SW_CTRL.to_le_bytes().to_vec())
    {
        return TestResult::Fail("8192eu RF switch control");
    }
    for reg in [0x424, 0x425, 0x45d, 0x114, 0x209] {
        if io.writes(reg).last() != Some(&vec![0xf4]) {
            return TestResult::Fail("8192eu TX buffer boundary");
        }
    }
    if !io.writes(0x104).is_empty() {
        return TestResult::Fail("8192eu must not program REG_PBP");
    }
    if io.writes(0x60f) != [vec![4]] || io.writes(0xb0) != [vec![0; 4]] {
        return TestResult::Fail("8192eu RX drvinfo / HIMR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_tables_and_rf
);

fn smoke_rtl8192eu_tx_power() -> TestResult {
    let id = parse_identity(0, 0, 0, Queues::from_sie(0x0111)).unwrap();
    let factory = parse_efuse(id, &logical_map()).unwrap();
    if [1, 2, 3, 6, 9, 11, 12, 14].map(channel_group) != [0, 0, 1, 2, 3, 3, 4, 4] {
        return TestResult::Fail("8192eu gen2 channel groups");
    }
    // Channel 1, HT20: path A ofdm=ht40[0]+0, mcs=ht40[0]+(-2);
    // path B uses diff index 1: ofdm=0x29+7, mcs=0x29+(-1).
    let [a, b] = tx_power(&factory, 1, false);
    if a != (0x20, 0x2828_2828, 0x2626_2626) || b != (0x21, 0x3030_3030, 0x2828_2828) {
        return TestResult::Fail("8192eu HT20 TX power words");
    }
    // HT40 uses ht40_diff: index 0 is zero, path B index 1 is +1.
    let [a, b] = tx_power(&factory, 1, true);
    if a.2 != 0x2828_2828 || b.2 != 0x2a2a_2a2a {
        return TestResult::Fail("8192eu HT40 TX power words");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtl8xxxu/8192eu", smoke_rtl8192eu_tx_power);

fn word(v: &[u8]) -> u32 {
    let mut raw = [0u8; 4];
    raw[..v.len()].copy_from_slice(v);
    u32::from_le_bytes(raw)
}

fn smoke_rtl8192eu_post_table_mac() -> TestResult {
    use super::rtl8192e_radio::{retry_limit, spec_sifs, RCR_INIT};
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(64))).is_err() {
        return TestResult::Fail("8192eu lifecycle failed");
    }
    if spec_sifs(0x10, 0x10) != 0x1010 || spec_sifs(0x0a, 0x10) != 0x100a {
        return TestResult::Fail("8192eu spec SIFS encode");
    }
    if retry_limit(0x30, 0x30) != 0x3030 {
        return TestResult::Fail("8192eu retry encode");
    }
    if io.writes_len(0x608, 4) != [RCR_INIT.to_le_bytes().to_vec()] || RCR_INIT != 0x7000_600e {
        return TestResult::Fail("8192eu RCR");
    }
    if io.writes_len(0x428, 2) != [vec![0x10, 0x10], vec![0x0a, 0x10]]
        || io.writes(0x42a) != [vec![0x30, 0x30]]
    {
        return TestResult::Fail("8192eu spec SIFS / retry order");
    }
    for (reg, value) in [
        (0x508u16, 0x005e_a42bu32),
        (0x50c, 0x0000_a44f),
        (0x504, 0x005e_a324),
        (0x500, 0x002f_a226),
        (0x434, 0x1008_0404),
        (0x438, 0x0403_0201),
        (0x43c, 0x0807_0605),
    ] {
        if io.writes_len(reg, 4) != [value.to_le_bytes().to_vec()] {
            return TestResult::Fail("8192eu EDCA / ARFR");
        }
    }
    if io.writes(0x670) != [0xc000_0000u32.to_le_bytes().to_vec()] {
        return TestResult::Fail("8192eu CAM invalidate");
    }
    // set_tx_power(1, HT20) from the factory map: ofdm A = 0x28 splat.
    if io.writes_len(0xe00, 4).last() != Some(&0x2828_2828u32.to_le_bytes().to_vec())
        || io.writes_len(0x830, 4).last() != Some(&0x3030_3030u32.to_le_bytes().to_vec())
    {
        return TestResult::Fail("8192eu initial TX power");
    }
    if io.writes_len(0x460, 2) != [vec![0, 0]]
        || io.writes(0x3e) != [vec![0]]
        || io.writes(0x423) != [vec![0xff]]
        || io.writes_len(0x4cc, 4) != [0x0201_ffffu32.to_le_bytes().to_vec()]
        || io.writes(0x4c6).len() != 1
        || io.writes(0x4c6)[0][0] & 0x08 != 0
    {
        return TestResult::Fail("8192eu FAST_EDCA / ACLK / queue control");
    }
    // The 8192E keeps DPDT selection and never gives LEDCFG2 to the 8051.
    if !io.writes(0x4e).is_empty() {
        return TestResult::Fail("8192eu must not touch LEDCFG2 at init");
    }
    if word(&io.writes(0x800).last().cloned().unwrap_or_default()) & 0x0300_0000 != 0x0300_0000 {
        return TestResult::Fail("8192eu CCK/OFDM block enable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_post_table_mac
);

fn smoke_rtl8192eu_config_channel() -> TestResult {
    use super::rtl8192e_radio::{channel_geometry, config_channel, Width};
    if channel_geometry(3, Width::Ht40Above) != Some((5, 2))
        || channel_geometry(11, Width::Ht40Below) != Some((9, 1))
        || channel_geometry(10, Width::Ht40Above).is_some()
        || channel_geometry(4, Width::Ht40Below).is_some()
        || channel_geometry(14, Width::Ht20).is_some()
        || channel_geometry(14, Width::NoHt20) != Some((14, 0))
        || channel_geometry(0, Width::NoHt20).is_some()
    {
        return TestResult::Fail("8192eu channel geometry");
    }
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(64))).is_err() {
        return TestResult::Fail("8192eu lifecycle failed");
    }
    // Pre-seed MODE_AG with unrelated high bits that must survive.
    {
        let mut g = io.0.lock();
        g.rf[0][0x18] = 0x8_0401;
        g.rf[1][0x18] = 0x8_0401;
    }
    if narf_scheduler::block_on(config_channel(&owner, 3, Width::Ht40Above)).is_err() {
        return TestResult::Fail("8192eu HT40 config failed");
    }
    {
        let g = io.0.lock();
        if g.rf[0][0x18] != 0x8_0405 || g.rf[1][0x18] != 0x8_0405 {
            return TestResult::Fail("8192eu HT40 MODE_AG channel/bandwidth");
        }
        if g.regs[0x483] != 2
            || word(&g.regs[0x668..0x66a]) & 0x180 != 0x80
            || g.regs[0x800] & 1 != 1
            || g.regs[0x900] & 1 != 1
            || g.regs[0xa00] & 0x10 != 0
            || word(&g.regs[0xd00..0xd04]) & 0xc00 != 0x400
            || word(&g.regs[0x818..0x81c]) & 0x0c00_0000 != 0x0800_0000
            || g.regs[0x515] != 0x0e
            || g.regs[0x517] != 0x0e
        {
            return TestResult::Fail("8192eu HT40-above BB/MAC programming");
        }
    }
    if narf_scheduler::block_on(config_channel(&owner, 6, Width::NoHt20)).is_err() {
        return TestResult::Fail("8192eu 20 MHz config failed");
    }
    let g = io.0.lock();
    if g.rf[0][0x18] != 0x8_0c06 || g.rf[1][0x18] != 0x8_0c06 {
        return TestResult::Fail("8192eu 20 MHz MODE_AG");
    }
    if g.regs[0x483] != 0
        || word(&g.regs[0x668..0x66a]) & 0x180 != 0
        || g.regs[0x800] & 1 != 0
        || g.regs[0x900] & 1 != 0
        || g.regs[0x515] != 0x0a
        || word(&g.regs[0x63c..0x640]) != 0x0a0a_0808
    {
        return TestResult::Fail("8192eu 20 MHz BB/MAC programming");
    }
    drop(g);
    if narf_scheduler::block_on(config_channel(&owner, 10, Width::Ht40Above))
        != Err(Error::RuntimeState)
    {
        return TestResult::Fail("8192eu admitted an out-of-band HT40 pair");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_config_channel
);

fn smoke_rtl8192eu_simularity_compare() -> TestResult {
    use super::rtl8192e_iqk::simularity_compare;
    let row = [0x100, 0x3fe, 0x0fc, 0x004, 0x101, 0x011, 0x0ff, 0x005];
    // Within MAX_TOLERANCE, odd entries compared sign-extended (0x3fe = -2
    // vs 0x002 = +2 differs by 4).
    let mut close = row;
    close[1] = 0x002;
    close[4] = 0x105;
    let mut result = [row, close, [0; 8], [0; 8]];
    if !simularity_compare(&mut result, 0, 1, 2) || result[3] != [0; 8] {
        return TestResult::Fail("8192eu similar rows");
    }
    // Path B TX differs: path A TX/RX and path B RX are copied into
    // result[3] from c1 and the runs are not similar.
    let mut far = row;
    far[4] = 0x140;
    let mut result = [row, far, [0; 8], [0; 8]];
    if simularity_compare(&mut result, 0, 1, 2)
        || result[3] != [0x100, 0x3fe, 0x0fc, 0x004, 0, 0, 0x0ff, 0x005]
    {
        return TestResult::Fail("8192eu per-group copy");
    }
    // A 1T board (bound 4) ignores path B entirely.
    let mut result = [row, far, [0; 8], [0; 8]];
    if !simularity_compare(&mut result, 0, 1, 1) {
        return TestResult::Fail("8192eu 1T bound");
    }
    // Path A RX missing in c1 only (first difference at i == 2): c2 is the
    // candidate and Linux copies its path-A TX pair (j in 0..2).
    let mut no_rx = row;
    no_rx[2] = 0;
    no_rx[3] = 0;
    let mut other = row;
    other[0] = 0x102;
    let mut result = [no_rx, other, [0; 8], [0; 8]];
    if simularity_compare(&mut result, 0, 1, 2) || result[3] != [0x102, 0x3fe, 0, 0, 0, 0, 0, 0] {
        return TestResult::Fail("8192eu RX-missing candidate copy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_simularity_compare
);

fn smoke_rtl8192eu_iqk_and_lck() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(64))).is_err()
        || owner.status().stage != Stage::RadioReady
    {
        return TestResult::Fail("8192eu lifecycle to RadioReady");
    }
    let radio = match owner.radio_8192e() {
        Some(radio) => radio,
        None => return TestResult::Fail("8192eu radio state not retained"),
    };
    if radio.iqk.candidate != 0 || radio.iqk.row != [0x100, 0x10, 0x100, 4, 0x100, 0x10, 0x100, 4] {
        return TestResult::Fail("8192eu IQK candidate/row");
    }
    // Two runs (t = 0, 1 agree): per run, path A one TX + two RX one-shots
    // (0xf9000000) and path B the same (0xfa000000).
    let pts = io.writes_len(0xe48, 4);
    let count = |v: u32| pts.iter().filter(|w| **w == v.to_le_bytes()).count();
    if count(0xf900_0000) != 6 || count(0xfa00_0000) != 6 || count(0xf800_0000) != 12 {
        return TestResult::Fail("8192eu IQK one-shot count");
    }
    // Only run t = 1 restores and reloads the 0xe30/0xe34 IQC default.
    let default = 0x0100_8c00u32.to_le_bytes().to_vec();
    if io
        .writes_len(0xe30, 4)
        .iter()
        .filter(|w| **w == default)
        .count()
        != 1
    {
        return TestResult::Fail("8192eu IQK restore count");
    }
    // LC calibration in packet-TX mode pauses then releases every queue,
    // before IQK's MAC calibration writes 0x3f.
    let pause = io.writes_len(0x522, 1);
    if pause.len() < 3 || pause[0] != [0xff] || pause[1] != [0x00] || pause[2] != [0x3f] {
        return TestResult::Fail("8192eu LCK/IQK TXPAUSE order");
    }
    let g = io.0.lock();
    if g.rf[0][0x18] & 0x8000 == 0 {
        return TestResult::Fail("8192eu LCK trigger");
    }
    // fill_iqk_matrix_{a,b} with oldval 0x100 from the PHY table.
    let r32 = |reg: usize| word(&g.regs[reg..reg + 4]);
    if r32(0xc80) != 0x4010_0100
        || r32(0xc88) != 0x4010_0100
        || r32(0xc14) != 0x4000_1100
        || r32(0xc1c) != 0x4000_1100
    {
        return TestResult::Fail("8192eu IQK matrix");
    }
    // Post-calibration: thermal meter, NAV upper, HRPWM, LDPC fix.
    if g.rf[0][0x42] != 0x37cf8 || g.regs[0x652] != 235 || r32(0x10) & 0x000f_f000 != 0x0007_e000 {
        return TestResult::Fail("8192eu post-calibration");
    }
    drop(g);
    if io.writes(0xfe58) != [vec![0]] {
        return TestResult::Fail("8192eu USB HRPWM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_iqk_and_lck
);

fn smoke_rtl8192eu_iqk_rejects_failed_path_a() -> TestResult {
    let io = Fake::new();
    // e94 & 0x03ff0000 == 0x01420000 fails every path-A TX IQK attempt.
    io.0.lock().regs[0xe94..0xe98].copy_from_slice(&0x0142_0000u32.to_le_bytes());
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8192eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(64))) != Err(Error::Calibration)
        || owner.status().stage != Stage::Failed
        || owner.radio_8192e().is_some()
    {
        return TestResult::Fail("8192eu admitted a failed path-A IQK");
    }
    // Linux's post-calibration tail never ran.
    if io.writes(0xfe58).iter().any(|w| w.len() == 1) {
        return TestResult::Fail("8192eu continued after failed IQK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/8192eu",
    smoke_rtl8192eu_iqk_rejects_failed_path_a
);
