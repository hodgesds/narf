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
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs,
            ops: Vec::new(),
            physical: physical_stream(&logical_map()),
            config: configuration(3),
            fw_bytes: 0,
            mailbox_stuck: false,
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
        if addr == REG_HMTFR && g.mailbox_stuck {
            g.regs[a] = 0x0f;
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
    if info.signature != 0x92e1 || owner.status().stage != Stage::FirmwareReady {
        return TestResult::Fail("8192eu firmware stage");
    }
    let factory = match owner.factory_8192e() {
        Some(f) => f,
        None => return TestResult::Fail("8192eu factory not retained"),
    };
    if factory.mac != [0x00, 0xe0, 0x4c, 0x81, 0x92, 0xe0] || factory.identity.tx_paths != 2 {
        return TestResult::Fail("8192eu retained factory");
    }
    // LDO path: SYS_CFG bit 24 clear raises the 1.2 V rail, then LDO_SW 0x83.
    if io.writes(0x14) != [vec![0x00, 0x00, 0x50, 0x00]] || io.writes(0x7c) != [vec![0x83]] {
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
