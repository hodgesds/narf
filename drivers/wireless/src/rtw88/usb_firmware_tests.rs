// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU firmware/register backend (`usb_firmware::Backend`) over an
//! inert EP0 register file and bulk receipt model. No USB device is
//! touched; nothing here runs inside an executor poll.
use super::{
    firmware_transport::{Error, Io as _},
    mac::{self, Hci},
    usb::{Endpoints, Speed, QSEL_BEACON, QSEL_H2C, TX_DESC},
    usb_firmware::Backend,
};
use crate::rtl8xxxu::{firmware_transport::ControlIo, packet_transport::Io as Bulk};
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_drivers_usb::device::UsbError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Default)]
struct Model {
    regs: BTreeMap<u16, u8>,
    /// Register writes in wire order (rtw_usb_reg_sec mirror excluded).
    writes: Vec<(u16, Vec<u8>)>,
    /// Bulk-OUT submissions (dci, bytes).
    sent: Vec<(u8, Vec<u8>)>,
    next: u64,
    beacon_dci: u8,
    /// Physical EFUSE bytes served through REG_EFUSE_CTRL (0x30).
    efuse: Vec<u8>,
}
#[derive(Clone)]
struct Fake(Arc<IrqSafeSpinLock<Model>>);
impl Default for Fake {
    fn default() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model::default())))
    }
}
struct Receipt(usize);
#[async_trait::async_trait]
impl ControlIo for Fake {
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        let m = self.0.lock();
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = m.regs.get(&(addr + i as u16)).copied().unwrap_or(0);
        }
        Ok(out.len())
    }
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError> {
        let mut m = self.0.lock();
        if addr == 0x4e0 {
            return Ok(data.len());
        }
        m.writes.push((addr, data.to_vec()));
        if addr == 0x30 && data.len() == 4 {
            // A read transaction: hardware returns the byte with VALID set.
            let control = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let at = (control >> 8 & 0x3ff) as usize;
            let byte = m.efuse.get(at).copied().unwrap_or(0xff);
            let done = (control & !0xff | u32::from(byte) | 1 << 31).to_le_bytes();
            for (i, b) in done.into_iter().enumerate() {
                m.regs.insert(0x30 + i as u16, b);
            }
            return Ok(data.len());
        }
        for (i, byte) in data.iter().enumerate() {
            let reg = addr + i as u16;
            let old = m.regs.get(&reg).copied().unwrap_or(0);
            let value = match reg {
                // REG_FIFOPAGE_CTRL_2 BIT_BCN_VALID_V1 is write-one-to-clear.
                0x205 => old & !(byte & 0x80) | byte & 0x7f,
                // BIT_AUTO_INIT_LLT_V1 self-clears once the LLT is built.
                0x208 => byte & !1,
                _ => *byte,
            };
            m.regs.insert(reg, value);
        }
        Ok(data.len())
    }
    async fn delay_us(&self, _: u64) {}
}
#[async_trait::async_trait]
impl Bulk for Fake {
    type Receipt = Receipt;
    fn begin_receive(&self, _: u8, _: usize) -> Result<Receipt, UsbError> {
        Err(UsbError::Stall)
    }
    fn poll_receive(&self, _: &Receipt, _: &mut [u8]) -> Result<Option<usize>, UsbError> {
        Err(UsbError::Stall)
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<Receipt, UsbError> {
        let mut m = self.0.lock();
        m.next += 1;
        m.sent.push((dci, bytes.to_vec()));
        if dci == m.beacon_dci {
            // The page reached TXBUF: hardware sets BCN_VALID_V1.
            let v = m.regs.get(&0x205).copied().unwrap_or(0);
            m.regs.insert(0x205, v | 0x80);
        }
        Ok(Receipt(bytes.len()))
    }
    fn poll_send(&self, r: &Receipt) -> Result<Option<usize>, UsbError> {
        Ok(Some(r.0))
    }
    async fn stop(&self, _: &Receipt) -> Result<(), UsbError> {
        Ok(())
    }
}

fn complete<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    for _ in 0..1_000_000 {
        if let Poll::Ready(value) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return value;
        }
    }
    panic!("rtw88 USB firmware fixture stalled");
}

/// Three bulk-OUT pipes (0x02, 0x03, 0x04) and bulk-IN 0x81.
fn endpoints() -> Endpoints {
    let eps: [(u8, u8, u16); 4] = [
        (0x81, 2, 512),
        (0x02, 2, 512),
        (0x03, 2, 512),
        (0x04, 2, 512),
    ];
    let mut c = vec![9, 2, 0, 0, 1, 1, 0, 0x80, 250];
    c.extend_from_slice(&[9, 4, 0, 0, eps.len() as u8, 0xff, 0xff, 0xff, 0]);
    for (address, attributes, packet) in eps {
        let p = packet.to_le_bytes();
        c.extend_from_slice(&[7, 5, address, attributes, p[0], p[1], 0]);
    }
    let total = (c.len() as u16).to_le_bytes();
    c[2] = total[0];
    c[3] = total[1];
    Endpoints::parse(&c).expect("three-pipe vendor interface")
}
fn backend(fake: &Fake) -> Backend<Fake, Fake> {
    let eps = endpoints();
    let beacon = eps.out_for(QSEL_BEACON).expect("beacon pipe");
    fake.0.lock().beacon_dci = narf_drivers_usb::bulk::dci_for(beacon);
    Backend::new(fake.clone(), fake.clone(), eps, Speed::High).expect("backend")
}

/// `fw.c::rtw_fw_write_data_rsvd_page` over USB: BCN_VALID W1C, ENSWBCN,
/// BCN_CTRL, one BEACON-qsel bulk packet, BCN_VALID receipt, then the
/// boundary/BCN_CTRL/CR+1 restore. The PCIe-only REG_FWHW_TXQ_CTRL+2 BCNQ_DL
/// toggle is never written; H2C before `begin_commands` is refused.
fn smoke_rtw88_usb_firmware_reserved_page_sequence() -> TestResult {
    let fake = Fake::default();
    {
        let mut m = fake.0.lock();
        m.regs.insert(0x550, 0x18);
        m.regs.insert(0x101, 0x02);
    }
    let mut b = backend(&fake);
    if complete(b.reserved_page(&[0xaa; 100])) != Err(Error::State) {
        return TestResult::Fail("page accepted before claim");
    }
    if b.claim_pristine().is_err() {
        return TestResult::Fail("claim");
    }
    for len in [100usize, 512 - TX_DESC] {
        fake.0.lock().writes.clear();
        if complete(b.reserved_page(&vec![0xaa; len])).is_err() {
            return TestResult::Fail("reserved page");
        }
        let m = fake.0.lock();
        let Some((dci, bytes)) = m.sent.last() else {
            return TestResult::Fail("no bulk packet");
        };
        // send_firmware_pkt: +1 byte when descriptor + payload is 512-aligned.
        let expect = TX_DESC + len + usize::from((TX_DESC + len) % 512 == 0);
        if *dci != m.beacon_dci || bytes.len() != expect || bytes[5] & 0x1f != QSEL_BEACON {
            return TestResult::Fail("beacon-qsel packet");
        }
        let order: Vec<(u16, Vec<u8>)> = m.writes.clone();
        let expected = [
            (0x204, vec![0x00, 0x80]),
            (0x101, vec![0x03]),
            (0x550, vec![0x10]),
            (0x204, vec![0xcc, 0x81]), // 460 | BIT_BCN_VALID_V1
            (0x550, vec![0x18]),
            (0x101, vec![0x02]),
        ];
        if order != expected {
            return TestResult::Fail("rsvd page register order");
        }
    }
    if fake.0.lock().writes.iter().any(|(a, _)| *a == 0x422) {
        return TestResult::Fail("PCIe-only BCNQ_DL written");
    }
    if complete(b.submit_h2c(&[0; 32])) != Err(Error::State) {
        return TestResult::Fail("H2C before begin_commands");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_firmware_reserved_page_sequence
);

/// `mac.c::txdma_queue_mapping` / `__priority_queue_cfg` USB rows for three
/// bulk-OUT pipes: REG_TXDMA_PQ_MAP 0xf5a0 then BIT_RXDMA_ARBBW_EN after the
/// CR write, FIFOPAGE_INFO_1..5 = 16/16/16/0/411, the AUTO_LLT_V1
/// block-descriptor count 3 and TXDMA_OFFSET_CHK+1 BIT(1) before LLT init.
/// The fixture's H2C queue pointers are not at the configured start, so
/// the walk ends at the empty-queue proof.
fn smoke_rtw88_usb_mac_fifo_rows() -> TestResult {
    let fake = Fake::default();
    fake.0.lock().regs.insert(0xf1, 0x10); // SYS_CFG1 cut 1
    let mut b = backend(&fake);
    let hci = Hci::Usb {
        bulkout: 3,
        speed: Speed::High,
    };
    if hci != b.hci() {
        return TestResult::Fail("backend hci");
    }
    if complete(mac::prepare_on(&mut b, 0xc822, hci)) != Err(Error::Unsupported) {
        return TestResult::Fail("USB accepted for C22");
    }
    if complete(mac::prepare_on(&mut b, 0xc821, hci)) != Err(Error::Prerequisite) {
        return TestResult::Fail("fifo walk");
    }
    let m = fake.0.lock();
    let at = |addr: u16| m.writes.iter().position(|(a, _)| *a == addr);
    let value = |addr: u16| {
        m.writes
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| v.clone())
    };
    if m.writes.first() != Some(&(0x10c, vec![0xa0, 0xf5])) {
        return TestResult::Fail("TXDMA_PQ_MAP row");
    }
    let arb = m
        .writes
        .iter()
        .rposition(|(a, v)| *a == 0x10c && v == &vec![0xa1]);
    if arb.is_none() || arb < at(0x100) {
        return TestResult::Fail("ARBBW_EN after CR");
    }
    for (reg, pages) in [
        (0x230u16, 16u16),
        (0x234, 16),
        (0x238, 16),
        (0x23c, 0),
        (0x240, 411),
    ] {
        if value(reg) != Some(pages.to_le_bytes().to_vec()) {
            return TestResult::Fail("FIFOPAGE_INFO rows");
        }
    }
    if value(0x20b) != Some(vec![3]) || m.regs.get(&0x208).copied().unwrap_or(0) & 0xf0 != 0x30 {
        return TestResult::Fail("AUTO_LLT_V1 descriptor count");
    }
    if m.regs.get(&0x20d).copied().unwrap_or(0) & 2 == 0 {
        return TestResult::Fail("TXDMA_OFFSET_CHK+1 BIT(1)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw88/usb", smoke_rtw88_usb_mac_fifo_rows);

/// `rtw_usb_write_data_h2c` after `begin_commands`: the 32-byte H2C goes to
/// the H2C-qsel pipe and `poll_h2c` reports its exact completion.
fn smoke_rtw88_usb_firmware_h2c_bulk() -> TestResult {
    let fake = Fake::default();
    fake.0.lock().regs.insert(0x522, 0xff);
    let mut b = backend(&fake);
    let ok = b.claim_pristine().is_ok()
        && complete(b.finish_dma()).is_ok()
        && b.begin_mac().is_ok()
        && b.finish_mac().is_ok()
        && b.begin_phy().is_ok()
        && b.finish_phy().is_ok()
        && b.begin_commands().is_ok();
    if !ok {
        return TestResult::Fail("phase walk");
    }
    if complete(b.submit_h2c(&[0x5a; 32])).is_err() {
        return TestResult::Fail("submit");
    }
    let h2c = narf_drivers_usb::bulk::dci_for(endpoints().out_for(QSEL_H2C).expect("h2c pipe"));
    {
        let m = fake.0.lock();
        let Some((dci, bytes)) = m.sent.last() else {
            return TestResult::Fail("no H2C packet");
        };
        if *dci != h2c || bytes.len() != TX_DESC + 32 || bytes[TX_DESC..] != [0x5a; 32] {
            return TestResult::Fail("H2C packet");
        }
    }
    if complete(b.poll_h2c()) != Ok(true) || complete(b.park_radio()).is_err() {
        return TestResult::Fail("completion/park");
    }
    if fake.0.lock().regs.get(&0x100).copied().unwrap_or(0) & 0xcf != 0 {
        return TestResult::Fail("CR left open");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_firmware_h2c_bulk
);

/// `efuse.c::rtw_dump_physical_efuse_map` over EP0 for RTL8821CU: the async
/// path decodes the two-byte-header records that place the MAC at 0x107
/// (`rtw8821cu_efuse_parsing`) and refuses an unprogrammed map.
fn smoke_rtw88_usb_efuse_factory_async() -> TestResult {
    const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let fake = Fake::default();
    let mut b = backend(&fake);
    if complete(super::efuse::read_factory8821c_usb(&mut b)).is_ok() {
        return TestResult::Fail("blank map accepted");
    }
    // Block 32 word 3 (0x106..0x108), block 33 words 0..2 (0x108..0x10e).
    fake.0.lock().efuse = vec![
        0x0f, 0x47, 0x00, MAC[0], 0x2f, 0x48, MAC[1], MAC[2], MAC[3], MAC[4], MAC[5], 0x00, 0xff,
    ];
    match complete(super::efuse::read_factory8821c_usb(&mut b)) {
        Ok(factory) if factory.usb() && factory.mac() == MAC => {}
        _ => return TestResult::Fail("USB factory map"),
    }
    // Bank 0 with the programming LDO off before the first byte.
    let m = fake.0.lock();
    if m.regs.get(&0x37).copied().unwrap_or(0) & 0x80 != 0 {
        return TestResult::Fail("efuse LDO left on");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_efuse_factory_async
);
