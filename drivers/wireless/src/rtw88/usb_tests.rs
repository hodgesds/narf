// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821CU USB transport (Linux rtw88/usb.c) register-model and framing
//! cases. Inert software models only: no USB device is touched.
use super::usb::{self, Endpoints, Registers, Speed, QSEL_BEACON, QSEL_H2C, QSEL_MGMT, TX_DESC};
use crate::rtl8xxxu::firmware_transport::ControlIo;
use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_drivers_usb::device::UsbError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Fake {
    regs: IrqSafeSpinLock<BTreeMap<u16, u8>>,
    /// (write, address, bytes) in wire order.
    ops: IrqSafeSpinLock<Vec<(bool, u16, Vec<u8>)>>,
}
impl Default for Fake {
    fn default() -> Self {
        Self {
            regs: IrqSafeSpinLock::new(BTreeMap::new()),
            ops: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}
impl Fake {
    fn with(regs: &[(u16, u8)]) -> Self {
        let fake = Self::default();
        fake.regs.lock().extend(regs.iter().copied());
        fake
    }
    fn reg(&self, addr: u16) -> u8 {
        self.regs.lock().get(&addr).copied().unwrap_or(0)
    }
    fn wrote(&self, addr: u16) -> bool {
        self.ops.lock().iter().any(|(w, a, _)| *w && *a == addr)
    }
}
#[async_trait::async_trait]
impl ControlIo for Fake {
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        {
            let regs = self.regs.lock();
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = regs.get(&(addr + i as u16)).copied().unwrap_or(0);
            }
        }
        self.ops.lock().push((false, addr, out.to_vec()));
        Ok(out.len())
    }
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError> {
        self.ops.lock().push((true, addr, data.to_vec()));
        if addr != 0x4e0 {
            let mut regs = self.regs.lock();
            for (i, byte) in data.iter().enumerate() {
                let reg = addr + i as u16;
                // APFM_ONMAC / APFM_OFFMAC self-clear once the PMU finishes.
                let value = if reg == 0x05 { byte & !3 } else { *byte };
                regs.insert(reg, value);
                // Card disable (REG_APS_FSMCO+3 = 0x20) leaves CR reading 0xea.
                if reg == 0x07 && value == 0x20 {
                    regs.insert(0x100, 0xea);
                }
            }
        }
        Ok(data.len())
    }
    async fn delay_us(&self, _: u64) {}
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
    panic!("rtw88 USB fixture stalled");
}

/// Config descriptor: one vendor interface, altsetting 0, with `eps`
/// (address, attributes, max packet).
fn config(eps: &[(u8, u8, u16)]) -> Vec<u8> {
    let mut c = vec![9, 2, 0, 0, 1, 1, 0, 0x80, 250];
    c.extend_from_slice(&[9, 4, 0, 0, eps.len() as u8, 0xff, 0xff, 0xff, 0]);
    for &(address, attributes, packet) in eps {
        let p = packet.to_le_bytes();
        c.extend_from_slice(&[7, 5, address, attributes, p[0], p[1], 0]);
    }
    let total = (c.len() as u16).to_le_bytes();
    c[2] = total[0];
    c[3] = total[1];
    c
}

fn smoke_rtw88_usb_endpoints_and_qsel_map() -> TestResult {
    let plan = match Endpoints::parse(&config(&[
        (0x84, 2, 512),
        (0x87, 3, 64),
        (0x05, 2, 512),
        (0x06, 2, 512),
        (0x08, 2, 512),
    ])) {
        Ok(plan) => plan,
        Err(_) => return TestResult::Fail("three-pipe RTL8821CU interface refused"),
    };
    if plan.bulk_in != 0x84 || plan.interrupt_in != Some(0x87) || plan.out_count != 3 {
        return TestResult::Fail("rtw_usb_parse pipe discovery changed");
    }
    // rqpn_table_8821c[3]: vo/vi NORMAL(ep1), be/bk LOW(ep2), mg/hi HIGH(ep0).
    let expected = [
        (0u8, Some(0x08u8)),
        (1, Some(0x08)),
        (2, Some(0x08)),
        (3, Some(0x08)),
        (4, Some(0x06)),
        (6, Some(0x06)),
        (8, None),
        (15, None),
        (QSEL_BEACON, Some(0x05)),
        (QSEL_MGMT, Some(0x05)),
        (QSEL_H2C, Some(0x05)),
        (20, None),
    ];
    if expected.iter().any(|&(q, ep)| plan.out_for(q) != ep) {
        return TestResult::Fail("qsel_to_ep mapping differs from rtw_usb_parse");
    }
    // A second bulk-IN overflows; a single OUT pipe maps EXTRA past it.
    if Endpoints::parse(&config(&[(0x84, 2, 512), (0x85, 2, 512), (0x05, 2, 512)])).is_ok()
        || Endpoints::parse(&config(&[(0x84, 2, 512), (0x05, 2, 512)])).is_ok()
    {
        return TestResult::Fail("invalid pipe geometry admitted");
    }
    let mut bad = config(&[(0x84, 2, 512), (0x05, 2, 512), (0x06, 2, 512)]);
    bad[9 + 5] = 0x08; // not the vendor interface
    if Endpoints::parse(&bad).is_ok() {
        return TestResult::Fail("non-vendor interface bound");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_endpoints_and_qsel_map
);

fn smoke_rtw88_usb_queue_tables_and_tx_qsel() -> TestResult {
    let maps: Vec<u16> = (2..=4)
        .map(|n| usb::txdma_pq_map(usb::usb_tables(n).unwrap().0))
        .collect();
    // Index 4 equals the PCIe row value (0xc5a0) programmed by mac.rs.
    if maps != [0xfea0, 0xf5a0, 0xc5a0] || usb::usb_tables(1).is_ok() {
        return TestResult::Fail("txdma_queue_mapping USB rows changed");
    }
    // reserved boundary 460 for C21 (mac.rs Info): pubq = acq - hq-lq-nq-exq-gapq.
    if usb::public_pages(460, usb::PAGES_8821C[2]) != Some(427)
        || usb::public_pages(460, usb::PAGES_8821C[4]) != Some(397)
    {
        return TestResult::Fail("priority_queue_cfg public pages changed");
    }
    let mut qos = vec![0x88, 0, 0, 0, 2, 4, 6, 8, 10, 12];
    let mgmt = [0x40u8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    if usb::tx_qsel(&mgmt, 0) != Some(QSEL_MGMT) || usb::tx_qsel(&qos, 5) != Some(5) {
        return TestResult::Fail("unicast/management qsel changed");
    }
    qos[4] = 1;
    if usb::tx_qsel(&qos, 5) != Some(usb::QSEL_HIGH) {
        return TestResult::Fail("group-addressed data not routed to HIGH");
    }
    if !usb::is_rtl8821cu(0x0bda, 0xc811) || usb::is_rtl8821cu(0x0bda, 0xb812) {
        return TestResult::Fail("rtw_8821cu_id_table changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_queue_tables_and_tx_qsel
);

fn checksum_ok(desc: &[u8]) -> bool {
    desc[..32]
        .chunks_exact(2)
        .fold(0u16, |s, p| s ^ u16::from_le_bytes([p[0], p[1]]))
        == 0
}
fn w(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn smoke_rtw88_usb_reserved_page_descriptor_and_checksum() -> TestResult {
    let packet = usb::reserved_page_packet(&[0xaa; 100]).unwrap();
    if packet.len() != TX_DESC + 100
        || w(&packet, 0) != 100 | 48 << 16 | 1 << 26
        || w(&packet, 4) != 0x10 << 8
        || !checksum_ok(&packet)
        || packet[TX_DESC..] != [0xaa; 100]
    {
        return TestResult::Fail("rtw_usb_write_data_rsvd_page descriptor changed");
    }
    // send_firmware_pkt: 464 + 48 is a multiple of 512, so one byte is added.
    let padded = usb::reserved_page_packet(&[1; 464]).unwrap();
    if padded.len() != 513 || w(&padded, 0) & 0xffff != 465 || padded[512] != 0 {
        return TestResult::Fail("USB 512-byte firmware packet rule changed");
    }
    let h2c = usb::h2c_packet(&[7; 32]).unwrap();
    if w(&h2c, 0) != 32 || w(&h2c, 4) != 0x13 << 8 || !checksum_ok(&h2c) {
        return TestResult::Fail("rtw_usb_write_data_h2c descriptor changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_reserved_page_descriptor_and_checksum
);

fn smoke_rtw88_usb_tx_aggregation_framing() -> TestResult {
    let packets: Vec<Vec<u8>> = [50usize, 61, 70, 80]
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let mut p = usb::descriptor(usb::PacketInfo {
                size: (n - TX_DESC) as u16,
                offset: TX_DESC as u8,
                ls: true,
                qsel: 0,
            })
            .to_vec();
            p.resize(n, i as u8 + 1);
            p
        })
        .collect();
    let (urb, count) = match usb::aggregate(&packets) {
        Ok(value) => value,
        Err(_) => return TestResult::Fail("aggregate refused"),
    };
    // usb_tx_agg_desc_num = 3; starts 0, 56 and 120 (8-byte aligned).
    if count != 3
        || urb.len() != 190
        || urb[56..117] != packets[1][..]
        || urb[120..] != packets[2][..]
    {
        return TestResult::Fail("rtw_usb_tx_agg_skb layout changed");
    }
    if w(&urb, 28) >> 24 != 3 || !checksum_ok(&urb) || urb[50..56] != [0; 6] {
        return TestResult::Fail("DMA_TXAGG_NUM/checksum not refreshed");
    }
    let (single, one) = usb::aggregate(&packets[3..]).unwrap();
    if one != 1 || single != packets[3] {
        return TestResult::Fail("single packet must be sent unchanged");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_tx_aggregation_framing
);

fn smoke_rtw88_usb_rx_aggregate_split() -> TestResult {
    let mut urb = vec![0u8; 122];
    // Record 1: pkt_len 30, drv_info 4 (32 bytes), shift 0 -> 86, next 88.
    urb[0..4].copy_from_slice(&(30u32 | 4 << 16 | 1 << 26).to_le_bytes());
    // Record 2 (C2H): pkt_len 10, no drv_info -> 34 bytes at 88.
    urb[88..92].copy_from_slice(&10u32.to_le_bytes());
    urb[96..100].copy_from_slice(&(1u32 << 28).to_le_bytes());
    let records = usb::split_rx(&urb);
    if records.len() != 2
        || records[0].bytes.len() != 86
        || records[0].payload_offset != 56
        || records[0].c2h
        || records[1].bytes.len() != 34
        || records[1].payload_offset != 24
        || !records[1].c2h
    {
        return TestResult::Fail("rtw_usb_rx_handler framing changed");
    }
    // A record running past the URB is not delivered; short URBs drop.
    urb[88..92].copy_from_slice(&200u32.to_le_bytes());
    if usb::split_rx(&urb).len() != 1 || !usb::split_rx(&urb[..23]).is_empty() {
        return TestResult::Fail("truncated aggregate delivered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_rx_aggregate_split
);

fn smoke_rtw88_usb_register_section_mirror() -> TestResult {
    let regs = Registers::new(Fake::with(&[(0x80, 0x5a), (0x2000, 0x11)]));
    if complete(regs.read8(0x80)) != Ok(0x5a)
        || complete(regs.read32(0x2000)) != Ok(0x11)
        || complete(regs.write16(0x1004, 0x1234)).is_err()
    {
        return TestResult::Fail("vendor register access failed");
    }
    let ops = regs.control().ops.lock().clone();
    let expected: Vec<(bool, u16, Vec<u8>)> = vec![
        (false, 0x80, vec![0x5a]),
        (true, 0x4e0, vec![0x5a]),
        (false, 0x2000, vec![0x11, 0, 0, 0]),
        (true, 0x1004, vec![0x34, 0x12]),
        (true, 0x4e0, vec![0x34]),
    ];
    if ops != expected {
        return TestResult::Fail("rtw_usb_reg_sec mirror order changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_register_section_mirror
);

fn smoke_rtw88_usb_power_on_sequence() -> TestResult {
    // Card off (CR 0xea), cut B, PMU ready bit 0x06[1] set.
    let fake = Fake::with(&[
        (0xf1, 0x10),
        (0x100, 0xea),
        (0x06, 0x02),
        (0x4a, 1),
        (0xf5, 1),
    ]);
    let regs = Registers::new(fake);
    if complete(regs.power_on()).is_err() {
        return TestResult::Fail("USB power-on refused");
    }
    let fake = regs.control();
    if fake.wrote(0x74) || fake.wrote(0x04) {
        return TestResult::Fail("PCIe-only HCI_OPT/PFM_WOWL write on USB");
    }
    if fake.reg(0x4a) & 1 != 0
        || fake.reg(0xf5) & 1 != 0
        || fake.reg(0x03) & 0xd8 != 0xd8
        || fake.reg(0x1082) & 1 == 0
        || fake.reg(0x1103) != 0x0c
        || fake.reg(0x20) & 9 != 9
    {
        return TestResult::Fail("USB card-enable/system-cfg receipts missing");
    }
    // Already on: Linux cycles through the USB card-disable flow first.
    let on = Registers::new(Fake::with(&[(0xf1, 0x10), (0x100, 0x00), (0x06, 0x02)]));
    if complete(on.power_on()).is_err()
        || !on
            .control()
            .ops
            .lock()
            .iter()
            .any(|(w, a, d)| *w && *a == 0x07 && d[..] == [0x20])
    {
        return TestResult::Fail("-EALREADY off/on cycle missing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_power_on_sequence
);

fn smoke_rtw88_usb_interface_cfg_and_rx_agg() -> TestResult {
    let regs = Registers::new(Fake::default());
    // Linux order: rtw_mac_init (queue mapping, priority queues) precedes
    // the hci interface_cfg and dynamic RX aggregation.
    let ok = complete(regs.queue_mapping(3)).is_ok()
        && complete(regs.queue_mapping_tail()).is_ok()
        && complete(regs.priority_queue_tail()).is_ok()
        && complete(regs.interface_cfg(Speed::High)).is_ok()
        && complete(regs.dynamic_rx_agg(true)).is_ok();
    let fake = regs.control();
    if !ok
        || fake.reg(0x290) != 0x1e
        || fake.reg(0x20d) & 2 != 2
        || fake.reg(0x280) != 0x05
        || fake.reg(0x281) != 0x20
        || fake.reg(0x10c) != 0xa5
        || fake.reg(0x10d) != 0xf5
        || fake.reg(0x208) != 0x30
        || fake.reg(0x20b) != 3
    {
        return TestResult::Fail("USB interface/RX-agg/queue registers changed");
    }
    if complete(regs.queue_mapping(1)).is_ok() {
        return TestResult::Fail("single bulk-out queue mapping admitted");
    }
    let mut map = [0u8; 512];
    map[0x107..0x10d].copy_from_slice(&[0, 0xe0, 0x4c, 1, 2, 3]);
    if usb::efuse_mac(&map) != [0, 0xe0, 0x4c, 1, 2, 3] {
        return TestResult::Fail("rtw8821cu_efuse_parsing MAC offset changed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_interface_cfg_and_rx_agg
);

/// `rtw8821cu.c::rtw_8821cu_id_table` registration: every Linux entry with
/// the vendor interface triple, 0bda:c811 no longer in the rtl8xxxu table,
/// and the xHCI contexts are the bulk-IN plus every bulk-OUT pipe.
fn smoke_rtw88_usb_driver_id_table_and_endpoint_contexts() -> TestResult {
    use narf_drivers_usb::xhci::EndpointKind;
    let table = &super::usb_driver::RTW8821CU_USB_IDS;
    if table.len() != usb::RTL8821CU_IDS.len()
        || table.iter().zip(usb::RTL8821CU_IDS).any(|(m, &(v, p))| {
            m.vendor_id != v
                || m.product_id != p
                || m.class != Some(0xff)
                || m.subclass != Some(0xff)
                || m.protocol != Some(0xff)
        })
    {
        return TestResult::Fail("rtw8821cu id table differs from rtw_8821cu_id_table");
    }
    if crate::rtl8xxxu::RTL8XXXU_USB_IDS
        .iter()
        .any(|m| usb::is_rtl8821cu(m.vendor_id, m.product_id))
    {
        return TestResult::Fail("rtl8xxxu still claims an rtw8821cu id");
    }
    let plan = match Endpoints::parse(&config(&[
        (0x84, 2, 512),
        (0x87, 3, 64),
        (0x05, 2, 512),
        (0x06, 2, 512),
        (0x08, 2, 512),
    ])) {
        Ok(plan) => plan,
        Err(_) => return TestResult::Fail("three-pipe interface refused"),
    };
    let contexts = super::usb_driver::endpoint_configs(&plan);
    let expected = [
        (0x84u8, EndpointKind::BulkIn),
        (0x05, EndpointKind::BulkOut),
        (0x06, EndpointKind::BulkOut),
        (0x08, EndpointKind::BulkOut),
    ];
    if contexts.len() != expected.len()
        || contexts
            .iter()
            .zip(expected)
            .any(|(c, (addr, kind))| c.ep_addr != addr || c.kind != kind || c.max_packet != 512)
    {
        return TestResult::Fail("endpoint contexts differ from the rtw88 pipes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/usb",
    smoke_rtw88_usb_driver_id_table_and_endpoint_contexts
);
