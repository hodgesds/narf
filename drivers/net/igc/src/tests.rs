//! Tests execute the production register, descriptor and DMA ownership paths.
//! Literal register/descriptor expectations come from Intel's Linux driver at
//! ecd997b0189a, rather than calling the production encoding helpers.

use crate::{
    hardware::{self, Registers},
    igc::decode_link,
    packet::{rx_metadata, TxPlan},
    queue::{Queue, RxWriteback},
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    ptr,
};
use narf_io::alloc_coherent;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;
use narf_net::{Frame, L4CsumKind, TxMeta};

#[derive(Default)]
struct Model {
    regs: RefCell<BTreeMap<u64, u32>>,
    phy: RefCell<BTreeMap<u8, u16>>,
    mmd: RefCell<BTreeMap<(u16, u16), u16>>,
    writes: RefCell<Vec<(u64, u32)>>,
    mmd_dev: Cell<u16>,
    mmd_reg: Cell<u16>,
    stuck_master: Cell<bool>,
    stuck_queue: Cell<bool>,
    stuck_nvm: Cell<bool>,
    mdic_error: Cell<bool>,
    bad_echo: Cell<bool>,
}
impl Model {
    fn new() -> Self {
        let m = Self::default();
        m.regs.borrow_mut().extend([
            (0x10, 0x200),
            (0xe14, 0x100),
            (0x5400, 0x33221102),
            (0x5404, 0x80005544),
        ]);
        m.phy
            .borrow_mut()
            .extend([(2, 0x67c9), (3, 0xdc10), (0, 0x0800), (4, 1), (9, 0)]);
        m
    }
    fn value(&self, reg: u64) -> u32 {
        *self.regs.borrow().get(&reg).unwrap_or(&0)
    }
    fn phy_value(&self, reg: u8) -> u16 {
        if reg == 14 && self.mmd_dev.get() & 0x4000 != 0 {
            *self
                .mmd
                .borrow()
                .get(&(self.mmd_dev.get() & 31, self.mmd_reg.get()))
                .unwrap_or(&0)
        } else {
            *self.phy.borrow().get(&reg).unwrap_or(&0)
        }
    }
}
impl Registers for Model {
    fn read(&self, reg: u64) -> u32 {
        let value = self.value(reg);
        if reg == 0x5b50 {
            self.regs.borrow_mut().insert(reg, value | 1);
        }
        value
    }
    fn write(&self, reg: u64, mut value: u32) {
        self.writes.borrow_mut().push((reg, value));
        if reg == 0 && value & (1 << 26) != 0 {
            value &= !(1 << 26);
            self.regs
                .borrow_mut()
                .insert(0x10, if self.stuck_nvm.get() { 0 } else { 0x200 });
        }
        if reg == 0 && value & 4 != 0 {
            self.regs
                .borrow_mut()
                .insert(8, if self.stuck_master.get() { 0x80000 } else { 0 });
        }
        if reg & 0x3f == 0x28 && self.stuck_queue.get() {
            value &= !(1 << 25);
        }
        if reg == 0x12014 && !self.stuck_nvm.get() {
            value = (((value >> 2) ^ 0x5aa5) << 16) | 2;
        }
        if reg == 0x20 {
            let index = ((value >> 16) & 31) as u8;
            if value & 0x04000000 != 0 {
                let data = value as u16;
                if index == 13 {
                    self.mmd_dev.set(data);
                } else if index == 14 {
                    if self.mmd_dev.get() & 0x4000 == 0 {
                        self.mmd_reg.set(data);
                    } else {
                        self.mmd
                            .borrow_mut()
                            .insert((self.mmd_dev.get() & 31, self.mmd_reg.get()), data);
                    }
                } else {
                    self.phy.borrow_mut().insert(index, data);
                }
            } else {
                value = (value & !0xffff) | u32::from(self.phy_value(index));
            }
            value |= 0x10000000;
            if self.mdic_error.get() {
                value |= 0x40000000;
            }
            if self.bad_echo.get() {
                value ^= 1 << 16;
            }
        }
        self.regs.borrow_mut().insert(reg, value);
    }
    fn wait(&self, _: u64, mut ready: impl FnMut() -> bool) -> bool {
        // Bounded deterministic model steps, never a hardware polling loop.
        for _ in 0..32 {
            if ready() {
                return true;
            }
        }
        false
    }
    fn delay(&self, _: u64) {}
}

macro_rules! check {
    ($condition:expr, $reason:literal) => {
        if !$condition {
            return TestResult::Fail($reason);
        }
    };
}

fn smoke_igc_wait_does_not_repeat_acquisition() -> TestResult {
    let acquisitions = Cell::new(0);
    check!(
        hardware::wait_until(100_000, || {
            acquisitions.set(acquisitions.get() + 1);
            true
        }),
        "ready wait failed"
    );
    check!(
        acquisitions.get() == 1,
        "successful acquisition predicate evaluated again"
    );
    let polls = Cell::new(0);
    check!(
        hardware::wait_until(100_000, || {
            polls.set(polls.get() + 1);
            polls.get() >= 3
        }),
        "delayed wait failed"
    );
    check!(
        polls.get() == 3,
        "completion predicate repeated after ready"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_wait_does_not_repeat_acquisition
);

fn smoke_igc_reset_and_phy_protocol() -> TestResult {
    let m = Model::new();
    check!(hardware::reset(&m, 4).is_ok(), "reset failed");
    check!(hardware::setup_phy(&m, false).is_ok(), "PHY setup failed");
    check!(
        m.phy_value(4) == 0x1e1 && m.phy_value(9) == 0x200,
        "10/100/1000 advertisement wrong"
    );
    check!(
        m.mmd.borrow().get(&(7, 32)) == Some(&0x80),
        "2500 advertisement missing"
    );
    check!(
        m.phy_value(0) & 0x1e00 == 0x1200,
        "PHY not powered/restarted"
    );
    check!(
        m.value(0x5b5c) == 0 && m.value(0x5b50) == 0,
        "PHY semaphore leaked"
    );
    check!(
        hardware::read_mac(&m) == Ok([2, 0x11, 0x22, 0x33, 0x44, 0x55]),
        "MAC decode wrong"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_reset_and_phy_protocol);

fn smoke_igc_phy_failures_release_ownership() -> TestResult {
    for echo in [false, true] {
        let m = Model::new();
        m.mdic_error.set(!echo);
        m.bad_echo.set(echo);
        check!(
            hardware::setup_phy(&m, false).is_err(),
            "bad MDIC completion accepted"
        );
        check!(
            m.value(0x5b5c) == 0 && m.value(0x5b50) == 0,
            "error leaked PHY ownership"
        );
    }
    let m = Model::new();
    m.regs.borrow_mut().insert(0x5b5c, 0x20000);
    check!(
        hardware::setup_phy(&m, false).is_err(),
        "firmware-owned PHY accessed"
    );
    check!(
        !m.writes.borrow().iter().any(|(r, _)| *r == 0x20),
        "MDIC written without semaphore"
    );
    let m = Model::new();
    m.regs.borrow_mut().insert(0x5820, 0x40000);
    check!(
        hardware::setup_phy(&m, false).is_err(),
        "firmware reset block ignored"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_phy_failures_release_ownership);

fn smoke_igc_gigabit_only_and_blank_nvm() -> TestResult {
    let m = Model::new();
    check!(
        hardware::setup_phy(&m, true).is_ok(),
        "gigabit PHY setup failed"
    );
    check!(
        m.mmd.borrow().get(&(7, 32)) == Some(&0),
        "1G-only part advertises 2.5G"
    );
    m.regs.borrow_mut().insert(0x5400, 0);
    m.regs.borrow_mut().insert(0x5404, 0);
    check!(hardware::read_mac(&m).is_err(), "blank NVM accepted");
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_gigabit_only_and_blank_nvm);

fn smoke_igc_reset_requires_dma_and_nvm_ack() -> TestResult {
    let m = Model::new();
    m.stuck_master.set(true);
    check!(
        hardware::reset(&m, 4).is_err(),
        "reset ignored active PCIe master"
    );
    check!(
        !m.writes
            .borrow()
            .iter()
            .any(|(r, v)| *r == 0 && v & (1 << 26) != 0),
        "reset issued before DMA fence"
    );
    let m = Model::new();
    m.stuck_nvm.set(true);
    check!(hardware::reset(&m, 4).is_err(), "NVM timeout accepted");
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_reset_requires_dma_and_nvm_ack);

fn smoke_igc_queue_enable_and_rss() -> TestResult {
    let m = Model::new();
    check!(
        hardware::queue(&m, 3, 0x112233440000, 0x556677880000, 256).is_ok(),
        "queue setup failed"
    );
    check!(
        m.value(0xe0c0) == 0x33440000 && m.value(0xe0c4) == 0x1122 && m.value(0xe0c8) == 4096,
        "TX ring DMA address/length wrong"
    );
    check!(
        m.value(0xc0d8) == 255 && m.value(0xc0cc) == 0x12000002,
        "RX tail/type/size wrong"
    );
    let rss = narf_net::rss::RssConfig::standard(4, 128);
    hardware::configure(&m, [2, 1, 2, 3, 4, 5], 9216, &rss);
    check!(
        m.value(0x100) & 2 == 0 && m.value(0x400) & 2 == 0,
        "global DMA enabled before queue acknowledgements"
    );
    check!(
        m.value(0x5000) == 0x2b00 && m.value(0xa000) == 0,
        "RX checksum/UTA configuration wrong"
    );
    check!(
        hardware::enable_data(&m).is_ok(),
        "global DMA enable not acknowledged"
    );
    check!(
        m.value(0x100) & 2 != 0 && m.value(0x400) & 2 != 0,
        "global DMA not enabled after queue configuration"
    );
    check!(
        m.value(0x5004) == 9238 && m.value(0x5818) == 0x00f70002,
        "jumbo/RSS control wrong"
    );
    for word in 0..32 {
        check!(
            m.value(0x5c00 + word * 4) == 0x03020100,
            "RETA does not span four queues"
        );
    }
    m.stuck_queue.set(true);
    check!(
        hardware::queue(&m, 0, 0x1000, 0x2000, 256).is_err(),
        "missing QUEUE_ENABLE accepted"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_queue_enable_and_rss);

fn smoke_igc_negotiated_link_metadata() -> TestResult {
    for (status, speed) in [(3, 10), (0x43, 100), (0x83, 1000), (0x400083, 2500)] {
        let link = decode_link(status);
        check!(
            link.carrier
                && link.speed_mbps == Some(speed)
                && link.duplex == Some(narf_net::iface::LinkDuplex::Full),
            "link mode decode wrong"
        );
    }
    check!(
        !decode_link(0x400080).carrier && !decode_link(u32::MAX).carrier,
        "down/removed controller reports carrier"
    );
    check!(
        decode_link(0x82).duplex == Some(narf_net::iface::LinkDuplex::Half),
        "half duplex lost"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_negotiated_link_metadata);

fn tcp4(payload: usize) -> Vec<u8> {
    let mut b = vec![0; 54 + payload];
    b[..6].fill(0x22);
    b[6..12].fill(0x44);
    b[12..14].copy_from_slice(&[8, 0]);
    b[14] = 0x45;
    b[16..18].copy_from_slice(&((40 + payload) as u16).to_be_bytes());
    b[22] = 64;
    b[23] = 6;
    b[26..34].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 2]);
    b[34..38].copy_from_slice(&[0x04, 0xd2, 0, 80]);
    b[46] = 0x50;
    for (i, v) in b[54..].iter_mut().enumerate() {
        *v = i as u8;
    }
    b
}
fn dma_frame(bytes: &[u8]) -> Frame {
    let mut buffer = alloc_coherent(bytes.len(), DomainId::DRIVER_0).unwrap();
    buffer.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
    Frame::new(buffer, bytes.len() as u32)
}

fn smoke_igc_tso_context_and_checksum_seed() -> TestResult {
    let mut b = tcp4(3000);
    let plan = TxPlan::prepare(&mut b, TxMeta::with_tso(1460), 3, 1500).unwrap();
    let c = plan.context.unwrap();
    check!(
        c.vlan_macip_lens == 0x1c14
            && c.type_tucmd_mlhl == 0x20200c00
            && c.mss_l4len_idx == 0x05b41400,
        "TSO context encoding wrong"
    );
    check!(
        plan.info == ((3000 << 14) | 0x300) && plan.command == 0xa2300000,
        "TSO data encoding wrong"
    );
    check!(
        b[16..18] == [0, 0] && b[24..26] == [0, 0] && b[50..52] == [0xec, 0x3d],
        "TSO checksum seed/header wrong"
    );
    let mut b = tcp4(0);
    let p = TxPlan::prepare(&mut b, TxMeta::with_csum(L4CsumKind::Tcp), 0, 1500).unwrap();
    check!(
        p.context.is_some() && b[50..52] == [0xec, 0x51],
        "checksum-only context/length seed missing"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_tso_context_and_checksum_seed);

fn smoke_igc_rejects_invalid_offloads() -> TestResult {
    let mut b = tcp4(3000);
    check!(
        TxPlan::prepare(&mut b, TxMeta::with_tso(0), 0, 1500).is_err(),
        "zero MSS accepted"
    );
    check!(
        TxPlan::prepare(&mut b, TxMeta::with_tso(1500), 0, 1500).is_err(),
        "oversize MSS accepted"
    );
    b[20] = 0x20;
    check!(
        TxPlan::prepare(&mut b, TxMeta::with_tso(1460), 0, 1500).is_err(),
        "fragment TSO accepted"
    );
    let mut b = tcp4(0);
    check!(
        TxPlan::prepare(&mut b, TxMeta::with_csum(L4CsumKind::Udp), 0, 1500).is_err(),
        "wrong L4 type accepted"
    );
    b[46] = 0xf0;
    check!(
        TxPlan::prepare(&mut b, TxMeta::with_tso(1400), 0, 1500).is_err(),
        "truncated TCP header accepted"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_rejects_invalid_offloads);

fn smoke_igc_ipv6_udp_and_vlan_offloads() -> TestResult {
    let mut b = vec![0; 62];
    b[12..14].copy_from_slice(&[0x86, 0xdd]);
    b[14] = 0x60;
    b[18..20].copy_from_slice(&8u16.to_be_bytes());
    b[20] = 17;
    b[58..60].copy_from_slice(&8u16.to_be_bytes());
    let mut meta = TxMeta::with_csum(L4CsumKind::Udp);
    meta.vlan_tag = Some(123);
    let p = TxPlan::prepare(&mut b, meta, 1, 1500).unwrap();
    let c = p.context.unwrap();
    check!(
        c.vlan_macip_lens == 0x007b1c28
            && c.type_tucmd_mlhl == 0x20200000
            && c.mss_l4len_idx == 0x800,
        "IPv6 UDP/VLAN context wrong"
    );
    check!(
        p.command == 0x62300000 && p.info & 0x300 == 0x200 && b[60..62] == [0, 25],
        "IPv6 checksum/VLAN data wrong"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_ipv6_udp_and_vlan_offloads);

fn smoke_igc_rx_checksum_status_bits() -> TestResult {
    let good = rx_metadata(0x73, 0x12345678);
    check!(
        good.csum_l3 && good.csum_l4 && good.rx_hash == 0x12345678,
        "RX checksum/hash missing"
    );
    let bad = rx_metadata(0x60000073, 1);
    check!(!bad.csum_l3 && !bad.csum_l4, "bad checksums trusted");
    let ignored = rx_metadata(0x77, 1);
    check!(!ignored.csum_l3 && !ignored.csum_l4, "IXSM ignored");
    let old = rx_metadata(0x83, 1);
    check!(!old.csum_l4, "unrelated bit interpreted as L4 checksum");
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_rx_checksum_status_bits);

fn smoke_igc_tx_owned_until_final_completion() -> TestResult {
    let q = Queue::new().unwrap();
    let m = Model::new();
    let frame = dma_frame(&tcp4(8000));
    let base = frame.buf().dma_addr().raw();
    check!(
        q.post(&m, 2, frame, TxMeta::with_tso(1460), 1500).is_ok(),
        "TX enqueue failed"
    );
    let end = m.value(0xe098) as usize;
    check!(end == 3, "context/scatter descriptor count wrong");
    // Model the device by decoding each actual ring descriptor. The bus
    // address stays independent of CPU pointers and covers exactly the frame.
    let mut covered = 0;
    for slot in 1..end {
        // SAFETY: software test inspects posted descriptors, no real device uses q.
        let desc = unsafe {
            ptr::read_volatile(
                q.tx_ring
                    .cpu_ptr_at::<crate::igc::AdvTxDataDesc>((slot * 16) as u64),
            )
        };
        check!(
            desc.buffer_addr == base + covered as u64,
            "scatter DMA address discontinuity"
        );
        covered += (desc.cmd_type_len & 0xffff) as usize;
        check!(
            (desc.cmd_type_len & 0x09000000 != 0) == (slot == end - 1),
            "intermediate EOP/RS set"
        );
    }
    check!(
        covered == 8054 && q.reclaim() == 0,
        "uncompleted frame reclaimed"
    );
    // Completing a context/intermediate slot is insufficient.
    // SAFETY: the test is the sole DMA model writer of this queue.
    unsafe {
        ptr::write_volatile(q.tx_ring.cpu_mut_ptr_at::<u32>(28), 1);
    }
    check!(q.reclaim() == 0, "intermediate DD released whole packet");
    // SAFETY: device model writes the final completion dword.
    unsafe {
        ptr::write_volatile(
            q.tx_ring
                .cpu_mut_ptr_at::<u32>(((end - 1) * 16 + 12) as u64),
            1,
        );
    }
    check!(
        q.reclaim() == 1 && q.reclaim() == 0,
        "final completion ownership not reclaimed exactly once"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_tx_owned_until_final_completion);

fn smoke_igc_tx_ring_full_and_wrap() -> TestResult {
    let q = Queue::new().unwrap();
    let m = Model::new();
    let b = tcp4(0);
    for _ in 0..255 {
        check!(
            q.post(&m, 0, dma_frame(&b), TxMeta::plain().with_more(true), 1500)
                .is_ok(),
            "ring filled early"
        );
    }
    check!(
        q.post(&m, 0, dma_frame(&b), TxMeta::plain(), 1500).is_err(),
        "sentinel overwritten"
    );
    check!(
        m.value(0xe018) == 255 && q.reclaim() == 0,
        "full ring/deferred doorbell wrong"
    );
    // SAFETY: test model owns all descriptor completion writes.
    unsafe {
        for slot in 0..255 {
            ptr::write_volatile(q.tx_ring.cpu_mut_ptr_at::<u32>((slot * 16 + 12) as u64), 1);
        }
    }
    check!(q.reclaim() == 255, "ordered completions not reclaimed");
    check!(
        q.post(&m, 0, dma_frame(&b), TxMeta::plain(), 1500).is_ok() && m.value(0xe018) == 0,
        "TX wrap failed"
    );
    // SAFETY: model's queues are unexposed; final retained packet may now be dropped.
    unsafe {
        q.reset_after_quiesce();
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_tx_ring_full_and_wrap);

fn inject(q: &Queue, slot: usize, bytes: &[u8], status: u32, hash: u32, vlan: u16) {
    // SAFETY: tests act as the sole DMA device. Resolve the programmed address
    // against the model's coherent identity DMA aperture only in this helper.
    let read = unsafe {
        ptr::read_volatile(
            q.rx_ring
                .cpu_ptr_at::<crate::queue::RxRead>((slot * 16) as u64),
        )
    };
    let cpu = narf_memory::PhysAddr::new(read.address).kernel_mut_ptr::<u8>();
    // SAFETY: descriptor points to its live 2048-byte model RX allocation.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), cpu, bytes.len());
        ptr::write_volatile(
            q.rx_ring.cpu_mut_ptr_at::<RxWriteback>((slot * 16) as u64),
            RxWriteback {
                info: 3,
                hash,
                status,
                length: bytes.len() as u16,
                vlan,
            },
        );
    }
}

fn smoke_igc_rx_scatter_vlan_and_metadata() -> TestResult {
    let q = Queue::new().unwrap();
    let m = Model::new();
    let bytes = tcp4(3000);
    inject(&q, 0, &bytes[..2048], 1, 0, 0);
    let (f, d) = q.receive(&m, 1, 9216, 1);
    check!(
        f.is_empty() && d == 0 && m.value(0xc058) == 0,
        "partial jumbo published or not rearmed"
    );
    inject(&q, 1, &bytes[2048..], 0x73, 0xdeadbeef, 0);
    let (f, d) = q.receive(&m, 1, 9216, 64);
    check!(
        f.len() == 1 && d == 0 && f[0].payload() == bytes && f[0].queue() == 1,
        "scatter jumbo corrupted"
    );
    check!(
        f[0].rx_meta().csum_l4 && f[0].rx_meta().rx_hash == 0xdeadbeef,
        "completion metadata misplaced"
    );
    let small = tcp4(0);
    inject(&q, 2, &small, 0x7b, 0x1234, 0x0123);
    let (f, d) = q.receive(&m, 1, 1500, 64);
    check!(
        f.len() == 1 && d == 0 && f[0].payload()[12..18] == [0x81, 0, 1, 0x23, 8, 0],
        "stripped VLAN not reconstructed"
    );
    check!(
        f[0].payload()[18..] == small[14..],
        "VLAN reinsertion damaged packet"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_rx_scatter_vlan_and_metadata);

fn smoke_igc_rx_errors_budget_and_wrap() -> TestResult {
    let q = Queue::new().unwrap();
    let m = Model::new();
    let b = tcp4(0);
    inject(&q, 0, &b, 0x80000001, 0, 0);
    inject(&q, 1, &b, 3, 0, 0);
    inject(&q, 2, &b, 3, 42, 0);
    let (frames, drops) = q.receive(&m, 0, 1500, 2);
    check!(
        frames.is_empty() && drops == 1 && m.value(0xc018) == 1,
        "bad partial packet/budget mishandled"
    );
    let (frames, drops) = q.receive(&m, 0, 1500, 1);
    check!(
        frames.len() == 1 && drops == 0 && frames[0].rx_meta().rx_hash == 42,
        "bad chain consumed next good packet"
    );
    for slot in 3..256 {
        inject(&q, slot, &b, 3, 0, 0);
    }
    let (frames, drops) = q.receive(&m, 0, 1500, 256);
    check!(
        frames.len() == 253 && drops == 0 && m.value(0xc018) == 255,
        "RX wrap tail wrong"
    );
    inject(&q, 0, &b, 3, 1, 0);
    let (frames, _) = q.receive(&m, 0, 1500, 1);
    check!(
        frames.len() == 1 && m.value(0xc018) == 0,
        "RX failed after wrap"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_rx_errors_budget_and_wrap);

fn smoke_igc_recovery_retains_dma_on_failure() -> TestResult {
    let queues = vec![Queue::new().unwrap()];
    let m = Model::new();
    check!(
        queues[0]
            .post(&m, 0, dma_frame(&tcp4(0)), TxMeta::plain(), 1500)
            .is_ok(),
        "enqueue failed"
    );
    m.stuck_master.set(true);
    check!(
        hardware::reset_queues(&m, &queues).is_err(),
        "stuck master reset succeeded"
    );
    // SAFETY: deterministic model observes the still-posted descriptor.
    let command = unsafe { ptr::read_volatile(queues[0].tx_ring.cpu_ptr_at::<u32>(8)) };
    check!(
        command == 0x2b300036 && queues[0].reclaim() == 0,
        "failed reset discarded live DMA ownership"
    );
    m.stuck_master.set(false);
    check!(
        hardware::reset_queues(&m, &queues).is_ok(),
        "reset retry failed"
    );
    // SAFETY: model checks the ring after acknowledged reset.
    let command = unsafe { ptr::read_volatile(queues[0].tx_ring.cpu_ptr_at::<u32>(8)) };
    check!(command == 0, "successful reset did not clear descriptors");
    check!(
        queues[0]
            .post(&m, 0, dma_frame(&tcp4(0)), TxMeta::plain(), 1500)
            .is_ok()
            && m.value(0xe018) == 1,
        "queue not reusable after reset"
    );
    // SAFETY: no physical device was attached to this model.
    unsafe {
        queues[0].reset_after_quiesce();
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_recovery_retains_dma_on_failure);

fn smoke_igc_phy_suspend_resume_sequence() -> TestResult {
    let m = Model::new();
    check!(hardware::setup_phy(&m, false).is_ok(), "PHY setup failed");
    check!(
        hardware::quiesce(&m, 4).is_ok() && hardware::power_down_phy(&m).is_ok(),
        "PHY suspend failed"
    );
    check!(
        m.phy_value(0) & 0x800 != 0 && m.value(0x5b5c) == 0,
        "suspend power/ownership incorrect"
    );
    check!(
        hardware::reset(&m, 4).is_ok() && hardware::setup_phy(&m, false).is_ok(),
        "PHY resume failed"
    );
    check!(
        m.phy_value(0) & 0x1e00 == 0x1200 && m.mmd.borrow().get(&(7, 32)) == Some(&0x80),
        "resume did not restore power/autoneg"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_phy_suspend_resume_sequence);

/// Normal QEMU has no I225. With --passthrough-device this tests the real
/// probe and device lifecycle; link/data traffic still needs a wired peer.
fn smoke_igc_live_controller_lifecycle() -> TestResult {
    let present = narf_bus::registry::devices()
        .iter()
        .any(|d| d.id.vendor == 0x8086 && crate::igc::SUPPORTED_DEVICE_IDS.contains(&d.id.device));
    if !present {
        return TestResult::Skip("no physical I225/I226 attached");
    }
    let Some(result) = crate::igc::with_controller(|c| {
        if !c.ready() || !hardware::valid_mac(c.mac()) {
            return TestResult::Fail("physical controller did not probe");
        }
        let name = crate::igc::igc_ifname();
        if name.is_empty() || !(1..=4).contains(&c.num_queues()) {
            return TestResult::Fail("physical queue/netdev publication failed");
        }
        if narf_net::iface::try_set_mtu(name, 9000).is_err()
            || c.mtu() != 9000
            || narf_net::iface::try_set_mtu(name, 9217) != Err(22)
            || narf_net::iface::lookup(name).unwrap().mtu != 9000
            || narf_net::iface::try_set_mtu(name, 1500).is_err()
        {
            return TestResult::Fail("physical MTU configuration failed");
        }
        let factory = c.mac();
        if narf_net::iface::try_set_mac(name, [2, 0, 0, 0, 0, 0x99]).is_err()
            || c.mac() != [2, 0, 0, 0, 0, 0x99]
            || narf_net::iface::try_set_mac(name, factory).is_err()
        {
            return TestResult::Fail("physical MAC configuration failed");
        }
        if c.recover().is_err() {
            return TestResult::Fail("physical reset recovery failed");
        }
        use narf_power::device_pm::DevicePmOps;
        if c.suspend().is_err() || c.ready() || c.resume().is_err() || !c.ready() {
            return TestResult::Fail("physical device suspend/resume failed");
        }
        TestResult::Pass
    }) else {
        return TestResult::Fail("physical I225/I226 present but probe failed");
    };
    result
}
kernel_test_in!("drivers/net/igc", smoke_igc_live_controller_lifecycle);

fn smoke_igc_rings_independent_geometry() -> TestResult {
    let m = Model::new();
    let q = Queue::new_sized(64, 128).unwrap();
    hardware::queue_sized(
        &m,
        3,
        q.tx_ring.dma_addr().raw(),
        q.rx_ring.dma_addr().raw(),
        64,
        128,
    )
    .unwrap();
    check!(
        m.value(0xe0c8) == 1024 && m.value(0xc0c8) == 2048 && m.value(0xc0d8) == 127,
        "independent ring lengths lost"
    );
    check!(
        Queue::new_sized(63, 128).is_err() && Queue::new_sized(64, 129).is_err(),
        "invalid ring size accepted"
    );
    for _ in 0..130 {
        q.post(&m, 3, dma_frame(&tcp4(0)), TxMeta::plain(), 1500)
            .unwrap();
        let tail = m.value(0xe0d8) as usize;
        let end = (tail + 63) % 64;
        // SAFETY: model is the sole DMA producer of this terminal DD.
        unsafe {
            ptr::write_volatile(q.tx_ring.cpu_mut_ptr_at::<u32>((end * 16 + 12) as u64), 1);
        }
        q.reclaim();
    }
    check!(q.statistics()[1] == 130, "ring wrap lost completions");
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_rings_independent_geometry);

fn smoke_igc_phy_policy_pause_eee_wake() -> TestResult {
    use narf_net::nic::{LinkSettings, Pause};
    let m = Model::new();
    let pause = Pause {
        autoneg: true,
        rx: true,
        tx: false,
    };
    hardware::setup_phy_policy(
        &m,
        false,
        &LinkSettings {
            advertised: 0x38,
            ..Default::default()
        },
        pause,
        true,
    )
    .unwrap();
    check!(
        m.phy_value(4) & 0xfe0 == 0xd00 && m.phy_value(9) & 0x300 == 0x200,
        "advertisement/pause policy wrong"
    );
    check!(
        *m.mmd.borrow().get(&(7, 60)).unwrap() == 6 && *m.mmd.borrow().get(&(7, 62)).unwrap() == 1,
        "EEE PHY advertisement wrong"
    );
    check!(
        m.value(0xe38) & 0x1c == 0x1c && m.value(0xe30) & 0x70000 == 0x70000,
        "EEE MAC policy wrong"
    );
    check!(
        hardware::resolve_pause(0xc00, 0x800, pause) == (true, false),
        "asymmetric RX pause resolution wrong"
    );
    check!(
        hardware::resolve_pause(0x400, 0x800, pause) == (false, false),
        "incompatible pause enabled"
    );
    m.mmd.borrow_mut().extend([((7, 61), 6), ((7, 63), 1)]);
    m.regs.borrow_mut().insert(0xe30, 0x20070000);
    m.regs.borrow_mut().insert(8, 0x400083);
    let eee = hardware::eee_status(&m).unwrap();
    check!(
        eee.active && eee.advertised == 0x38 && eee.partner == 0x38,
        "negotiated EEE status not reported"
    );
    m.regs.borrow_mut().insert(8, 0);
    check!(
        hardware::wake(&m, 0x2f).unwrap() && m.value(0x5808) == 0x1f && m.value(0x5800) == 2,
        "Linux wake flags not translated"
    );
    check!(m.phy_value(0) & 0x800 == 0, "wake PHY powered down");
    hardware::wake(&m, 0).unwrap();
    check!(
        m.value(0x5808) == 0 && m.phy_value(0) & 0x800 != 0,
        "disabled wake left PHY powered"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_phy_policy_pause_eee_wake);

fn smoke_igc_clock_frequency_and_timestamp_slots() -> TestResult {
    let m = Model::new();
    crate::ptp::write(&m, 12_000_000_123).unwrap();
    check!(
        crate::ptp::read(&m).unwrap() == 12_000_000_123,
        "clock seconds/nanos split wrong"
    );
    crate::ptp::frequency(&m, -1000).unwrap();
    check!(
        m.value(0xb608) == 0x800035af,
        "negative frequency conversion wrong"
    );
    let before = m.writes.borrow().len();
    check!(
        crate::ptp::frequency(&m, 62_500_000).is_err() && m.writes.borrow().len() == before,
        "invalid frequency wrote hardware"
    );
    let mut clock = crate::ptp::ClockState::new();
    clock.config = narf_net::nic::TimestampConfig { tx: true, rx: true };
    crate::ptp::configure(&m, 4, clock.config);
    check!(
        m.value(0xc0cc) & 0x40064000 == 0x40004000 && m.value(0xb620) == 0x418,
        "RX clock selector or timestamp mode wrong"
    );
    check!(
        clock.reserve(2, 77, 0).unwrap() == 0xa0000 && clock.reserve(2, 88, 0).is_err(),
        "TX timestamp slot overwritten"
    );
    m.regs
        .borrow_mut()
        .extend([(8, 0x82), (0xb614, 4), (0xb6b8, 123), (0xb6bc, 12)]);
    clock.collect(&m, 10);
    let event = clock.events.pop_front().unwrap();
    check!(
        event.cookie == 77 && event.nanoseconds == 12_000_000_203,
        "TX timestamp/latency wrong"
    );
    clock.reserve(2, 88, 0).unwrap();
    m.regs.borrow_mut().insert(0xb614, 0);
    clock.collect(&m, 1_000_000_001);
    check!(
        clock.timeouts == 1 && clock.pending[2].is_none(),
        "TX timestamp timeout retained busy register"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_clock_frequency_and_timestamp_slots
);

fn smoke_igc_rx_timestamp_prefix_and_truncation() -> TestResult {
    let q = Queue::new().unwrap();
    let m = Model::new();
    m.regs.borrow_mut().insert(8, 0x82);
    let packet = tcp4(0);
    let mut bytes = vec![0; 16];
    bytes[8..12].copy_from_slice(&1234u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&9u32.to_le_bytes());
    bytes.extend_from_slice(&packet);
    inject(&q, 0, &bytes, 0x8003, 0, 0);
    let (frames, drops) = q.receive(&m, 0, 1500, 1);
    check!(
        drops == 0
            && frames.len() == 1
            && frames[0].payload() == packet
            && frames[0].offset() == 16,
        "timestamp prefix delivered as Ethernet"
    );
    check!(
        frames[0].rx_meta().timestamp_ns == Some(9_000_000_934),
        "RX timestamp clock/latency wrong"
    );
    inject(&q, 1, &[0; 8], 0x8003, 0, 0);
    let (f, d) = q.receive(&m, 0, 1500, 1);
    check!(f.is_empty() && d == 1, "truncated timestamp accepted");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_rx_timestamp_prefix_and_truncation
);

fn smoke_igc_gate_validation_and_cbs_registers() -> TestResult {
    use narf_net::nic::{Gate, Shaper, TrafficSchedule};
    let m = Model::new();
    let config = TrafficSchedule {
        base_time_ns: 0,
        cycle_ns: 10000,
        gates: vec![
            Gate {
                mask: 1,
                interval_ns: 4000,
            },
            Gate {
                mask: 2,
                interval_ns: 6000,
            },
        ],
        shapers: vec![Shaper {
            queue: 0,
            idle_slope_kbps: 100000,
            send_slope_kbps: -2400000,
            high_credit: 10,
            low_credit: -100,
        }],
        ..Default::default()
    };
    let schedule = crate::traffic::Schedule::validate(config.clone(), 2, 15000).unwrap();
    let extra = crate::traffic::Schedule::validate(config.clone(), 3, 15000).unwrap();
    check!(
        extra.windows[2] == (10000, 10000),
        "permanently closed gate was programmed as an open cycle"
    );
    check!(
        schedule.base == 20000,
        "past base not advanced to next cycle"
    );
    schedule.apply(&m, 2, true);
    check!(
        m.value(0x3324) == 0
            && m.value(0x3334) == 4000
            && m.value(0x3328) == 4000
            && m.value(0x3338) == 10000,
        "gate windows wrong"
    );
    check!(
        m.value(0x3004) == 0x4000098a && m.value(0x3344) == 0x86 && m.value(0x300c) == 0x8004a81c,
        "CBS credits/slope wrong"
    );
    let mut bad = config;
    bad.gates = vec![
        Gate {
            mask: 1,
            interval_ns: 3000,
        },
        Gate {
            mask: 2,
            interval_ns: 3000,
        },
        Gate {
            mask: 1,
            interval_ns: 4000,
        },
    ];
    let count = m.writes.borrow().len();
    check!(
        crate::traffic::Schedule::validate(bad, 2, 0).is_err() && m.writes.borrow().len() == count,
        "unrepresentable gate schedule wrote MMIO"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_gate_validation_and_cbs_registers
);

fn smoke_igc_launch_next_cycle_workaround() -> TestResult {
    use narf_net::nic::TrafficSchedule;
    let m = Model::new();
    let q = Queue::new().unwrap();
    let schedule = crate::traffic::Schedule::validate(
        TrafficSchedule {
            base_time_ns: 1_000_000,
            cycle_ns: 1_000_000,
            launch_time_queues: 1,
            ..Default::default()
        },
        1,
        0,
    )
    .unwrap();
    let launch = schedule.launch(0, 2_100_000, 1_010_000).unwrap();
    q.post_options(
        &m,
        0,
        dma_frame(&tcp4(0)),
        TxMeta::plain(),
        1500,
        crate::queue::TxOptions {
            launch: Some(launch),
            ..Default::default()
        },
    )
    .unwrap();
    // SAFETY: model inspects descriptors after the production release/TDT.
    let (empty, ctx) = unsafe {
        (
            ptr::read_volatile(q.tx_ring.cpu_ptr_at::<crate::igc::AdvTxCtxtDesc>(0)),
            ptr::read_volatile(q.tx_ring.cpu_ptr_at::<crate::igc::AdvTxCtxtDesc>(32)),
        )
    };
    check!(
        m.value(0xe018) == 4
            && empty.launch_time == 0
            && empty.mss_l4len_idx == 0
            && ctx.launch_time == 100000
            && ctx.mss_l4len_idx == 0x80,
        "next-cycle empty frame/context FIRST wrong"
    );
    check!(
        schedule.launch(0, 3_100_000, 1_010_000).is_err(),
        "unencodable launch horizon accepted"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_launch_next_cycle_workaround);

fn smoke_igc_merge_verification_and_retry_limit() -> TestResult {
    let mut merge = crate::merge::Merge::new();
    merge.config = narf_net::nic::Preemption {
        enabled: true,
        tx_enabled: true,
        verify: true,
        verify_ms: 10,
        minimum_fragment: 128,
    };
    check!(
        merge.tick(0, true, 2) == (true, false) && !merge.status.active,
        "unsolicited response enabled preemption"
    );
    merge.tick(1, true, 4);
    merge.tick(2, true, 2);
    check!(
        merge.status.active && merge.status.verified,
        "verified partner did not enable preemption"
    );
    let m = Model::new();
    merge.apply(&m, 2, 1);
    check!(
        m.value(0x3344) & 8 != 0
            && m.value(0xe068) & (1 << 27) != 0
            && m.value(0x3570) & 0xc002 == 0x4002,
        "merge express/preemptible programming wrong"
    );
    merge.tick(3, false, 0);
    check!(
        !merge.status.active && !merge.status.verified,
        "link loss kept verified partner"
    );
    merge.tick(4, true, 0);
    merge.tick(10_000_004, true, 0);
    merge.tick(20_000_004, true, 0);
    merge.tick(30_000_004, true, 0);
    check!(
        merge.status.failed && merge.status.attempts == 3,
        "verification retries unbounded"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_merge_verification_and_retry_limit
);

fn smoke_igc_smd_control_packets() -> TestResult {
    let m = Model::new();
    let q = Queue::new().unwrap();
    q.post_smd(&m, 1).unwrap();
    // SAFETY: model marks the single SMD descriptor complete.
    // SAFETY: model publishes terminal DD in the live software-owned ring.
    unsafe {
        ptr::write_volatile(q.tx_ring.cpu_mut_ptr_at::<u32>(12), 1);
    }
    q.reclaim();
    check!(q.merge_events() == 4, "SMD-V DD not reported");
    inject(&q, 0, &[0; 60], 0x4003, 0, 0);
    let (f, d) = q.receive(&m, 0, 1500, 1);
    check!(
        f.is_empty() && d == 0 && q.merge_events() == 2,
        "SMD-R leaked into protocol stack"
    );
    let mut stamp = [0u8; 76];
    stamp[8] = 123;
    inject(&q, 1, &stamp, 0xc003, 0, 0);
    let (f, d) = q.receive(&m, 0, 1500, 1);
    check!(
        f.is_empty() && d == 0 && q.merge_events() == 2,
        "timestamp prefix hid SMD-R control packet"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_smd_control_packets);

fn smoke_igc_flow_filters_and_validation() -> TestResult {
    use narf_net::nic::FlowRule;
    let m = Model::new();
    let rules = vec![
        FlowRule {
            location: 0,
            queue: 2,
            ethertype: Some(0x88f7),
            destination_mac: None,
            vlan_priority: None,
        },
        FlowRule {
            location: 1,
            queue: 1,
            ethertype: None,
            destination_mac: Some([2, 1, 2, 3, 4, 5]),
            vlan_priority: None,
        },
        FlowRule {
            location: 2,
            queue: 3,
            ethertype: None,
            destination_mac: None,
            vlan_priority: Some(7),
        },
    ];
    crate::traffic::validate_flows(&rules, 4, 0).unwrap();
    crate::traffic::flows(&m, &rules, 1);
    check!(
        m.value(0x5cb0) == 0x840288f7
            && m.value(0x540c) == 0x90040504
            && m.value(0x55b0) == 0xb0000000,
        "flow filter register encoding wrong"
    );
    let mut bad = rules.clone();
    bad.push(rules[0].clone());
    check!(
        crate::traffic::validate_flows(&bad, 4, 0).is_err(),
        "duplicate rule accepted"
    );
    check!(
        crate::traffic::validate_flows(&rules, 2, 0).is_err(),
        "filter targets absent queue"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_flow_filters_and_validation);

fn smoke_igc_sctp_crc_descriptor() -> TestResult {
    let mut bytes = tcp4(0);
    bytes.truncate(46);
    bytes[16..18].copy_from_slice(&32u16.to_be_bytes());
    bytes[23] = 132;
    bytes[42..46].fill(0xaa);
    let p = TxPlan::prepare(&mut bytes, TxMeta::with_csum(L4CsumKind::Sctp), 0, 1500).unwrap();
    check!(
        p.context.unwrap().type_tucmd_mlhl == 0x20201400
            && p.info & 0x300 == 0x300
            && bytes[42..46] == [0; 4],
        "SCTP used TCP/UDP checksum seed"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/net/igc", smoke_igc_sctp_crc_descriptor);

fn smoke_igc_xsk_direct_dma_completion_and_duplicate_fill() -> TestResult {
    use narf_net::bypass::{
        umem::Umem,
        xdp::{UmemSlot, XdpSocket},
    };
    let m = Model::new();
    let q = Queue::new().unwrap();
    let umem = Umem::register(4096 * 4, 4096).unwrap();
    let mut parts = XdpSocket::create(umem.clone());
    parts
        .fill_prod
        .try_send(
            UmemSlot {
                frame_idx: 0,
                len: 0,
            }
            .pack(),
        )
        .unwrap();
    parts
        .fill_prod
        .try_send(
            UmemSlot {
                frame_idx: 0,
                len: 0,
            }
            .pack(),
        )
        .unwrap();
    parts
        .fill_prod
        .try_send(
            UmemSlot {
                frame_idx: 1,
                len: 0,
            }
            .pack(),
        )
        .unwrap();
    // SAFETY: new queues have never reached hardware.
    unsafe {
        q.bind_xsk(Some(parts.socket.clone()));
        q.reset_after_quiesce();
    }
    // SAFETY: inspect the software-armed RX descriptors.
    let (a, b) = unsafe {
        (
            ptr::read_volatile(q.rx_ring.cpu_ptr_at::<crate::queue::RxRead>(0)),
            ptr::read_volatile(q.rx_ring.cpu_ptr_at::<crate::queue::RxRead>(16)),
        )
    };
    check!(
        a.address == umem.desc().base_phys && b.address == umem.desc().base_phys + 4096,
        "duplicate FILL aliased active DMA"
    );
    inject(&q, 0, &tcp4(0), 3, 0, 0);
    let (f, d) = q.receive(&m, 0, 1500, 1);
    let slot = UmemSlot::unpack(parts.rx_cons.try_recv().unwrap().unwrap());
    check!(
        f.is_empty() && d == 0 && slot.frame_idx == 0 && slot.len == 54,
        "direct UMEM RX copied into stack"
    );
    parts
        .tx_prod
        .try_send(
            UmemSlot {
                frame_idx: 2,
                len: 54,
            }
            .pack(),
        )
        .unwrap();
    q.poll_xsk(&m, 0, 1500);
    // SAFETY: inspect posted TX, then act as the device publishing final DD.
    let desc = unsafe { ptr::read_volatile(q.tx_ring.cpu_ptr_at::<crate::igc::AdvTxDataDesc>(0)) };
    check!(
        desc.buffer_addr == umem.desc().base_phys + 8192 && umem.lease(2).is_err(),
        "TX copied or released before DD"
    );
    check!(
        parts.comp_cons.try_recv().unwrap().is_none(),
        "completion before DD"
    );
    // SAFETY: model publishes terminal DD in the live software-owned ring.
    unsafe {
        ptr::write_volatile(q.tx_ring.cpu_mut_ptr_at::<u32>(12), 1);
    }
    q.reclaim();
    let done = UmemSlot::unpack(parts.comp_cons.try_recv().unwrap().unwrap());
    check!(
        done.frame_idx == 2 && umem.lease(2).is_ok(),
        "DD failed to return ownership"
    );
    q.set_gate_closed(true);
    let tail = m.value(0xe018);
    check!(
        q.post(&m, 0, dma_frame(&tcp4(0)), TxMeta::plain(), 1500)
            .is_err(),
        "permanently closed queue accepted a frame"
    );
    parts
        .tx_prod
        .try_send(
            UmemSlot {
                frame_idx: 3,
                len: 54,
            }
            .pack(),
        )
        .unwrap();
    q.poll_xsk(&m, 0, 1500);
    let rejected = UmemSlot::unpack(parts.comp_cons.try_recv().unwrap().unwrap());
    check!(
        rejected.frame_idx == 3
            && umem.lease(3).is_ok()
            && m.value(0xe018) == tail
            && q.statistics()[4] == 0,
        "closed gate published DMA or retained rejected UMEM ownership"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_xsk_direct_dma_completion_and_duplicate_fill
);

fn smoke_igc_xsk_rx_backpressure_recycles_unpublished_buffer() -> TestResult {
    use narf_net::bypass::{
        umem::Umem,
        xdp::{UmemSlot, XdpSocket},
    };
    let m = Model::new();
    let q = Queue::new().unwrap();
    let umem = Umem::register(8192, 4096).unwrap();
    let mut parts = XdpSocket::create(umem.clone());
    parts
        .fill_prod
        .try_send(
            UmemSlot {
                frame_idx: 0,
                len: 0,
            }
            .pack(),
        )
        .unwrap();
    // SAFETY: model queues have never been exposed to hardware.
    unsafe {
        q.bind_xsk(Some(parts.socket.clone()));
    }
    for _ in 0..64 {
        parts
            .socket
            .push_rx(UmemSlot {
                frame_idx: 1,
                len: 54,
            })
            .unwrap();
    }
    inject(&q, 0, &tcp4(0), 3, 0, 0);
    let (frames, drops) = q.receive(&m, 0, 1500, 1);
    check!(
        frames.is_empty() && drops == 1 && umem.lease(0).is_err(),
        "RX backpressure lost the unpublished UMEM frame"
    );
    // SAFETY: the model has no outstanding hardware transactions.
    unsafe {
        q.reset_after_quiesce();
    }
    // SAFETY: model owns this software-armed descriptor and its DMA allocation.
    let read = unsafe { ptr::read_volatile(q.rx_ring.cpu_ptr_at::<crate::queue::RxRead>(0)) };
    check!(
        read.address == umem.desc().base_phys,
        "unpublished buffer was not reused for RX"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_xsk_rx_backpressure_recycles_unpublished_buffer
);

fn smoke_igc_clear_on_read_statistics_persist() -> TestResult {
    struct Clear(Model);
    impl Registers for Clear {
        fn read(&self, reg: u64) -> u32 {
            let v = self.0.read(reg);
            if (0x4000..0x4200).contains(&reg) {
                self.0.regs.borrow_mut().insert(reg, 0);
            }
            v
        }
        fn write(&self, reg: u64, value: u32) {
            self.0.write(reg, value)
        }
        fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool {
            self.0.wait(us, ready)
        }
        fn delay(&self, us: u64) {
            self.0.delay(us)
        }
    }
    let m = Clear(Model::new());
    m.0.regs.borrow_mut().extend([
        (0x4000, 3),
        (0x4010, 7),
        (0x4074, 12),
        (0x4088, 0x12345678),
        (0x408c, 2),
        (0xc030, 9),
    ]);
    let mut counters = crate::counters::Counters::new();
    check!(
        counters.sample(&m, 1, false) == (3, 7, 9),
        "counter deltas lost"
    );
    counters.sample(&m, 1, false);
    check!(
        counters.value(0x4088) == 0x212345678
            && counters.value(0x4074) == 12
            && counters.drops[0] == 9,
        "clear-on-read totals lost or counted twice"
    );
    m.0.regs.borrow_mut().insert(0x4074, 11);
    counters.sample(&m, 1, true);
    check!(
        counters.value(0x4074) == 12,
        "inherited counters corrupted software totals"
    );
    check!(
        counters.snapshot().len() > 55,
        "hardware counter coverage incomplete"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_clear_on_read_statistics_persist
);
fn smoke_igc_nvm_reads_odd_ranges_without_writes() -> TestResult {
    let m = Model::new();
    let bytes = hardware::read_nvm(&m, 1, 5).unwrap();
    check!(
        bytes == [0x5a, 0xa4, 0x5a, 0xa7, 0x5a],
        "odd NVM byte range wrong"
    );
    check!(
        m.value(0x5b5c) & 1 == 0 && m.value(0x5b50) & 3 == 0,
        "NVM semaphore not released"
    );
    let before = m.writes.borrow().len();
    check!(
        hardware::read_nvm(&m, u32::MAX, 2).is_err() && m.writes.borrow().len() == before,
        "overflowing NVM range touched MMIO"
    );
    check!(
        !m.writes
            .borrow()
            .iter()
            .any(|(reg, _)| matches!(*reg, 0x12018 | 0x1201c)),
        "NVM write command issued"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_nvm_reads_odd_ranges_without_writes
);
fn smoke_igc_timestamp_timeout_quarantine_and_clock_rate() -> TestResult {
    let m = Model::new();
    let mut clock = crate::ptp::ClockState::new();
    clock.config.tx = true;
    clock.reserve(1, 17, 0).unwrap();
    clock.collect(&m, 1_000_000_001);
    check!(
        clock.reserve(1, 18, 1_000_000_002).is_err(),
        "timed-out timestamp slot reused before terminal arrival"
    );
    check!(
        clock.events.pop_front().unwrap().error == Some(110),
        "timestamp timeout lost error completion"
    );
    m.regs.borrow_mut().insert(0xb614, 2);
    clock.collect(&m, 1_000_000_003);
    check!(
        clock.reserve(1, 18, 1_000_000_004).is_ok(),
        "late timestamp did not retire quarantine"
    );
    clock.cancel(19);
    let cancelled = clock.events.pop_front().unwrap();
    check!(
        cancelled.cookie == 18
            && cancelled.error == Some(19)
            && clock.pending.iter().all(Option::is_none)
            && clock.reserve(1, 19, 1_000_000_005).is_err(),
        "device removal lost cancellation or released a live timestamp slot"
    );
    clock.reserve(0, 20, 1_000_000_005).unwrap();
    m.regs.borrow_mut().insert(0xb614, 1);
    m.regs.borrow_mut().insert(0xb618, u32::MAX);
    clock.collect(&m, 1_000_000_006);
    check!(
        clock.events.pop_front().unwrap().error == Some(5),
        "invalid hardware timestamp lost its terminal error"
    );
    check!(
        crate::ptp::advance(3_000_000_000, 2_000_000_000, 1000) == 5_000_002_000
            && crate::ptp::advance(3_000_000_000, 2_000_000_000, -1000) == 4_999_998_000,
        "reset clock continuity ignored adjusted frequency"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/igc",
    smoke_igc_timestamp_timeout_quarantine_and_clock_rate
);
