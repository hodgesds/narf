// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE native packet/station owner over a register-file and DMA model.
//! Written; not yet executed (no QEMU in this lane).
use super::super::super::super::{
    btcoex::btc::{ChipInterface, ChipType, HwPg, Packet},
    firmware_transport::{Error as AccessError, Io},
    rtl8723be::{
        adapter, dm, envelope, h2c, init, mac, station as hw, tests as be, txpower, version,
    },
};
use super::super::super::{Chip, Error, Memory, Phase, Prepared, RX_BASE, TX_BASES};
use super::super::{Port, OWN};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone)]
pub(crate) struct Block {
    address: u64,
    bytes: Arc<IrqSafeSpinLock<Vec<u8>>>,
}
// SAFETY: inert synthetic extents shared only with this model; no synthetic
// address is a CPU pointer or reaches a physical bus.
unsafe impl Memory for Block {
    fn address(&self) -> u64 {
        self.address
    }
    fn len(&self) -> usize {
        self.bytes.lock().len()
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.write_bytes(offset, &value.to_le_bytes())
    }
    fn read32(&self, offset: usize) -> Result<u32, Error> {
        let mut b = [0; 4];
        self.read_bytes(offset, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.bytes
            .lock()
            .get_mut(offset..offset + bytes.len())
            .ok_or(Error::Memory)?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn read_bytes(&self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.copy_from_slice(
            self.bytes
                .lock()
                .get(offset..offset + bytes.len())
                .ok_or(Error::Memory)?,
        );
        Ok(())
    }
    fn sync(&self) {}
}

struct Model {
    regs: Vec<u8>,
    writes: Vec<(u8, u16, u32)>,
    kicks: Vec<u16>,
    master: bool,
    events: Vec<(bool, u16)>,
    yield_delay: bool,
    next: u64,
    deny: bool,
    fail_write32: Option<u16>,
}
#[derive(Clone)]
pub(crate) struct BePort(Arc<IrqSafeSpinLock<Model>>);
impl BePort {
    pub(crate) fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            // The hardware radio switch reads on (REG_GPIO_PIN_CTRL_2
            // 0x60 bit 1), as on a board with the switch pulled up.
            regs: {
                let mut regs = vec![0; 0x1000];
                regs[0x60] = 1 << 1;
                regs
            },
            writes: Vec::new(),
            kicks: Vec::new(),
            master: false,
            events: Vec::new(),
            yield_delay: false,
            next: 0x10_0000,
            deny: false,
            fail_write32: None,
        })))
    }
    fn block(&self, bytes: usize) -> Block {
        let mut m = self.0.lock();
        let block = Block {
            address: m.next,
            bytes: Arc::new(IrqSafeSpinLock::new(vec![0; bytes])),
        };
        m.next += 0x1_0000;
        block
    }
    fn reg8(&self, reg: u16) -> u8 {
        self.0.lock().regs[usize::from(reg)]
    }
    fn reg32(&self, reg: u16) -> u32 {
        let m = self.0.lock();
        let r = usize::from(reg);
        u32::from_le_bytes(m.regs[r..r + 4].try_into().unwrap())
    }
    fn set8(&self, reg: u16, value: u8) {
        self.0.lock().regs[usize::from(reg)] = value;
    }
    fn set32(&self, reg: u16, value: u32) {
        let r = usize::from(reg);
        self.0.lock().regs[r..r + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn wrote(&self, width: u8, reg: u16, value: u32) -> Option<usize> {
        self.0
            .lock()
            .writes
            .iter()
            .position(|w| *w == (width, reg, value))
    }
}
#[async_trait::async_trait]
impl Io for BePort {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        if self.0.lock().deny {
            return Err(AccessError::Access);
        }
        Ok(self.reg8(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        if self.0.lock().deny {
            return Err(AccessError::Access);
        }
        Ok(self.reg32(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        if m.deny {
            return Err(AccessError::Access);
        }
        // The modelled firmware takes every H2C box at once and reports
        // BCN_VALID for every reserved-page upload.
        m.regs[usize::from(reg)] = match reg {
            0x20a => value | 1,
            _ => value,
        };
        m.writes.push((1, reg, value.into()));
        m.events.push((false, reg));
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        if m.deny {
            return Err(AccessError::Access);
        }
        let r = usize::from(reg);
        m.regs[r..r + 2].copy_from_slice(&value.to_le_bytes());
        m.writes.push((2, reg, value.into()));
        m.events.push((false, reg));
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        if m.deny || m.fail_write32 == Some(reg) {
            return Err(AccessError::Access);
        }
        let r = usize::from(reg);
        m.regs[r..r + 4].copy_from_slice(&value.to_le_bytes());
        m.writes.push((4, reg, value));
        m.events.push((false, reg));
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), AccessError> {
        Err(AccessError::Access)
    }
    async fn delay_us(&self, _micros: u64) {
        let yield_delay = self.0.lock().yield_delay;
        if yield_delay {
            let mut first = true;
            core::future::poll_fn(|cx| {
                if core::mem::take(&mut first) {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
        }
    }
}
impl Port for BePort {
    type Buffer = Block;
    fn authority<T>(
        &self,
        _active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.0.lock().deny {
            return Err(Error::State);
        }
        operation()
    }
    fn allocate_packet(&self, bytes: usize) -> Result<Block, Error> {
        Ok(self.block(bytes))
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.0.lock().master = enabled;
        Ok(())
    }
    fn kick(&self, queue_bit: u16) -> Result<(), Error> {
        let mut model = self.0.lock();
        model.kicks.push(queue_bit);
        model.events.push((true, queue_bit));
        Ok(())
    }
}

fn run<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("unexpected 8723BE model wait"),
    }
}

const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
/// A trimmed RCR as `rtl8723be_phy_mac_config` leaves it.
const RCR: u32 = 0xf400_7a0e;

/// A MacConfigured 8723BE owner with published rings (as `prepare` would
/// leave them), a bound coexistence owner (no BT), a configured radio and
/// an `NAPC` permission for channel 6 / 20 MHz, or — with `forty` — a v2
/// permission for 40 MHz (primary 3 above).
fn owner_with(forty: bool) -> Option<(Prepared<BePort, Block>, BePort)> {
    let port = BePort::new();
    let mut owner =
        Prepared::allocate_for(Chip::Rtl8723be, port.clone(), 4, |b| Ok(port.block(b))).ok()?;
    for (reg, ring) in TX_BASES.iter().zip(&owner.tx) {
        port.set32(*reg, ring.address() as u32);
    }
    port.set32(RX_BASE, owner.receive.as_ref()?.address() as u32);
    let factory = be::be_factory();
    let (fixture, operating) = if forty {
        (
            be::be_napc_fixture(
                2,
                0,
                80,
                &[
                    (6, 20, 0, be::be_rising),
                    (3, 40, 1, be::be_rising),
                    (9, 40, 2, be::be_rising),
                ],
            ),
            envelope::Operating {
                width: envelope::Width::W40Above,
                channel: 3,
            },
        )
    } else {
        (
            be::be_napc_fixture(1, 0, 80, &[(6, 20, 0, be::be_rising)]),
            envelope::Operating::twenty(6),
        )
    };
    let cal = envelope::Calibration::from_verified(&fixture, Some([0xab; 32]), &factory).ok()?;
    owner.rtl8723be_power = Some(cal.permission_for(&be::be_us_domain(), operating).ok()?);
    let logical = be::provisioned();
    let facts = adapter::Adapter::from_hardware(
        version::Version::from_registers(version::CHIP_8723B, 0).ok()?,
        adapter::CR9346_AUTOLOAD_OK,
        0,
        &logical,
        0,
    )
    .ok()?;
    let radio = init::Radio {
        adapter: facts,
        cck_high_power: false,
        chnlval: [0; 2],
        receive_config: RCR,
        efuse: txpower::Efuse::from_logical(&logical).ok()?,
        by_rate: txpower::ByRate::from_table(),
        iqk: None,
    };
    owner.rtl8723be = Some(Box::new((
        crate::rtlwifi::radio::factory_identity(&factory),
        radio,
    )));
    owner.rtl8723be_coex = Some(Box::new(
        super::super::super::super::rtl8723be::coex::Owner::bind(HwPg {
            bt_exist: false,
            ant_num: 2,
            single_ant_path: 0,
            chip_type: ChipType::Rtl8723b,
            package_type: 0,
            rfe_type: 0,
            interface: ChipInterface::Pci,
        }),
    ));
    owner.packet.local = Some(factory.mac);
    owner.published = true;
    owner.phase = Phase::MacConfigured;
    Some((owner, port))
}

fn owner() -> Option<(Prepared<BePort, Block>, BePort)> {
    owner_with(false)
}

fn owner40() -> Option<(Prepared<BePort, Block>, BePort)> {
    owner_with(true)
}

pub(crate) fn station_fixture() -> Option<(Prepared<BePort, Block>, BePort)> {
    let (mut owner, port) = owner()?;
    let factory = be::be_factory();
    let fixture = be::be_napc_fixture(1, 0, 80, &[(6, 20, 0, be::be_rising)]);
    let cal = envelope::Calibration::from_verified(&fixture, Some([0xab; 32]), &factory).ok()?;
    owner
        .stage_rtl8723be_calibration(cal, &be::be_us_domain())
        .ok()?;
    owner.start_packets().ok()?;
    run(owner.prepare_station_peer(PEER, 0xfff, 0x15, 0x421)).ok()?;
    Some((owner, port))
}
impl BePort {
    pub(crate) fn special_events(&self) -> Vec<(bool, u16)> {
        self.0.lock().events.clone()
    }
    pub(crate) fn stall_special(&self) {
        let mut model = self.0.lock();
        model.regs[0x1cc] = 0xff;
        model.yield_delay = true;
    }
    pub(crate) fn deny_special(&self) {
        self.0.lock().deny = true;
    }
}

#[path = "packet_owner_tests/edca.rs"]
mod edca;

fn tx_word(owner: &Prepared<BePort, Block>, queue: usize, slot: usize, word: usize) -> u32 {
    owner.tx[queue].read32(slot * 64 + word * 4).unwrap()
}

/// `rtl8723be_hw_init`'s DMA release and `set_network_type(STATION)`, one
/// `rtl8723be_tx_fill_desc` management frame (forced 1M, DISFB, HWSEQ, MC
/// rate id), its host receipt, the `NAPC` rate gate, a legacy RX frame and a
/// `rpt_sel` C2H buffer queued for the coexistence dispatch.
fn smoke_rtl8723be_native_owner_start_descriptors_receipt_and_rx() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    if owner.start_packets().is_err() || owner.phase != Phase::Running {
        return TestResult::Fail("start_packets refused a prepared owner");
    }
    let cr = port.wrote(2, 0x100, 0x2ff);
    let dma = port.wrote(1, 0x301, 0);
    if !port.0.lock().master
        || cr.is_none()
        || dma.is_none()
        || cr > dma
        || port.reg32(mac::REG_RCR) != RCR & !(hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN)
        || port.reg8(hw::MSR) & 3 != hw::MSR_NOLINK
        || port.reg8(hw::REG_BCNTCFG + 1) != 0x66
        || port.reg8(h2c::REG_BCN_CTRL) != (0x1d & !2) | 0x10
    {
        return TestResult::Fail("hw_init DMA release / set_network_type(STATION) differ");
    }
    let mut probe = vec![0u8; 30];
    probe[0] = 0x40;
    probe[4..10].copy_from_slice(&[0xff; 6]);
    probe[10..16].copy_from_slice(&be::be_factory().mac);
    probe[16..22].copy_from_slice(&[0xff; 6]);
    let slot = owner.packet.next[1];
    let Ok(id) = owner.submit(&probe, 0) else {
        return TestResult::Fail("management submit");
    };
    let buffer = owner
        .packet
        .pending
        .as_ref()
        .map(|p| p.buffer.address() as u32);
    let next = owner.tx[1].address() as u32 + (((slot + 1) % 4) * 64) as u32;
    let dw0 = 30 | (40 << 16) | (1 << 24) | (1 << 26) | (1 << 27) | OWN;
    if tx_word(&owner, 1, slot, 0) != dw0
        || tx_word(&owner, 1, slot, 1) != (0x12 << 8) | (7 << 16)
        || tx_word(&owner, 1, slot, 3) != (1 << 8) | (1 << 10)
        || tx_word(&owner, 1, slot, 4) != (0x1f << 8) | (0xf << 13)
        || tx_word(&owner, 1, slot, 7) != 30
        || tx_word(&owner, 1, slot, 8) != 1 << 15
        || Some(tx_word(&owner, 1, slot, 10)) != buffer
        || tx_word(&owner, 1, slot, 12) != next
        || port.0.lock().kicks.len() != 1
    {
        return TestResult::Fail("rtl8723be_tx_fill_desc fields / doorbell");
    }
    if owner.submit(&probe, 0).is_ok() {
        return TestResult::Fail("second frame while one is outstanding");
    }
    owner.tx[1].write32(slot * 64, dw0 & !OWN).unwrap();
    match owner.poll_delivery() {
        Ok(Some(d)) if d.id == id && d.bytes == probe => {}
        _ => return TestResult::Fail("host receipt of the exact payload"),
    }
    if owner.submit(&probe, 12).is_ok() {
        return TestResult::Fail("HT rate admitted on the legacy link");
    }
    let rx = owner.packet.receive;
    let mut beacon = vec![0u8; 28];
    beacon[0] = 0x80;
    beacon[4..10].copy_from_slice(&[0xff; 6]);
    owner.buffers[rx].write_bytes(0, &beacon).unwrap();
    let ring = owner.receive.as_mut().unwrap();
    ring.write32(rx * 32, 28).unwrap();
    match owner.poll_receive_step() {
        Ok(s)
            if s.consumed
                && s.packet
                    .as_ref()
                    .is_some_and(|p| p.bytes() == &beacon[..24]) => {}
        _ => return TestResult::Fail("legacy beacon not delivered without FCS"),
    }
    if owner.receive.as_ref().unwrap().read32(rx * 32).unwrap() & OWN == 0 {
        return TestResult::Fail("RX descriptor not re-armed");
    }
    let rx = owner.packet.receive;
    let ring = owner.receive.as_mut().unwrap();
    ring.write32(rx * 32, 16).unwrap();
    ring.write32(rx * 32 + 8, 1 << 28).unwrap();
    match owner.poll_receive_step() {
        Ok(s) if s.consumed && s.packet.is_none() && owner.packet.be8723.c2h.len() == 1 => {}
        _ => return TestResult::Fail("C2H buffer must be queued for the coexistence owner"),
    }
    if run(owner.be8723_service_c2h()) != Ok(1) || !owner.packet.be8723.c2h.is_empty() {
        return TestResult::Fail("queued C2H not dispatched through the coexistence owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_native_owner_start_descriptors_receipt_and_rx
);

/// Use the production queue, rather than a fake with already separate
/// arrivals/deferred storage: a non-MP report cannot re-enter its own wait.
fn smoke_rtl8723be_real_c2h_queue_mp_deferral_and_timeout() -> TestResult {
    use super::super::super::super::rtl8723be::{
        btc::{BtMpSource, C2hSource, RxBtMp, C2H_MAX},
        c2h,
        packet::C2hQueue,
    };
    let Some((_, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    let info = [c2h::C2H_BT_INFO, 0, 0, 7, 0, 0, 0];
    let report = [c2h::C2H_TX_REPORT, 0, 0, 0, 2, 0, 0, 0, 4];
    let mp = [c2h::C2H_BT_MP, 0, 1, 0, 0xe0, 0x34, 0x12, 7];
    let mut queue = C2hQueue::default();
    queue.push(&info);
    queue.push(&report);
    let mut bytes = [0; C2H_MAX];
    for expected in [&info[..], &report[..]] {
        if queue.poll_c2h(&mut bytes) != Ok(Some(expected.len()))
            || &bytes[..expected.len()] != expected
        {
            return TestResult::Fail("fresh arrival order");
        }
        if queue.defer_c2h(expected).is_err() {
            return TestResult::Fail("defer");
        }
    }
    if queue.poll_c2h(&mut bytes) != Ok(None) || queue.len() != 2 {
        return TestResult::Fail("deferred packet re-enters the same MP wait");
    }
    if run(RxBtMp {
        io: &port,
        source: &mut queue,
    }
    .next_bt_mp(1))
        != Ok(None)
    {
        return TestResult::Fail("real queue MP timeout");
    }
    queue.push(&mp);
    let got = run(RxBtMp {
        io: &port,
        source: &mut queue,
    }
    .next_bt_mp(1));
    if !matches!(got, Ok(Some(value)) if value.body() == &mp[2..]) {
        return TestResult::Fail("fresh MP bypasses deferred non-MP work");
    }
    for expected in [&info[..], &report[..]] {
        if !matches!(queue.pop(), Some((n, bytes)) if &bytes[..n] == expected) {
            return TestResult::Fail("deferred reports delivered exactly once in order");
        }
    }
    if !queue.is_empty() {
        return TestResult::Fail("duplicate report");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_real_c2h_queue_mp_deferral_and_timeout
);

/// Authentication-time registers, the association `JOINBSSRPT`
/// (`HW_VAR_AID`, the reserved-page upload on beacon descriptor 0 with
/// BCN_VALID and the `RSVDPAGE` location, MSRRPT connect) through the
/// coexistence owner's mailbox, the RA mask bounded by the `NAPC`
/// admitted rates, then the disassociation report.
fn smoke_rtl8723be_native_join_rsvd_page_ra_mask_and_leave() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    port.set8(hw::REG_BCN_PSR_RPT + 1, 0xc0);
    if owner.start_packets().is_err()
        || run(owner.prepare_station_peer(PEER, 0x0fff, 0x0015, 0x0421)).is_err()
    {
        return TestResult::Fail("start / authentication-time registers");
    }
    if (0..6).any(|i| port.reg8(hw::REG_BSSID + i) != PEER[usize::from(i)])
        // `HW_VAR_BASIC_RATE` takes the peer's `supp_rates[0]`.
        || port.reg8(hw::REG_RRSR) != 0x5f
        || port.reg8(hw::REG_RRSR + 1) != 0x01
        || port.reg8(hw::REG_INIRTS_RATE_SEL) != 8
        || port.reg8(hw::REG_SLOT) != 9
    {
        return TestResult::Fail("BSSID / BASIC_RATE / slot");
    }
    if run(owner.complete_station_peer(PEER, 5)).is_err() {
        return TestResult::Fail("association join report");
    }
    let keep = port.wrote(1, h2c::REG_HMEBOX_0, 0x03);
    let kick = port.0.lock().kicks.last().copied();
    let rsvd = port.wrote(1, h2c::REG_HMEBOX_0 + 4, h2c::H2C_RSVDPAGE.into());
    if keep.is_none()
        || kick != Some(1 << 4)
        || rsvd.is_none()
        || tx_word(&owner, 0, 0, 0) & OWN == 0
        || port.reg8(hw::MSR) & 3 != hw::MSR_INFRA
        || port.reg8(hw::REG_BCN_PSR_RPT) != 5
        || port.reg8(hw::REG_BCN_PSR_RPT + 1) != 0xc0
    {
        return TestResult::Fail("KEEP_ALIVE / rsvd page upload / AID / MSR");
    }
    let peer = h2c::Peer {
        legacy: 0x0fff,
        ht: None,
        sgi20: false,
        sgi40: false,
    };
    if run(owner.install_rtl8723be_rate_mask(peer, false, 0)).is_err()
        || owner.rate_mask() != Some(4)
        || port.reg8(h2c::REG_BCN_CTRL) & (1 << 3) == 0
    {
        return TestResult::Fail("RA mask install (GB, ratr_index 4)");
    }
    if run(owner.leave_station_peer()).is_err()
        || owner.rate_mask().is_some()
        || port.reg8(hw::MSR) & 3 != hw::MSR_NOLINK
        || (0..6).any(|i| port.reg8(hw::REG_BSSID + i) != 0)
    {
        return TestResult::Fail("disassociation report / registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_native_join_rsvd_page_ra_mask_and_leave
);

/// HT/40 MHz rate-mask install (`rtl8723be_update_hal_rate_mask` N rows):
/// an HT peer on the 40 MHz owner installs `RATR_INX_WIRELESS_NGB` (0)
/// with the `H2C_RA_MASK` command sent. The join-flow install is covered
/// by the GB test above; the HT-specific code is the N-row computation
/// (`h2c::rate_mask`) and the NGB index. The command takes box 0 here:
/// it is the first H2C command on this owner, unlike the join flow
/// where KEEP_ALIVE takes box 0 first.
fn smoke_rtl8723be_ht40_rate_mask_n_rows() -> TestResult {
    let Some((mut owner, port)) = owner40() else {
        return TestResult::Fail("fixture");
    };
    if owner.start_packets().is_err() {
        return TestResult::Fail("start_packets refused a prepared 40 MHz owner");
    }
    let peer = h2c::Peer {
        legacy: 0x0fff,
        ht: Some([0xff, 0x00]),
        sgi20: false,
        sgi40: false,
    };
    if run(owner.install_rtl8723be_rate_mask(peer, true, 0)).is_err()
        || owner.rate_mask() != Some(0)
        || owner.packet.be8723.link != Some((peer, true, 0))
        || port
            .wrote(1, h2c::REG_HMEBOX_0, h2c::H2C_RA_MASK.into())
            .is_none()
    {
        return TestResult::Fail("HT40 RA mask install (NGB, ratr_index 0)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_ht40_rate_mask_n_rows
);

/// A legacy DATA frame at 24M with short preamble sets TXD DW5 bit 4; the
/// same frame at 1M does not (Linux `_rtl_qurey_shortpreamble_mode`:
/// short preamble unless `hw_rate == 1M`); a long-preamble peer does not
/// either. Capability 0x0421 carries short preamble, 0x0401 does not.
fn smoke_rtl8723be_short_preamble_descriptor_bit() -> TestResult {
    for (capability, rate, short) in [
        (0x0421u16, 8u8, true),
        (0x0421, 0, false),
        (0x0401, 8, false),
    ] {
        let Some((mut owner, _port)) = owner() else {
            return TestResult::Fail("fixture");
        };
        if owner.start_packets().is_err()
            || run(owner.prepare_station_peer(PEER, 0x0fff, 0x0015, capability)).is_err()
        {
            return TestResult::Fail("start / prepare");
        }
        let mut data = vec![0u8; 30];
        data[0] = 0x08;
        data[1] = 0x01;
        data[4..10].copy_from_slice(&PEER);
        data[10..16].copy_from_slice(&be::be_factory().mac);
        data[16..22].copy_from_slice(&PEER);
        let slot = owner.packet.next[4];
        if owner.submit(&data, rate).is_err() {
            return TestResult::Fail("data submit");
        }
        if (tx_word(&owner, 4, slot, 5) & (1 << 4) != 0) != short {
            return TestResult::Fail("TXD DW5 short-preamble bit");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_short_preamble_descriptor_bit
);

/// TX-report matching (`base.c::rtl_tx_report_handler`): a Null DATA
/// frame mints report sequence 4 (`(1 & 0x3f) << 2`); the firmware's V1
/// TX-report C2H (`id 3`, `st 0`, `sn 4`) matches it to the frame id,
/// marks it acknowledged, and settles the report state.
fn smoke_rtl8723be_tx_report_match_and_settled() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    port.set8(hw::REG_BCN_PSR_RPT + 1, 0xc0);
    if owner.start_packets().is_err()
        || run(owner.prepare_station_peer(PEER, 0x0fff, 0x0015, 0x0421)).is_err()
        || run(owner.complete_station_peer(PEER, 5)).is_err()
    {
        return TestResult::Fail("start / prepare / complete");
    }
    let peer = h2c::Peer {
        legacy: 0x0fff,
        ht: None,
        sgi20: false,
        sgi40: false,
    };
    if run(owner.install_rtl8723be_rate_mask(peer, false, 0)).is_err() {
        return TestResult::Fail("RA mask install");
    }
    let mut null = vec![0u8; 30];
    null[0] = 0x48;
    null[1] = 0x01;
    null[4..10].copy_from_slice(&PEER);
    null[10..16].copy_from_slice(&be::be_factory().mac);
    null[16..22].copy_from_slice(&PEER);
    let Ok(id) = owner.submit(&null, 8) else {
        return TestResult::Fail("Null DATA submit");
    };
    if owner.packet.be8723.waiting.len() != 1 || owner.packet.be8723.waiting[0].0 != 4 {
        return TestResult::Fail("TX-report sequence not queued");
    }
    let mut report = [0u8; 16];
    report[0] = 3;
    report[8] = 4;
    let rx = owner.packet.receive;
    owner.buffers[rx].write_bytes(0, &report).unwrap();
    let ring = owner.receive.as_mut().unwrap();
    ring.write32(rx * 32, 16).unwrap();
    ring.write32(rx * 32 + 8, 1 << 28).unwrap();
    if !matches!(owner.poll_receive_step(), Ok(s) if s.consumed && owner.packet.be8723.c2h.len() == 1)
        || run(owner.be8723_service_c2h()) != Ok(1)
    {
        return TestResult::Fail("TX-report C2H not dispatched");
    }
    match owner.take_rtl8723be_tx_report() {
        Some(r) if r.id == id && r.acked && r.retry == 0 => {}
        _ => return TestResult::Fail("TX-report not matched to the frame"),
    }
    if !owner.rtl8723be_tx_reports_settled() {
        return TestResult::Fail("TX reports not settled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_tx_report_match_and_settled
);

/// The shared-station coexistence call sites on the 8723BE owner: scan,
/// connect and special-packet notifies run without error and leave the
/// owner Running; IPS enter writes hardware registers (the 2-antenna
/// `ex_btc8723b2ant_*_notify` implementations are log-only for scan /
/// connect / special, so only the return and the phase are asserted
/// there); IPS leave returns the owner to the running state.
fn smoke_rtl8723be_coex_notify_scan_connect_special_ips() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    if owner.start_packets().is_err() {
        return TestResult::Fail("start_packets refused a prepared owner");
    }
    if run(owner.be8723_scan_notify(true)).is_err()
        || run(owner.be8723_scan_notify(false)).is_err()
        || run(owner.be8723_connect_notify(true)).is_err()
        || run(owner.be8723_connect_notify(false)).is_err()
        || run(owner.be8723_special_packet_notify(Packet::Dhcp)).is_err()
        || owner.phase != Phase::Running
        || owner.packet.leisure
    {
        return TestResult::Fail("scan / connect / special-packet notify");
    }
    let writes = port.0.lock().writes.len();
    if run(owner.be8723_ips_notify(true)).is_err()
        || owner.phase != Phase::Running
        || port.0.lock().writes.len() <= writes
    {
        return TestResult::Fail("IPS notify enter");
    }
    if run(owner.be8723_ips_notify(false)).is_err() || owner.phase != Phase::Running {
        return TestResult::Fail("IPS notify leave");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_coex_notify_scan_connect_special_ips
);

/// The composed `rtl8723be_dm_watchdog` pure steps over the register
/// model: false-alarm counts (8723BE includes fast-fsync / SB-search in
/// `cnt_all`), first-connect DIG (IGI from the RSSI), the CCK packet
/// detection threshold, dynamic EDCCA enable, and the ATC unlinked branch
/// (CFO-track enable + crystal-cap re-apply on drift).
fn smoke_rtl8723be_dm_steps_false_alarm_dig_cck_edcca_atc() -> TestResult {
    let port = BePort::new();
    port.set32(dm::DM_REG_OFDM_FA_TYPE1_11N, 0x0002_0003);
    port.set32(dm::DM_REG_OFDM_FA_TYPE2_11N, 0x0004_0005);
    port.set32(dm::DM_REG_OFDM_FA_TYPE3_11N, 0x0006_0007);
    port.set32(dm::DM_REG_OFDM_FA_TYPE4_11N, 8);
    port.set32(dm::DM_REG_CCK_FA_RST_11N, 0x11);
    port.set32(dm::DM_REG_CCK_FA_MSB_11N, 0x0200_0000);
    port.set32(dm::DM_REG_CCK_CCA_CNT_11N, 0x0304);
    let Ok(fa) = dm::false_alarm(&port) else {
        return TestResult::Fail("false_alarm");
    };
    if fa.cnt_ofdm_fail != 30
        || fa.cnt_cck_fail != 0x211
        || fa.cnt_cck_cca != 0x403
        || fa.cnt_all != 559
        || fa.cnt_cca_all != 1032
    {
        return TestResult::Fail("false-alarm counts");
    }
    port.set32(dm::ROFDM0_XAAGCCORE1, 0x30);
    port.set32(dm::REG_MAC_PHY_CTRL, 0x20 << 12);
    port.set32(dm::ROFDM1_CFOTRACKING, 0);
    let Ok(mut state) = dm::Dm::init(&port) else {
        return TestResult::Fail("Dm::init");
    };
    if state.cur_igvalue != 0x30 || state.crystal_cap != 0x20 || state.atc_status != 0 {
        return TestResult::Fail("Dm::init live reads");
    }
    state.useramask = false;
    match dm::rssi_monitor(&port, &mut state, 55, false) {
        Ok(None) if port.reg8(dm::RSSI_REPORT_BYTE) == 55 && state.rssi_val_min == 0 => {}
        _ => return TestResult::Fail("rssi_monitor non-useramask path"),
    }
    state.useramask = true;
    match dm::rssi_monitor(&port, &mut state, 40, true) {
        Ok(Some([0, 0x20, 40])) if state.rssi_val_min == 40 => {}
        _ => return TestResult::Fail("rssi_monitor useramask path"),
    }
    if dm::dig(&port, &mut state, true, 100).is_err()
        || state.cur_igvalue != 40
        || port.reg32(dm::ROFDM0_XAAGCCORE1) & 0x7f != 40
        || !state.media_connect_0
    {
        return TestResult::Fail("dig first-connect IGI");
    }
    if dm::cck_packet_detection_thresh(&port, &mut state, true, 5).is_err()
        || port.reg32(dm::RCCK0_CCA) & 0x00ff_0000 != 0xcd << 16
        || state.cur_cck_cca_thres != 0xcd
    {
        return TestResult::Fail("cck_packet_detection_thresh");
    }
    port.set32(dm::ROFDM0_XAAGCCORE1, 0x30);
    port.set32(dm::ROFDM0_XBAGCCORE1, 0x30);
    if dm::dynamic_edcca(&port, false).is_err()
        || port.reg8(dm::ROFDM0_ECCATHRESHOLD) != 0x03
        || port.reg8(dm::ROFDM0_ECCATHRESHOLD + 2) != 0x00
    {
        return TestResult::Fail("dynamic_edcca enable");
    }
    if dm::atc_switch_unlinked(&port, &mut state, true).is_err()
        || state.atc_status != 1
        || port.reg32(dm::ROFDM1_CFOTRACKING) & (1 << 11) == 0
    {
        return TestResult::Fail("atc_switch_unlinked CFO-track enable");
    }
    port.set32(dm::REG_MAC_PHY_CTRL, 0x10 << 12);
    if dm::atc_switch_unlinked(&port, &mut state, true).is_err()
        || port.reg32(dm::REG_MAC_PHY_CTRL) != 0x820 << 12
    {
        return TestResult::Fail("atc_switch_unlinked crystal-cap re-apply");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_dm_steps_false_alarm_dig_cck_edcca_atc
);

/// The composed `rtl8723be_dm_watchdog` on a linked owner at RSSI 60:
/// the RA level rises to `STA_HIGH`, DIG takes the first-connect IGI 50,
/// dynamic EDCCA enables, the CCK threshold goes to 0xcd, and the RSSI
/// H2C report is sent.
fn smoke_rtl8723be_dm_watchdog_linked_refresh() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    port.set8(hw::REG_BCN_PSR_RPT + 1, 0xc0);
    if owner.start_packets().is_err()
        || run(owner.prepare_station_peer(PEER, 0x0fff, 0x0015, 0x0421)).is_err()
        || run(owner.complete_station_peer(PEER, 5)).is_err()
    {
        return TestResult::Fail("start / prepare / complete");
    }
    let peer = h2c::Peer {
        legacy: 0x0fff,
        ht: None,
        sgi20: false,
        sgi40: false,
    };
    if run(owner.install_rtl8723be_rate_mask(peer, false, 0)).is_err() {
        return TestResult::Fail("RA mask install");
    }
    port.set32(dm::ROFDM0_XAAGCCORE1, 0x30);
    port.set32(dm::ROFDM0_XBAGCCORE1, 0x30);
    port.set32(dm::DM_REG_OFDM_FA_TYPE1_11N, 0x0001_0002);
    port.set32(dm::DM_REG_OFDM_FA_TYPE2_11N, 0x0002_0003);
    port.set32(dm::DM_REG_OFDM_FA_TYPE3_11N, 0x0001_0001);
    port.set32(dm::DM_REG_OFDM_FA_TYPE4_11N, 1);
    port.set32(dm::DM_REG_CCK_FA_RST_11N, 0x05);
    port.set32(dm::DM_REG_CCK_FA_MSB_11N, 0);
    port.set32(dm::DM_REG_CCK_CCA_CNT_11N, 0x0102);
    port.set32(dm::RCCK0_CCA, 0);
    port.set32(dm::REG_MAC_PHY_CTRL, 0x20 << 12);
    port.set32(dm::ROFDM1_CFOTRACKING, 0);
    port.set32(dm::ROFDM0_ECCATHRESHOLD, 0);
    if run(owner.rtl8723be_dm_watchdog(60, 1000)) != Ok(true)
        || owner.packet.be8723.ratr_state != 1
        || port.reg32(dm::ROFDM0_XAAGCCORE1) & 0x7f != 50
        || port.reg8(dm::ROFDM0_ECCATHRESHOLD) != 0x03
        || port.reg32(dm::RCCK0_CCA) & 0x00ff_0000 != 0xcd << 16
        || port
            .wrote(1, h2c::REG_HMEBOX_0 + 4, h2c::H2C_RSSIBE_REPORT.into())
            .is_none()
        || !owner
            .packet
            .be8723
            .dm
            .as_ref()
            .is_some_and(|d| d.rssi_val_min == 60 && d.cur_igvalue == 50)
    {
        return TestResult::Fail("dm_watchdog linked refresh");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_dm_watchdog_linked_refresh
);

/// Literal PHY-report offsets and 802.11 BSSID selection from trx.c.
fn smoke_rtl8723be_cfo_samples_match_bssid_and_phy() -> TestResult {
    let mut cfo = dm::Cfo::default();
    let mut phy = [0; 16];
    phy[9] = 0xf8; // signed -8, not 248
    phy[10] = 7;
    let mut frame = [0; 24];
    frame[0] = 0x80;
    frame[16..22].copy_from_slice(&PEER);
    cfo.observe(&phy, &frame, PEER, true);
    cfo.observe(&phy[..10], &frame, PEER, false);
    cfo.observe(&phy, &frame[..23], PEER, false);
    cfo.observe(&phy, &frame, [0; 6], false);
    cfo.observe(&phy, &frame, [2; 6], false);
    kt_assert_eq!(cfo.packet_count, 0);
    cfo.observe(&phy, &frame, PEER, false);
    kt_assert_eq!(cfo.tail, [-8, 7]);
    kt_assert_eq!(cfo.packet_count, 1);
    // FromDS picks A2, ToDS picks A1 (also for a four-address frame).
    frame[0] = 0x08;
    frame[1] = 2;
    cfo.observe(&phy, &frame, PEER, false);
    kt_assert_eq!(cfo.packet_count, 1);
    frame[10..16].copy_from_slice(&PEER);
    cfo.observe(&phy, &frame, PEER, false);
    kt_assert_eq!(cfo.packet_count, 2);
    frame[1] = 3;
    cfo.observe(&phy, &frame, PEER, false);
    kt_assert_eq!(cfo.packet_count, 2);
    frame[4..10].copy_from_slice(&PEER);
    cfo.packet_count = u32::MAX;
    cfo.observe(&phy, &frame, PEER, false);
    kt_assert_eq!(cfo.packet_count, 0);
    frame[0] = 0x04;
    cfo.observe(&phy, &frame, PEER, false);
    kt_assert_eq!(cfo.packet_count, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_cfo_samples_match_bssid_and_phy
);

/// Fixed source examples: 8 -> 19 kHz -> +5 caps; extreme signed
/// offsets need two samples and clamp at 0/63. No fresh RX means no I/O.
fn smoke_rtl8723be_linked_atc_hysteresis_clamps_and_restore() -> TestResult {
    let port = BePort::new();
    port.set32(dm::REG_MAC_PHY_CTRL, 0x20 << 12);
    let mut state = dm::Dm::init(&port).unwrap();
    let mut cfo = dm::Cfo {
        tail: [8, -128],
        packet_count: 1,
    };
    kt_assert!(dm::atc_switch_linked(&port, &mut state, &cfo).is_ok());
    kt_assert_eq!(state.crystal_cap, 37);
    kt_assert_eq!(port.reg32(dm::REG_MAC_PHY_CTRL) & 0xfff000, 0x965000);
    cfo.tail[0] = 127;
    let before = port.0.lock().writes.len();
    kt_assert!(dm::atc_switch_linked(&port, &mut state, &cfo).is_ok());
    kt_assert_eq!(port.0.lock().writes.len(), before);
    for (tail, cap, atc) in [(127, 63, 1), (-128, 0, 1), (0, 0, 0)] {
        cfo.tail[0] = tail;
        cfo.packet_count += 1;
        let old_cap = state.crystal_cap;
        kt_assert!(dm::atc_switch_linked(&port, &mut state, &cfo).is_ok());
        kt_assert!(state.large_cfo_hit);
        kt_assert_eq!(state.crystal_cap, old_cap);
        cfo.packet_count += 1;
        kt_assert!(dm::atc_switch_linked(&port, &mut state, &cfo).is_ok());
        kt_assert!(!state.large_cfo_hit);
        kt_assert_eq!(state.crystal_cap, cap);
        kt_assert_eq!(state.atc_status, atc);
    }
    kt_assert_eq!(state.cfo_threshold, 20);
    kt_assert!(state.is_freeze);
    // BT coexistence holds the adjusted cap; BT-disabled restores efuse.
    kt_assert!(dm::atc_switch_unlinked(&port, &mut state, false).is_ok());
    kt_assert_eq!(state.crystal_cap, 0);
    kt_assert!(dm::atc_switch_unlinked(&port, &mut state, true).is_ok());
    kt_assert_eq!(state.crystal_cap, 32);
    kt_assert_eq!(port.reg32(dm::REG_MAC_PHY_CTRL) & 0xfff000, 0x820000);
    // 32/33 PHY units truncate to 78/80 kHz: the source window is
    // strict at both +/-80, including the negative division boundary.
    for (tail, atc) in [(32, 0), (33, 1), (-32, 0), (-33, 1)] {
        cfo.tail[0] = tail;
        for _ in 0..2 {
            cfo.packet_count += 1;
            kt_assert!(dm::atc_switch_linked(&port, &mut state, &cfo).is_ok());
        }
        kt_assert_eq!(state.atc_status, atc);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_linked_atc_hysteresis_clamps_and_restore
);

/// The original native DMA owner must retain PHY samples before the
/// first watchdog initialization, reject error/foreign-BSSID reports,
/// and consume each sample just once through the linked watchdog.
fn smoke_rtl8723be_native_rx_drives_linked_atc() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    port.set8(hw::REG_BCN_PSR_RPT + 1, 0xc0);
    if owner.start_packets().is_err()
        || run(owner.prepare_station_peer(PEER, 0x0fff, 0x0015, 0x0421)).is_err()
        || run(owner.complete_station_peer(PEER, 5)).is_err()
        || run(owner.install_rtl8723be_rate_mask(
            h2c::Peer {
                legacy: 0x0fff,
                ht: None,
                sgi20: false,
                sgi40: false,
            },
            false,
            0,
        ))
        .is_err()
    {
        return TestResult::Fail("linked owner");
    }
    port.set32(dm::REG_MAC_PHY_CTRL, 0x20 << 12);
    // No payload is sent to hardware: DMA blocks hold literal RXD/PHY
    // bytes. One CRC-error and one foreign beacon cannot train the CFO.
    for (bssid, crc) in [([2; 6], false), (PEER, true), (PEER, false)] {
        let slot = owner.packet.receive;
        let mut payload = [0; 44]; // PHY16 + beacon24 + FCS4
        payload[4] = 140;
        payload[9] = 8;
        payload[10] = 0x80; // path B is not used by RF_1T1R
        payload[16] = 0x80;
        payload[20..26].fill(0xff);
        payload[26..32].copy_from_slice(&bssid);
        payload[32..38].copy_from_slice(&bssid);
        owner.buffers[slot].write_bytes(0, &payload).unwrap();
        let ring = owner.receive.as_mut().unwrap();
        let eor = if slot + 1 == owner.depth { 1 << 30 } else { 0 };
        ring.write32(
            slot * 32,
            28 | (2 << 16) | (1 << 26) | (u32::from(crc) << 14) | eor,
        )
        .unwrap();
        ring.write32(slot * 32 + 12, 4).unwrap(); // OFDM 6 Mbps
        kt_assert!(owner.poll_receive_step().is_ok());
        kt_assert_eq!(
            owner.packet.be8723.cfo.packet_count,
            u32::from(bssid == PEER && !crc)
        );
    }
    kt_assert!(owner.packet.be8723.dm.is_none());
    kt_assert!(run(owner.rtl8723be_dm_watchdog(40, 1000)).is_ok());
    kt_assert_eq!(owner.packet.be8723.dm.as_ref().unwrap().crystal_cap, 37);
    kt_assert!(run(owner.rtl8723be_dm_watchdog(40, 2000)).is_ok());
    kt_assert_eq!(owner.packet.be8723.dm.as_ref().unwrap().crystal_cap, 37);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_native_rx_drives_linked_atc
);
