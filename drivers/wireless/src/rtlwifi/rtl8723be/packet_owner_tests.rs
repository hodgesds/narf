// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE native packet/station owner over a register-file and DMA model.
//! Written; not yet executed (no QEMU in this lane).
use super::super::super::super::{
    btcoex::btc::{ChipInterface, ChipType, HwPg},
    firmware_transport::{Error as AccessError, Io},
    rtl8723be::{adapter, envelope, h2c, init, mac, station as hw, tests as be, txpower, version},
};
use super::super::super::{Chip, Error, Memory, Phase, Prepared, RX_BASE, TX_BASES};
use super::super::{Port, OWN};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone)]
struct Block {
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
    next: u64,
}
#[derive(Clone)]
struct BePort(Arc<IrqSafeSpinLock<Model>>);
impl BePort {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs: vec![0; 0x1000],
            writes: Vec::new(),
            kicks: Vec::new(),
            master: false,
            next: 0x10_0000,
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
        Ok(self.reg8(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        Ok(self.reg32(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        // The modelled firmware takes every H2C box at once and reports
        // BCN_VALID for every reserved-page upload.
        m.regs[usize::from(reg)] = match reg {
            0x20a => value | 1,
            _ => value,
        };
        m.writes.push((1, reg, value.into()));
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        let r = usize::from(reg);
        m.regs[r..r + 2].copy_from_slice(&value.to_le_bytes());
        m.writes.push((2, reg, value.into()));
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        let r = usize::from(reg);
        m.regs[r..r + 4].copy_from_slice(&value.to_le_bytes());
        m.writes.push((4, reg, value));
        Ok(())
    }
    fn write_bytes(&self, _reg: u16, _bytes: &[u8]) -> Result<(), AccessError> {
        Err(AccessError::Access)
    }
    async fn delay_us(&self, _micros: u64) {}
}
impl Port for BePort {
    type Buffer = Block;
    fn authority<T>(
        &self,
        _active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
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
        self.0.lock().kicks.push(queue_bit);
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
/// an `NAPC` permission for channel 6 / 20 MHz.
fn owner() -> Option<(Prepared<BePort, Block>, BePort)> {
    let port = BePort::new();
    let mut owner =
        Prepared::allocate_for(Chip::Rtl8723be, port.clone(), 4, |b| Ok(port.block(b))).ok()?;
    for (reg, ring) in TX_BASES.iter().zip(&owner.tx) {
        port.set32(*reg, ring.address() as u32);
    }
    port.set32(RX_BASE, owner.receive.as_ref()?.address() as u32);
    let factory = be::be_factory();
    let cal = envelope::Calibration::from_verified(
        &be::be_napc_fixture(1, 0, 80, &[(6, 20, 0, be::be_rising)]),
        Some([0xab; 32]),
        &factory,
    )
    .ok()?;
    owner.rtl8723be_power = Some(
        cal.permission_for(&be::be_us_domain(), envelope::Operating::twenty(6))
            .ok()?,
    );
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
