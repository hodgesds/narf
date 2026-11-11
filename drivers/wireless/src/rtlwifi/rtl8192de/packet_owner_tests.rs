// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE native packet/station owner over a register-file and DMA model.
//! Written; not yet executed (no QEMU in this lane).
use super::super::super::super::{
    firmware_transport::{Error as AccessError, Io},
    rtl8192de::{
        envelope, h2c, mac, rate::WirelessMode, station as hw, tests as de, MacPhyMode, RfType,
    },
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
struct DePort(Arc<IrqSafeSpinLock<Model>>);
impl DePort {
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
impl Io for DePort {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        Ok(self.reg8(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        Ok(self.reg32(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        // The modelled firmware takes every H2C box at once
        // (`REG_HMETFR` stays 0).
        m.regs[usize::from(reg)] = value;
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
impl Port for DePort {
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
        Poll::Pending => panic!("unexpected 8192DE model wait"),
    }
}

const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
/// A trimmed RCR as `rtl92de_hw_init` leaves it (`RCR & ~(ACRC32|AICV)`).
const RCR: u32 = 0xf000_690e;

/// A MacConfigured single-MAC 8192DE owner with published rings (as
/// `prepare` would leave them), bound per-function facts, firmware version
/// `0x20` and an `N92D` permission for channel 6 / 20 MHz.
fn owner() -> Option<(Prepared<DePort, Block>, DePort)> {
    let port = DePort::new();
    let mut owner =
        Prepared::allocate_for(Chip::Rtl8192de, port.clone(), 4, |b| Ok(port.block(b))).ok()?;
    for (reg, ring) in TX_BASES.iter().zip(&owner.tx) {
        port.set32(*reg, ring.address() as u32);
    }
    port.set32(RX_BASE, owner.receive.as_ref()?.address() as u32);
    let factory = de::de_factory();
    let cal = envelope::Calibration::from_verified(
        &de::de_napc_fixture(1, 0, 80, &[(6, 20, 0, de::de_rising)]),
        Some([0xab; 32]),
        &factory,
    )
    .ok()?;
    owner.rtl8192de_power = Some(
        cal.permission_for(&de::de_us_domain(), envelope::Operating::twenty(6))
            .ok()?,
    );
    owner.packet.de92.facts = Some(super::Facts {
        receive_config: RCR,
        mode: MacPhyMode::SingleMacSinglePhy,
        interface_index: 0,
        rf_type: RfType::TwoT2R,
    });
    owner.bind_rtl8192de_firmware(0x20);
    owner.packet.local = Some(factory.mac);
    owner.published = true;
    owner.phase = Phase::MacConfigured;
    Some((owner, port))
}

fn tx_word(owner: &Prepared<DePort, Block>, queue: usize, slot: usize, word: usize) -> u32 {
    owner.tx[queue].read32(slot * 64 + word * 4).unwrap()
}

/// `_rtl92de_init_mac`'s DESA writes and DMA release with
/// `set_network_type(STATION)`, one `rtl92de_tx_fill_desc` management frame
/// (driver 1M, DISFB, MC rate id, buffer at dword 8, link at byte 40
/// intact), its host receipt, the HT / `N92D` rate refusals and a legacy RX
/// frame at `drvinfo + shift` of the buffer.
fn smoke_rtl8192de_native_owner_start_descriptors_receipt_and_rx() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    let link0 = tx_word(&owner, 1, 0, 10);
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
        || port.reg8(hw::REG_MSR) & 3 != hw::MSR_INFRA
        || port.reg8(hw::REG_BCNTCFG + 1) != 0x66
    {
        return TestResult::Fail("init_mac DMA release / set_network_type(STATION) differ");
    }
    let mut probe = vec![0u8; 30];
    probe[0] = 0x40;
    probe[4..10].copy_from_slice(&[0xff; 6]);
    probe[10..16].copy_from_slice(&de::de_factory().mac);
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
    let dw0 = 30 | (32 << 16) | (1 << 26) | (1 << 27) | OWN;
    if tx_word(&owner, 1, slot, 0) != dw0
        || tx_word(&owner, 1, slot, 1) != (0x12 << 8) | (7 << 16)
        || tx_word(&owner, 1, slot, 4) & ((1 << 8) | (1 << 10)) != (1 << 8) | (1 << 10)
        || tx_word(&owner, 1, slot, 5) & 0x3f != 0
        || tx_word(&owner, 1, slot, 7) != 30
        || Some(tx_word(&owner, 1, slot, 8)) != buffer
        || tx_word(&owner, 1, slot, 10) != link0
        || port.0.lock().kicks.len() != 1
    {
        return TestResult::Fail("rtl92de_tx_fill_desc fields / ring link / doorbell");
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
                    .is_some_and(|p| p.bytes() == &beacon[..24] && p.channel() == 6) => {}
        _ => return TestResult::Fail("legacy beacon not delivered without FCS"),
    }
    if owner.receive.as_ref().unwrap().read32(rx * 32).unwrap() & OWN == 0 {
        return TestResult::Fail("RX descriptor not re-armed");
    }
    if owner.stop_packets().is_err()
        || port.reg32(mac::REG_HIMR) != 0
        || port.reg8(0x301) != 0xff
        || port.reg8(0x522) != 0xff
    {
        return TestResult::Fail("terminal stop: 0x120 IMR / DMA stop / TX pause");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_native_owner_start_descriptors_receipt_and_rx
);

/// Authentication-time registers, the association join (CAM reset,
/// `HW_VAR_AID`, the reserved page on beacon descriptor 0 with the `BIT(4)`
/// doorbell and `H2C_RSVDPAGE`, then `H2C_JOINBSSRPT(1)`), the RA mask
/// bounded by the `N92D` admitted rates (GB, ratr_index 4), the LPS no-op
/// and the disassociation report.
fn smoke_rtl8192de_native_join_rsvd_page_ra_mask_and_leave() -> TestResult {
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
        || port.reg8(mac::REG_RRSR) != 0x5f
        || port.reg8(mac::REG_RRSR + 1) != 0x01
        || port.reg8(mac::REG_INIRTS_RATE_SEL) != 8
        || port.reg8(mac::REG_SLOT) != 9
    {
        return TestResult::Fail("BSSID / BASIC_RATE / slot");
    }
    let link0 = tx_word(&owner, 0, 0, 10);
    if run(owner.complete_station_peer(PEER, 5)).is_err() {
        return TestResult::Fail("association join report");
    }
    let cam = port.wrote(4, mac::REG_CAMCMD, mac::CAM_RESET);
    let rsvd = port.wrote(1, h2c::REG_HMEBOX_0, h2c::H2C_RSVDPAGE.into());
    let join = port.wrote(1, h2c::REG_HMEBOX_0 + 4, h2c::H2C_JOINBSSRPT.into());
    let kick = port.0.lock().kicks.last().copied();
    if cam.is_none()
        || rsvd.is_none()
        || join.is_none()
        || rsvd > join
        || kick != Some(1 << 4)
        || tx_word(&owner, 0, 0, 0) & OWN == 0
        || tx_word(&owner, 0, 0, 0) & 0xffff != 768
        || tx_word(&owner, 0, 0, 10) != link0
        || port.reg8(h2c::REG_HMEBOX_0 + 5) != h2c::MEDIA_CONNECT
        || port.reg8(hw::REG_MSR) & 3 != hw::MSR_INFRA
        || port.reg8(hw::REG_BCN_PSR_RPT) != 5
        || port.reg8(hw::REG_BCN_PSR_RPT + 1) != 0xc0
        || port.reg32(mac::REG_RCR) & (hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN)
            != hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN
    {
        return TestResult::Fail("CAM reset / rsvd page upload / JOINBSSRPT / AID / CBSSID");
    }
    let peer = h2c::Peer {
        mode: WirelessMode::G,
        supp_rates: [0x0fff, 0],
        rx_mask: [0; 2],
        sgi20: false,
        sgi40: false,
        mimo_ps_static: false,
        ap_or_adhoc: false,
        aid: 0,
    };
    if run(owner.install_rtl8192de_rate_mask(peer, false, 0)).is_err()
        || owner.rate_mask() != Some(h2c::RATR_INX_WIRELESS_GB)
        || port.reg8(h2c::REG_HMEBOX_0 + 8) != h2c::H2C_RA_MASK | 0x80
    {
        return TestResult::Fail("RA mask install (GB, ratr_index 4)");
    }
    if run(owner.enter_leisure()).is_err() || owner.leisure() {
        return TestResult::Fail("fwctrl_lps false: LPS enter is a no-op");
    }
    if run(owner.leave_station_peer()).is_err()
        || owner.rate_mask().is_some()
        // `_rtl92de_set_media_status(STATION)` keeps MSR INFRA; only the
        // check-BSSID bits follow the link.
        || port.reg8(hw::REG_MSR) & 3 != hw::MSR_INFRA
        || port.reg32(mac::REG_RCR) & (hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN) != 0
        || port.wrote(1, h2c::REG_HMEBOX_0 + 12, h2c::H2C_JOINBSSRPT.into()).is_none()
        || port.reg8(h2c::REG_HMEBOX_0 + 13) != h2c::MEDIA_DISCONNECT
        || (0..6).any(|i| port.reg8(hw::REG_BSSID + i) != 0)
    {
        return TestResult::Fail("disassociation report / registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8192de",
    smoke_rtl8192de_native_join_rsvd_page_ra_mask_and_leave
);
