//! RTL8821AE native packet/station owner over a register-file and DMA model.
//! Written; not yet executed (no QEMU in this lane).
use super::super::super::super::{
    channel_power::tests::domain,
    efuse::Factory,
    firmware_transport::{Error as AccessError, Io},
    rtl8821ae::{envelope, h2c, mac, station as hw, tests as ae},
};
use super::super::super::{Chip, Error, Memory, Phase, Prepared, TX_BASES};
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
    blocks: Vec<Block>,
    next: u64,
}
#[derive(Clone)]
struct AePort(Arc<IrqSafeSpinLock<Model>>);
impl AePort {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs: vec![0; 0x1000],
            writes: Vec::new(),
            kicks: Vec::new(),
            master: false,
            blocks: Vec::new(),
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
        m.blocks.push(block.clone());
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
impl Io for AePort {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        Ok(self.reg8(reg))
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        Ok(self.reg32(reg))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        let mut m = self.0.lock();
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
impl Port for AePort {
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
        Poll::Pending => panic!("unexpected 8821AE model wait"),
    }
}

const MAC: [u8; 6] = [0x00, 0xe0, 0x4c, 0x88, 0x21, 0x02];
const PEER: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

/// A MacConfigured 8821AE owner with published rings (as `prepare` would
/// leave them) and an envelope permission for channel 1.
fn owner() -> Option<(Prepared<AePort, Block>, AePort)> {
    let port = AePort::new();
    let mut owner =
        Prepared::allocate_for(Chip::Rtl8821ae, port.clone(), 4, |b| Ok(port.block(b))).ok()?;
    for (reg, ring) in TX_BASES.iter().zip(&owner.tx) {
        port.set32(*reg, ring.address() as u32);
    }
    port.set32(
        super::super::super::RX_BASE,
        owner.receive.as_ref()?.address() as u32,
    );
    // Hardware RCR as rewritten by the MAC table rows.
    port.set32(mac::REG_RCR, 0xf400_2a0e);
    let factory = Factory {
        mac: MAC,
        logical: ae::powered_logical(0xf2, 2),
    };
    let cal = envelope::Calibration::from_verified(
        &ae::napc(&factory, &[1], 30),
        Some([1; 32]),
        &factory,
    )
    .ok()?;
    owner.rtl8821ae_power = Some(cal.permission(&domain(20), 1).ok()?);
    owner.packet.local = Some(MAC);
    owner.published = true;
    owner.phase = Phase::MacConfigured;
    Some((owner, port))
}

fn tx_word(owner: &Prepared<AePort, Block>, queue: usize, slot: usize, word: usize) -> u32 {
    owner.tx[queue].read32(slot * 64 + word * 4).unwrap()
}

fn smoke_rtl8821ae_native_owner_start_descriptors_receipt_and_rx() -> TestResult {
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
        || port.reg32(mac::REG_RCR) != mac::RCR & !0xc0
        || port.reg8(hw::MSR) & 3 != hw::MSR_INFRA
        || port.reg8(0x511) != 0x66
        || port.reg8(0x550) != (0x1d & !2) | 0x10
    {
        return TestResult::Fail("hw_init DMA release / set_network_type(STATION) differ");
    }
    // Broadcast probe request on MGNT: forced 1M, DISFB, HWSEQ, MC rate id.
    let mut probe = vec![0u8; 30];
    probe[0] = 0x40;
    probe[4..10].copy_from_slice(&[0xff; 6]);
    probe[10..16].copy_from_slice(&MAC);
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
        || port.0.lock().kicks != [1 << 6]
    {
        return TestResult::Fail("rtl8821ae_tx_fill_desc fields / doorbell");
    }
    if owner.submit(&probe, 12).is_ok() {
        return TestResult::Fail("second frame while one is outstanding");
    }
    // Device retires the descriptor: clear OWN only.
    owner.tx[1].write32(slot * 64, dw0 & !OWN).unwrap();
    match owner.poll_delivery() {
        Ok(Some(d)) if d.id == id && d.bytes == probe => {}
        _ => return TestResult::Fail("host receipt of the exact payload"),
    }
    if owner.submit(&probe, 12).is_ok() {
        return TestResult::Fail("HT rate admitted on the legacy profile");
    }
    // RX: one beacon (24 + FCS) at drvinfo 0 / shift 0, then a C2H buffer.
    let rx = owner.packet.receive;
    let mut beacon = vec![0u8; 28];
    beacon[0] = 0x80;
    beacon[4..10].copy_from_slice(&[0xff; 6]);
    owner.buffers[rx].write_bytes(0, &beacon).unwrap();
    let ring = owner.receive.as_mut().unwrap();
    ring.write32(rx * 32, 28).unwrap();
    ring.write32(rx * 32 + 12, 0).unwrap();
    let step = owner.poll_receive_step();
    let rearmed = owner.receive.as_ref().unwrap().read32(rx * 32).unwrap();
    match step {
        Ok(s)
            if s.consumed
                && s.packet
                    .as_ref()
                    .is_some_and(|p| p.bytes() == &beacon[..24]) => {}
        _ => return TestResult::Fail("legacy beacon not delivered without FCS"),
    }
    if rearmed != 9100 | OWN {
        return TestResult::Fail("RX descriptor not re-armed");
    }
    let rx = owner.packet.receive;
    let ring = owner.receive.as_mut().unwrap();
    ring.write32(rx * 32, 16).unwrap();
    ring.write32(rx * 32 + 8, 1 << 28).unwrap();
    match owner.poll_receive_step() {
        Ok(s) if s.consumed && s.packet.is_none() => {}
        _ => return TestResult::Fail("C2H report buffer must be consumed and dropped"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_native_owner_start_descriptors_receipt_and_rx
);

fn smoke_rtl8821ae_native_join_rsvd_page_h2c_and_leave() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    port.set8(0x6a9, 0xc0);
    if owner.start_packets().is_err()
        || run(owner.prepare_station_peer(PEER, 0x0fff, 0x015f, 0x0421)).is_err()
    {
        return TestResult::Fail("start / authentication-time registers");
    }
    if (0..6).any(|i| port.reg8(hw::REG_BSSID + i) != PEER[usize::from(i)])
        || port.wrote(2, hw::REG_RRSR, 0x15f).is_none()
        || port.reg8(hw::REG_SLOT) != 9
        || port.reg8(hw::REG_SIFS_CTX + 1) != 0x0a
        || port.reg8(hw::REG_RESP_SIFS_OFDM + 1) != 0x0a
        || port.reg32(hw::REG_EDCA_BK_PARAM) != 0xa44f
        || port.reg8(hw::REG_TRXPTCL_CTL + 2) & 2 == 0
    {
        return TestResult::Fail("BSSID/RRSR/slot/SIFS/set_qos/preamble");
    }
    port.0.lock().writes.clear();
    if run(owner.complete_station_peer(PEER, 5)).is_err() {
        return TestResult::Fail("association join");
    }
    let cam = port.wrote(4, hw::REG_CAMCMD, 0xc000_0000);
    let keepalive = port.wrote(1, 0x1d0, 3);
    let linked = port.wrote(4, mac::REG_RCR, mac::RCR | 0xc0);
    let aid = port.wrote(2, hw::REG_BCN_PSR_RPT, 0xc005);
    let rsvd_loc = port.wrote(1, 0x1d4, h2c::H2C_RSVDPAGE.into());
    let msr = port.wrote(1, 0x1d8, h2c::H2C_MSRRPT.into());
    let order = [cam, keepalive, linked, aid, rsvd_loc, msr];
    if order.iter().any(Option::is_none) || order.windows(2).any(|w| w[0] > w[1]) {
        return TestResult::Fail("CAM, KEEP_ALIVE, network type, AID, RSVDPAGE, MSRRPT order");
    }
    // RSVDPAGE location is a 5-byte command: extension box first.
    if port.reg8(0x1d5) != 0 || port.reg8(0x1d6) != 1 || port.reg8(0x1d7) != 2 {
        return TestResult::Fail("rsvdpage location payload");
    }
    let Some(reserved) = owner.packet.reserved.as_ref() else {
        return TestResult::Fail("reserved page body not retained");
    };
    let mut body = vec![0u8; hw::RSVD_PAGE_LEN];
    reserved.read_bytes(0, &mut body).unwrap();
    let Ok(expected) = hw::reserved_pages(MAC, PEER, 5) else {
        return TestResult::Fail("page builder");
    };
    if body != expected
        || body[256 + 2..256 + 4] != [5, 0xc0]
        || body[512 + 4..512 + 10] != PEER
        || body[1024 + 10..1024 + 16] != MAC
    {
        return TestResult::Fail("rtl8821ae_set_fw_rsvdpagepkt bodies");
    }
    let descriptor = hw::command_descriptor(hw::RSVD_PAGE_LEN as u16, reserved.address() as u32);
    if (0..11).any(|w| {
        tx_word(&owner, 0, 0, w)
            != if w == 0 {
                descriptor[0] | OWN
            } else {
                descriptor[w]
            }
    }) || !port.0.lock().kicks.contains(&(1 << 4))
        || port.reg8(0x101) & 1 != 0
    {
        return TestResult::Fail("tx_fill_cmddesc on BEACON descriptor 0 / CR+1 restore");
    }
    let g = h2c::Peer {
        legacy: 0x0fff,
        ht: None,
        sgi20: false,
        sgi40: false,
        vht: None,
        sgi80: false,
        five_ghz: false,
    };
    if run(owner.install_rtl8821ae_rate_mask(h2c::rate_mask(&g, false, 0, true), None)).is_err()
        || owner.packet.rate_mask != Some(4)
        || port.reg8(0x550) & 8 == 0
    {
        return TestResult::Fail("RA mask H2C and ratr_index");
    }
    port.0.lock().writes.clear();
    if run(owner.leave_station_peer()).is_err()
        || port.reg32(mac::REG_RCR) != mac::RCR & !0xc0
        || (0..6).any(|i| port.reg8(hw::REG_BSSID + i) != 0)
        // Boxes so far: KEEP_ALIVE 0, RSVDPAGE 1, MSRRPT 2, RA_MASK 3;
        // `last_hmeboxnum` wraps, so the disconnect report takes box 0.
        || port.wrote(1, 0x1d0, h2c::H2C_MSRRPT.into()).is_none()
        || port.reg8(0x1d1) != 0
        || owner.packet.rate_mask.is_some()
        || owner.packet.retired.len() != 1
    {
        return TestResult::Fail("disassociation: network type, MSRRPT 0, BSSID zero");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_native_join_rsvd_page_h2c_and_leave
);

fn smoke_rtl8821ae_bt_function_board_admitted_with_coexistence() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    let factory = Factory {
        mac: MAC,
        logical: ae::powered_logical(0xf2, 2),
    };
    owner.rtl8821ae_identity = Some(super::super::super::super::radio::factory_identity(
        &factory,
    ));
    owner.phase = Phase::ChannelConfigured;
    owner.packet.local = None;
    // BT-strapped board: admitted with a coexistence owner.
    port.set32(0x68, 1 << 18);
    if owner.configure_rtl8821ae_mac(&factory).is_err()
        || owner.phase != Phase::MacConfigured
        || owner.packet.local != Some(MAC)
        || owner.rtl8821ae_coex().is_none()
    {
        return TestResult::Fail("BT-function board refused or admitted without coexistence");
    }
    // Another factory identity is still refused (phase reset first so
    // the identity check, not the phase check, decides).
    owner.phase = Phase::ChannelConfigured;
    owner.packet.local = None;
    let mut other = factory.clone();
    other.mac[5] ^= 1;
    if owner.configure_rtl8821ae_mac(&other).is_ok() {
        return TestResult::Fail("another factory identity admitted");
    }
    // WLAN-only board: admitted with no coexistence owner.
    owner.phase = Phase::ChannelConfigured;
    port.set32(0x68, 0);
    if owner.configure_rtl8821ae_mac(&factory).is_err()
        || owner.phase != Phase::MacConfigured
        || owner.packet.local != Some(MAC)
        || owner.rtl8821ae_coex().is_some()
    {
        return TestResult::Fail("WLAN-only board refused or given a coexistence owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_bt_function_board_admitted_with_coexistence
);

fn smoke_rtl8821ae_coex_bt_only_holds_lps_off() -> TestResult {
    use super::super::super::super::btcoex::BtState;
    let Some((mut owner, _port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    owner.phase = Phase::Running;
    // Baseline (no coexistence owner): LPS enter and leave proceed.
    if run(owner.enter_leisure()).is_err() || !owner.leisure() {
        return TestResult::Fail("baseline LPS enter failed");
    }
    if run(owner.leave_leisure()).is_err() || owner.leisure() {
        return TestResult::Fail("baseline LPS leave failed");
    }
    // BT-strapped owner with BT streaming: enter is a held-off no-op —
    // Ok, but `leisure` stays false and the phase stays Running.
    owner.rtl8821ae_coex = Some(Box::new(
        super::super::super::super::rtl8821ae::coex::Owner::bind(),
    ));
    owner
        .rtl8821ae_coex
        .as_mut()
        .unwrap()
        .notify_bt(BtState::Streaming);
    if run(owner.enter_leisure()).is_err() || owner.leisure() || owner.phase != Phase::Running {
        return TestResult::Fail("BtOnly LPS enter not held off");
    }
    // BT idle releases the antenna: enter proceeds again.
    owner
        .rtl8821ae_coex
        .as_mut()
        .unwrap()
        .notify_bt(BtState::Idle);
    if run(owner.enter_leisure()).is_err() || !owner.leisure() {
        return TestResult::Fail("BT idle LPS enter failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_coex_bt_only_holds_lps_off
);

/// Deliver one RX buffer: `bytes` at offset 0, descriptor dwords 0 and 2..4.
fn rx_buffer(
    owner: &mut Prepared<AePort, Block>,
    bytes: &[u8],
    dw0: u32,
    dw2: u32,
    dw3: u32,
) -> Result<super::super::ReceiveStep, Error> {
    let rx = owner.packet.receive;
    // The device's status write-back keeps the EOR bit the host armed on
    // the last descriptor (`rtl8821ae_set_desc` HW_DESC_RXERO).
    let eor = if rx + 1 == owner.depth { 1 << 30 } else { 0 };
    owner.buffers[rx].write_bytes(0, bytes).unwrap();
    let ring = owner.receive.as_mut().unwrap();
    ring.write32(rx * 32, dw0 | eor).unwrap();
    ring.write32(rx * 32 + 8, dw2).unwrap();
    ring.write32(rx * 32 + 12, dw3).unwrap();
    owner.poll_receive_step()
}

fn retire(owner: &mut Prepared<AePort, Block>, queue: usize, slot: usize) -> Option<u64> {
    let dw0 = tx_word(owner, queue, slot, 0);
    owner.tx[queue].write32(slot * 64, dw0 & !OWN).unwrap();
    owner.poll_delivery().ok().flatten().map(|d| d.id)
}

fn smoke_rtl8821ae_c2h_tx_ra_reports_pwdb_and_firmware_rate_adaptation() -> TestResult {
    let Some((mut owner, port)) = owner() else {
        return TestResult::Fail("fixture");
    };
    if owner.start_packets().is_err() {
        return TestResult::Fail("start_packets");
    }
    // Association mask installed (RATR_INX_WIRELESS_GB).
    owner.packet.rate_mask = Some(4);
    // EAPOL (unprotected, ToDS): forced rate with SPE_RPT, SW_DEFINE 4.
    let mut eapol = vec![0u8; 40];
    eapol[0] = 0x08;
    eapol[1] = 0x01;
    eapol[4..10].copy_from_slice(&PEER);
    eapol[10..16].copy_from_slice(&MAC);
    eapol[16..22].copy_from_slice(&PEER);
    eapol[24..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    let slot = owner.packet.next[4];
    let Ok(id) = owner.submit(&eapol, 4) else {
        return TestResult::Fail("EAPOL submit");
    };
    if tx_word(&owner, 4, slot, 2) & (1 << 19) == 0
        || tx_word(&owner, 4, slot, 6) & 0xfff != 4
        || tx_word(&owner, 4, slot, 3) & ((1 << 8) | (1 << 10)) != (1 << 8) | (1 << 10)
        || tx_word(&owner, 4, slot, 4) & 0x7f != 4
    {
        return TestResult::Fail("rtl_set_tx_report / forced EAPOL descriptor");
    }
    if retire(&mut owner, 4, slot) != Some(id) || owner.rtl8821ae_tx_reports_settled() {
        return TestResult::Fail("EAPOL receipt / report still outstanding");
    }
    // C2H_TX_REPORT V1: st byte0[7:6] 0, retry byte2[5:0] 2, sn byte6 4.
    let report = [3u8, 0, 0, 0, 2, 0, 0, 0, 4];
    match rx_buffer(&mut owner, &report, report.len() as u32, 1 << 28, 0) {
        Ok(s) if s.consumed && s.packet.is_none() => {}
        _ => return TestResult::Fail("C2H TX report not consumed"),
    }
    match owner.take_rtl8821ae_tx_report() {
        Some(r) if r.id == id && r.acked && r.retry == 2 => {}
        _ => return TestResult::Fail("TX report not matched to the EAPOL frame"),
    }
    if !owner.rtl8821ae_tx_reports_settled() {
        return TestResult::Fail("rtl_check_tx_report_acked after the report");
    }
    // Ordinary DATA under firmware RA: no USE_RATE/DISFB, 54M, ratr_index.
    let mut data = eapol.clone();
    data[30..32].copy_from_slice(&[0x08, 0x00]);
    let slot = owner.packet.next[4];
    let Ok(id) = owner.submit_aggregate(&data, 4, None, true, false) else {
        return TestResult::Fail("adaptive DATA refused");
    };
    if tx_word(&owner, 4, slot, 3) & ((1 << 8) | (1 << 10)) != 0
        || tx_word(&owner, 4, slot, 4) & 0x7f != 0x0b
        || (tx_word(&owner, 4, slot, 1) >> 16) & 0x1f != 4
        || tx_word(&owner, 4, slot, 2) & (1 << 19) != 0
    {
        return TestResult::Fail("rtl_get_tcb_desc firmware-RA DATA descriptor");
    }
    if retire(&mut owner, 4, slot) != Some(id) {
        return TestResult::Fail("DATA receipt");
    }
    let mut null = data[..24].to_vec();
    null[0] = 0x48;
    if owner.submit_aggregate(&null, 4, None, true, false).is_ok() {
        return TestResult::Fail("Null frame given firmware RA");
    }
    // C2H_RA_RPT: 54M; the DM step rewrites RA_TXSCALE with the default
    // swing's table entry (54M limit 28 >= index).
    let swing = owner.rtl8821ae_power.unwrap().swing();
    port.set32(0xc1c, 0x0000_0123);
    match rx_buffer(&mut owner, &[12, 0, 0x0b], 3, 1 << 28, 0) {
        Ok(s) if s.consumed => {}
        _ => return TestResult::Fail("C2H RA report not consumed"),
    }
    if owner.rtl8821ae_ra_rate() != Some(0x0b)
        || !matches!(owner.update_rtl8821ae_init_rate(), Ok(true))
        || !matches!(owner.update_rtl8821ae_init_rate(), Ok(false))
    {
        return TestResult::Fail("RA report not applied exactly once");
    }
    let index =
        usize::from(super::super::super::super::rtl8821ae::channel::default_ofdm_index(swing));
    let table = super::super::super::super::rtl8821ae::channel::TXSCALING[index];
    if port.reg32(0xc1c) != (table << 21) | 0x123 {
        return TestResult::Fail("dm_update_init_rate MIX_MODE RA_TXSCALE");
    }
    // PHY status: OFDM 6M beacon with drvinfo 8 bytes, pwdb_all 0x8c -> 60.
    let mut buffer = vec![0u8; 8 + 28];
    buffer[4] = 0x8c;
    buffer[8] = 0x80;
    buffer[12..18].copy_from_slice(&[0xff; 6]);
    buffer[24..30].copy_from_slice(&PEER);
    match rx_buffer(&mut owner, &buffer, 28 | (1 << 16) | (1 << 26), 0, 4) {
        Ok(s) if s.packet.as_ref().and_then(|p| p.pwdb()) == Some(60) => {}
        _ => return TestResult::Fail("OFDM PWDB not decoded"),
    }
    // CCK 1M: cfosho[0] LNA1 VGA3 -> -7 dBm -> 93.
    buffer[4] = 0;
    buffer[5] = (1 << 5) | 3;
    match rx_buffer(&mut owner, &buffer, 28 | (1 << 16) | (1 << 26), 0, 0) {
        Ok(s) if s.packet.as_ref().and_then(|p| p.pwdb()) == Some(93) => {}
        _ => return TestResult::Fail("CCK PWDB not decoded"),
    }
    // PHYST without room for the PHY status is a descriptor error.
    if rx_buffer(&mut owner, &buffer[8..], 28 | (1 << 26), 0, 0).is_ok() {
        return TestResult::Fail("PHYST without drvinfo accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_rtl8821ae_c2h_tx_ra_reports_pwdb_and_firmware_rate_adaptation
);
