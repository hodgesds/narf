//! Retained first-channel native radio owner. TX starts only through the
//! private signed-power path; the controlled port remains closed. Reusing
//! this owner never changes the channel label.
use super::{
    firmware_transport::{ControlIo, Error as ControlError, Owner as Firmware, Stage},
    packet_codec::{Mpdu, Record},
    packet_transport::{self, Io as PacketIo, Owner as Packets},
};
use alloc::{sync::Arc, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Control(ControlError),
    Packet(packet_transport::Error),
    State,
    Policy,
    Power(super::power_policy::Error),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Starting,
    Receiving,
    EnablingTransmit,
    Active,
    Configuring,
    Stopped,
    Failed,
}
/// The caller authenticates the deployment regulatory domain; this value
/// bounds the supported receive profile and grants no TX gain/power authority. The initial
/// profile receives on channel1 only; no hot retune is implemented.
#[derive(Debug, Clone, Copy)]
pub struct Permission {
    channel: u8,
}
impl Permission {
    pub fn from_domain(domain: &narf_wireless::reg::RegulatoryDomain) -> Result<Self, Error> {
        if domain.rules.iter().any(|r| {
            r.freq_start_mhz <= 2402
                && r.freq_end_mhz >= 2422
                && r.max_bandwidth_mhz >= 20
                && r.flags.is_empty()
        }) {
            Ok(Self { channel: 1 })
        } else {
            Err(Error::Policy)
        }
    }
}
pub struct Receiver<C: ControlIo, B: PacketIo> {
    firmware: Arc<Firmware<C>>,
    packets: Packets<B>,
    phase: Phase,
    mailbox: u8,
    peer: Option<[u8; 6]>,
    wmm: Option<Arc<super::wmm_runtime::Proof>>,
}
impl<C: ControlIo, B: PacketIo> core::fmt::Debug for Receiver<C, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euReceiver")
            .field("phase", &self.phase)
            .field("channel", &self.packets.channel())
            .finish_non_exhaustive()
    }
}
struct Attempt<C: ControlIo> {
    firmware: Arc<Firmware<C>>,
    armed: bool,
}
impl<C: ControlIo> Drop for Attempt<C> {
    fn drop(&mut self) {
        if self.armed {
            self.firmware.runtime_failed(ControlError::Cancelled);
        }
    }
}
impl<C: ControlIo, B: PacketIo> Receiver<C, B> {
    pub fn new(firmware: Arc<Firmware<C>>, io: B, permission: Permission) -> Result<Self, Error> {
        if firmware.status().stage != Stage::RadioReady || firmware.calibration().is_none() {
            return Err(Error::State);
        }
        let endpoints = firmware.endpoints().ok_or(Error::State)?;
        let packets = Packets::new(io, endpoints, permission.channel).map_err(Error::Packet)?;
        firmware.claim_receive().map_err(Error::Control)?;
        Ok(Self {
            firmware,
            packets,
            phase: Phase::Prepared,
            mailbox: 0,
            peer: None,
            wmm: None,
        })
    }
    pub fn phase(&self) -> Phase {
        if self.firmware.status().stage == Stage::Failed {
            Phase::Failed
        } else {
            self.phase
        }
    }
    pub(super) fn wmm_proof(&self) -> Option<Arc<super::wmm_runtime::Proof>> {
        self.wmm.clone()
    }
    pub(super) fn qualify_wmm(
        &mut self,
        permission: super::power_policy::Permission,
    ) -> Result<(), Error> {
        if self.wmm.is_none() {
            let factory = self.firmware.factory().ok_or(Error::State)?;
            let (vid, pid) = self.firmware.usb_identity().ok_or(Error::State)?;
            self.wmm = Some(super::wmm_runtime::Proof::registered(
                factory, vid, pid, permission,
            )?);
        }
        self.current_wmm()
    }
    pub(super) fn current_wmm(&self) -> Result<(), Error> {
        if let Some(proof) = &self.wmm {
            proof.invoke(|| ())?;
        }
        Ok(())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn install_wmm_model(&mut self, proof: Arc<super::wmm_runtime::Proof>) {
        self.wmm = Some(proof);
    }
    pub(super) async fn configure_wmm(
        &mut self,
        p: narf_wireless::wmm::Parameters,
        short: bool,
    ) -> Result<(), Error> {
        let values = super::wmm_runtime::words(p, short)?;
        if self.phase() != Phase::Active || self.wmm.is_none() {
            return Err(Error::State);
        }
        let proof = self.wmm.clone().ok_or(Error::State)?;
        self.phase = Phase::Configuring;
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let result = proof
            .fence(
                async {
                    for (reg, value) in [0x508, 0x50c, 0x504, 0x500].into_iter().zip(values) {
                        self.firmware
                            .write32(reg, value)
                            .await
                            .map_err(Error::Control)?;
                        if self.firmware.read32(reg).await.map_err(Error::Control)? != value {
                            return Err(Error::State);
                        }
                    }
                    let acm = self.firmware.read8(0x5c0).await.map_err(Error::Control)? & !0x0e;
                    self.firmware
                        .write8(0x5c0, acm)
                        .await
                        .map_err(Error::Control)?;
                    if self.firmware.read8(0x5c0).await.map_err(Error::Control)? != acm {
                        return Err(Error::State);
                    }
                    Ok(())
                },
                core::convert::identity,
            )
            .await;
        attempt.armed = false;
        if result.is_ok() {
            self.packets.qos = true;
            self.phase = Phase::Active;
        } else {
            self.fail();
        }
        result
    }
    pub fn channel(&self) -> u8 {
        self.packets.channel()
    }
    pub async fn start(&mut self) -> Result<(), Error> {
        if !matches!(self.phase(), Phase::Prepared | Phase::Stopped) {
            return Err(Error::State);
        }
        // Closing local admission before the first await is cancellation safe.
        self.phase = Phase::Starting;
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let result = async {
            let cr = self.firmware.read16(0x100).await.map_err(Error::Control)?;
            if cr & 0xc0 != 0 {
                return Err(Error::State);
            }
            self.packets.start().map_err(Error::Packet)?;
            // Linux start enables data/management filter maps and resets IGI
            // after posting RX URBs. The firmware/table stage alone does not
            // establish these receive-admission registers.
            for register in [0x6a4, 0x6a0] {
                self.firmware
                    .write16(register, 0xffff)
                    .await
                    .map_err(Error::Control)?;
                if self
                    .firmware
                    .read16(register)
                    .await
                    .map_err(Error::Control)?
                    != 0xffff
                {
                    return Err(Error::State);
                }
            }
            let igi = (self.firmware.read32(0xc50).await.map_err(Error::Control)? & !0x7f) | 0x1e;
            self.firmware
                .write32(0xc50, igi)
                .await
                .map_err(Error::Control)?;
            if self.firmware.read32(0xc50).await.map_err(Error::Control)? != igi {
                return Err(Error::State);
            }
            // The controller owns an RX buffer before MAC RX opens. TX bit6
            // remains clear; no transmitter or station key state is created.
            self.firmware
                .write16(0x100, cr | 0x80)
                .await
                .map_err(Error::Control)?;
            let cr = self.firmware.read16(0x100).await.map_err(Error::Control)?;
            if cr & 0xc0 != 0x80 {
                return Err(Error::State);
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.phase = Phase::Receiving;
                self.firmware.receiving();
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    pub fn poll(&mut self) -> Result<Option<Vec<Mpdu>>, Error> {
        if !matches!(self.phase(), Phase::Receiving | Phase::Active) {
            return Err(Error::State);
        }
        match self.packets.poll_receive() {
            Ok(None) => Ok(None),
            Ok(Some(records)) => Ok(Some(
                records
                    .into_iter()
                    .filter_map(|r| match r {
                        // Hardware decryption is disabled. Never adopt unexpected
                        // plaintext metadata as a software-authenticated MPDU.
                        Record::Frame(f) if !f.decrypted => Some(f),
                        _ => None,
                    })
                    .collect(),
            )),
            Err(error) => {
                self.fail();
                Err(Error::Packet(error))
            }
        }
    }
    pub async fn stop(&mut self) -> Result<(), Error> {
        if !matches!(self.phase(), Phase::Receiving | Phase::Active) {
            return Err(Error::State);
        }
        let was_active = self.phase == Phase::Active;
        self.phase = Phase::Starting;
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let result = async {
            let cr = self.firmware.read16(0x100).await.map_err(Error::Control)?;
            if (cr & 0x40 != 0) != was_active {
                return Err(Error::State);
            }
            self.firmware
                .write16(0x100, cr & !0xc0)
                .await
                .map_err(Error::Control)?;
            if self.firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0 {
                return Err(Error::State);
            }
            for register in [0x6a0, 0x6a4] {
                self.firmware
                    .write16(register, 0)
                    .await
                    .map_err(Error::Control)?;
                if self
                    .firmware
                    .read16(register)
                    .await
                    .map_err(Error::Control)?
                    != 0
                {
                    return Err(Error::State);
                }
            }
            // A successful EP0 closure precedes host Stop/SetDeq. No USB
            // cleanup is attempted after an ambiguous EP0 error/cancellation.
            self.packets.stop().await.map_err(Error::Packet)
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.phase = Phase::Stopped;
                self.firmware.receive_stopped();
                Ok(())
            }
            Err(e) => {
                self.fail();
                Err(e)
            }
        }
    }
    /// Private activation for the pending station owner. Every selected gain
    /// comes from the signed per-device curve intersected with host policy.
    pub(super) async fn enable_transmit(
        &mut self,
        permission: super::power_policy::Permission,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Receiving {
            return Err(Error::State);
        }
        let factory = self.firmware.factory().ok_or(Error::State)?;
        let (vid, pid) = self.firmware.usb_identity().ok_or(Error::State)?;
        let (cck, ofdm) = permission
            .gains(factory, vid, pid, self.channel())
            .map_err(Error::Power)?;
        self.phase = Phase::EnablingTransmit;
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let result = async {
            let cr = self.firmware.read16(0x100).await.map_err(Error::Control)?;
            if cr & 0xc0 != 0x80 {
                return Err(Error::State);
            }
            // The CCK/OFDM register lanes follow Linux rtl8188f_set_tx_power.
            // Other lanes and controls survive; no unqualified MCS mode is
            // enabled by this legacy-only owner.
            for (register, mask, bits) in [
                (
                    super::calibration_regs::REG_TX_AGC_A_CCK1_MCS32,
                    0xff00u32,
                    u32::from(cck) << 8,
                ),
                (
                    super::calibration_regs::REG_TX_AGC_B_CCK11_A_CCK2_11,
                    0xffffff00,
                    u32::from(cck) * 0x01010100,
                ),
                (
                    super::calibration_regs::REG_TX_AGC_A_RATE18_06,
                    u32::MAX,
                    u32::from(ofdm) * 0x01010101,
                ),
                (
                    super::calibration_regs::REG_TX_AGC_A_RATE54_24,
                    u32::MAX,
                    u32::from(ofdm) * 0x01010101,
                ),
                (
                    super::calibration_regs::REG_RESPONSE_RATE_SET,
                    super::calibration_regs::RESPONSE_RATE_BITMAP_ALL,
                    1, // Only legacy1Mbps; the Linux-named CCK_ONLY_1M value also enables other rates.
                ),
            ] {
                let prior = self
                    .firmware
                    .read32(register)
                    .await
                    .map_err(Error::Control)?;
                let target = (prior & !mask) | bits;
                self.firmware
                    .write32(register, target)
                    .await
                    .map_err(Error::Control)?;
                if self
                    .firmware
                    .read32(register)
                    .await
                    .map_err(Error::Control)?
                    != target
                {
                    return Err(Error::State);
                }
            }
            self.firmware
                .write16(0x100, cr | 0x40)
                .await
                .map_err(Error::Control)?;
            if self.firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0xc0 {
                return Err(Error::State);
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.phase = Phase::Active;
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    pub(super) fn submit_management(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.current_wmm()?;
        if self.phase() != Phase::Active {
            return Err(Error::State);
        }
        let factory = self.firmware.factory().ok_or(Error::State)?;
        if frame.len() < 24
            || frame[10..16] != factory.mac
            || frame[4..10] != frame[16..22]
            || frame[4] & 1 != 0
            || frame[4..10] == [0; 6]
            || frame[4..10] == factory.mac
            || frame[1] & 0xc7 != 0
        {
            return Err(Error::State);
        }
        let result = self
            .packets
            .submit(super::packet_codec::Kind::Management, frame);
        if self.packets.is_failed() {
            self.fail();
        }
        result.map_err(Error::Packet)
    }
    pub(super) fn poll_delivery(
        &mut self,
    ) -> Result<Option<super::packet_transport::Delivered>, Error> {
        self.current_wmm()?;
        if self.phase() != Phase::Active {
            return Err(Error::State);
        }
        match self.packets.poll_transmit() {
            Ok(result) => Ok(result),
            Err(error) => {
                self.fail();
                Err(Error::Packet(error))
            }
        }
    }
    pub(super) fn matches_power(&self, permission: super::power_policy::Permission) -> bool {
        match (self.firmware.factory(), self.firmware.usb_identity()) {
            (Some(factory), Some((vid, pid))) => {
                permission.gains(factory, vid, pid, self.channel()).is_ok()
            }
            _ => false,
        }
    }
    pub(super) fn local(&self) -> Option<[u8; 6]> {
        self.firmware.factory().map(|f| f.mac)
    }
    pub(super) fn fail_terminal(&mut self) {
        self.fail();
    }
    pub(super) fn submit_native_data(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.submit_native_data_rate(frame, 0)
    }
    pub(super) fn submit_native_data_rate(&mut self, frame: &[u8], rate: u8) -> Result<(), Error> {
        self.current_wmm()?;
        if rate != 0 && self.wmm.is_none() {
            return Err(Error::State);
        }
        if self.phase() != Phase::Active
            || frame.len() < 24
            || frame[10..16] != self.local().ok_or(Error::State)?
            || Some(frame[4..10].try_into().unwrap()) != self.peer
        {
            return Err(Error::State);
        }
        let proof = self.wmm.clone();
        let mut submit = || {
            self.packets
                .submit_rate(super::packet_codec::Kind::Data, frame, rate)
        };
        let result = if let Some(proof) = proof {
            proof.invoke(submit)?
        } else {
            submit()
        };
        if self.packets.is_failed() {
            self.fail();
        }
        result.map_err(Error::Packet)
    }
    /// Serialized unicast station programming, from Linux set_linktype and
    /// set_bssid. This owner has no packet in flight during this transition.
    pub(super) async fn prepare_station(
        &mut self,
        peer: [u8; 6],
        short_slot: bool,
    ) -> Result<(), Error> {
        if self.phase() != Phase::Active
            || peer == [0; 6]
            || peer[0] & 1 != 0
            || Some(peer) == self.local()
            || self.peer.is_some()
        {
            return Err(Error::State);
        }
        self.phase = Phase::Configuring;
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let result = async {
            if self.firmware.read16(0x100).await.map_err(Error::Control)? & 0xc0 != 0xc0 {
                return Err(Error::State);
            }
            // Linux add_interface(STATION, port0): suppress local beacons
            // and enable the port's receive/TSF function with ATIM semantics.
            let q = self.firmware.read8(0x422).await.map_err(Error::Control)?;
            self.firmware
                .write8(0x422, q & !0x40)
                .await
                .map_err(Error::Control)?;
            self.firmware
                .write8(0x541, 0x64)
                .await
                .map_err(Error::Control)?;
            let t = self.firmware.read8(0x542).await.map_err(Error::Control)?;
            self.firmware
                .write8(0x542, t & !1)
                .await
                .map_err(Error::Control)?;
            let beacon = self.firmware.read8(0x550).await.map_err(Error::Control)? | 0x19;
            self.firmware
                .write8(0x550, beacon)
                .await
                .map_err(Error::Control)?;
            if self.firmware.read8(0x550).await.map_err(Error::Control)? != beacon {
                return Err(Error::State);
            }
            let prior = self.firmware.read8(0x102).await.map_err(Error::Control)?;
            let msr = (prior & 0x0c) | 2;
            self.firmware
                .write8(0x102, msr)
                .await
                .map_err(Error::Control)?;
            if self.firmware.read8(0x102).await.map_err(Error::Control)? != msr {
                return Err(Error::State);
            }
            for (i, byte) in peer.iter().enumerate() {
                let reg = 0x618 + i as u16;
                self.firmware
                    .write8(reg, *byte)
                    .await
                    .map_err(Error::Control)?;
                if self.firmware.read8(reg).await.map_err(Error::Control)? != *byte {
                    return Err(Error::State);
                }
            }
            self.firmware
                .write8(0x51b, if short_slot { 9 } else { 20 })
                .await
                .map_err(Error::Control)?;
            // This one-channel passive scan is complete. Linux's scan_complete
            // permits TSF updates only after the selected BSSID is installed.
            let beacon = beacon & !0x10;
            self.firmware
                .write8(0x550, beacon)
                .await
                .map_err(Error::Control)?;
            if self.firmware.read8(0x550).await.map_err(Error::Control)? != beacon {
                return Err(Error::State);
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.peer = Some(peer);
                self.phase = Phase::Active;
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    /// Port0 Linux association bookkeeping and gen2 MEDIA_STATUS_RPT. The
    /// fixed-rate legacy profile does not enable host rate adaptation/HT.
    pub(super) async fn association(&mut self, aid: u16, connected: bool) -> Result<(), Error> {
        if self.phase() != Phase::Active
            || self.peer.is_none()
            || connected && !(1..=2007).contains(&aid)
        {
            return Err(Error::State);
        }
        self.phase = Phase::Configuring;
        let mut attempt = Attempt {
            firmware: self.firmware.clone(),
            armed: true,
        };
        let mailbox = self.mailbox;
        let result = async {
            if connected {
                self.firmware
                    .write8(0x55d, 255)
                    .await
                    .map_err(Error::Control)?;
                let q = self.firmware.read8(0x422).await.map_err(Error::Control)?;
                self.firmware
                    .write8(0x422, q & !0x40)
                    .await
                    .map_err(Error::Control)?;
                self.firmware
                    .write8(0x541, 0x64)
                    .await
                    .map_err(Error::Control)?;
                let t = self.firmware.read8(0x542).await.map_err(Error::Control)?;
                self.firmware
                    .write8(0x542, t & !1)
                    .await
                    .map_err(Error::Control)?;
                self.firmware
                    .write16(0x6a8, 0xc000 | aid)
                    .await
                    .map_err(Error::Control)?;
                if self.firmware.read16(0x6a8).await.map_err(Error::Control)? != 0xc000 | aid {
                    return Err(Error::State);
                }
            } else {
                // Linux bss_info_changed disconnect: suppress peer TSF updates
                // before publishing the disconnected media command.
                let beacon = self.firmware.read8(0x550).await.map_err(Error::Control)? | 0x10;
                self.firmware
                    .write8(0x550, beacon)
                    .await
                    .map_err(Error::Control)?;
                if self.firmware.read8(0x550).await.map_err(Error::Control)? != beacon {
                    return Err(Error::State);
                }
            }
            // Availability precedes publication. Any failed/dropped EP0
            // poisons the entire radio; mailbox contents are never replayed.
            let mut ready = false;
            for _ in 0..100 {
                if self.firmware.read8(0x1cc).await.map_err(Error::Control)? & (1 << mailbox) == 0 {
                    ready = true;
                    break;
                }
                self.firmware.delay_us(50).await;
            }
            if !ready {
                return Err(Error::State);
            }
            self.firmware
                .write32(
                    0x1d0 + u16::from(mailbox) * 4,
                    if connected { 0x2101 } else { 0x2001 },
                )
                .await
                .map_err(Error::Control)?;
            let mut consumed = false;
            for _ in 0..100 {
                if self.firmware.read8(0x1cc).await.map_err(Error::Control)? & (1 << mailbox) == 0 {
                    consumed = true;
                    break;
                }
                self.firmware.delay_us(50).await;
            }
            if !consumed {
                return Err(Error::State);
            }
            Ok(())
        }
        .await;
        attempt.armed = false;
        match result {
            Ok(()) => {
                self.mailbox = (mailbox + 1) % 4;
                self.phase = Phase::Active;
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    fn fail(&mut self) {
        self.phase = Phase::Failed;
        self.packets.fail();
        self.firmware.runtime_failed(ControlError::RuntimeState);
    }
}
impl<C: ControlIo, B: PacketIo> Drop for Receiver<C, B> {
    fn drop(&mut self) {
        // No I/O and no lease release on drop. DMA pages/claims remain owned
        // by xHCI; a new software receiver cannot restart this radio.
        if self.firmware.status().stage != Stage::Failed {
            self.firmware.runtime_failed(ControlError::Cancelled);
        }
    }
}
