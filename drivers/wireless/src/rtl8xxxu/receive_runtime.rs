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
        })
    }
    pub fn phase(&self) -> Phase {
        if self.firmware.status().stage == Stage::Failed {
            Phase::Failed
        } else {
            self.phase
        }
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
