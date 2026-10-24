//! SoundWire bus layer (MIPI SDW): manager-side enumeration, peripheral
//! register access and stream transport setup.
//!
//! The bus logic is transport-abstract: a [`Transport`] is the manager's
//! command path (one command frame out, one classified response back) plus
//! bus reset and the programmed frame shape. The in-tree binding is the
//! AMD ACP 6.3 manager in [`crate::acp63_sdw`]. Intel SoundWire links are
//! owned by the platform DSP (SOF) in the tree's model and are *not*
//! bound here; see specification §8.
//!
//! The protocol model follows Linux's soundwire core:
//!
//! - Enumeration mirrors `sdw_program_device_num`
//!   (`drivers/soundwire/bus.c`): read the six DevID registers from the
//!   enumeration address 0, parse the 48-bit ID, assign the next free
//!   device number with a write to `SCP_DEVNUMBER` (still addressed to
//!   device 0), then repeat until a DevID read goes unanswered.
//! - Stream setup mirrors `stream.c`'s prepare/enable conversation
//!   reduced to a stopped bus: program the port's transport parameters
//!   (word length, sample interval), write `DPn_PREPARE`, poll the
//!   register until its NotFinished bits clear, then set
//!   `DPn_CHANNELEN`. Disable clears `CHANNELEN`; deprepare clears
//!   `PREPARE`. Glitchless bank switching while a stream runs is a
//!   manager-frame concern and is out of scope: streams here are
//!   configured while stopped, like the HDA/ACP paths in this crate.
//!
//! Register addresses are the MIPI-standard SCP/DPn map, as in Linux
//! `include/linux/soundwire/sdw_registers.h`.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use narf_drivers_sound::{
    format::{ChannelCount, HwParams, SampleFormat, SampleRate},
    hardware::{PcmCapabilities, PcmDevice, PcmHardware},
    SoundError,
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

/// MIPI-standard SoundWire register map (peripheral side).
pub mod regs {
    /// SCP interrupt status/mask block.
    pub const SCP_INT1: u32 = 0x0000;
    /// SCP interrupt status 1 (read-to-clear source status).
    pub const SCP_INTSTAT1: u32 = 0x0001;
    /// SCP control (clock-stop request lives here).
    pub const SCP_CONTROL: u32 = 0x0007;
    /// SCP port state for the control port: low 3 bits mirror the PING
    /// encoding (0 = unattached, 1 = attached, 2 = alert).
    pub const SCP_PORTSTATE: u32 = 0x0040;
    /// SCP device number: the manager writes the assigned number here
    /// while the peripheral still listens on the enumeration address.
    pub const SCP_DEVNUMBER: u32 = 0x0046;
    /// Mask of the device-number field in `SCP_DEVNUMBER`.
    pub const SCP_DEVNUMBER_MASK: u8 = 0xF;
    /// First of the six DevID registers (`SCP_DEVID_0..=SCP_DEVID_5`).
    pub const SCP_DEVID_0: u32 = 0x0050;

    /// Base of data port `port`'s register block (DP0 included: its block
    /// carries the bulk-register-access registers). Blocks are 0x100
    /// apart, DP0 at 0x0100, DPn at `0x0100 + 0x100 * n`.
    pub const fn dpn_base(port: u8) -> u32 {
        0x0100 + 0x100 * (port as u32)
    }
    /// Within-block offset of DPn interrupt status.
    pub const DPN_INT: u32 = 0x00;
    /// Within-block offset of DPn port control.
    pub const DPN_PORTCTRL: u32 = 0x02;
    /// Within-block offset of DPn block control 1: bits [5:0] hold the
    /// word length minus one, bits [7:6] the block group count.
    pub const DPN_BLOCKCTRL1: u32 = 0x03;
    /// Within-block offset of DPn prepare control/status: writing a
    /// channel mask starts channel prepare; reading it back returns the
    /// NotFinished mask (a bit reads 1 while that channel is still
    /// preparing, 0 once it is ready).
    pub const DPN_PREPARE: u32 = 0x04;
    /// Within-block offset of DPn sample control 1 (interval bits [7:0]).
    pub const DPN_SAMPLECTRL1: u32 = 0x10;
    /// Within-block offset of DPn sample control 2 (interval bits [15:8]).
    pub const DPN_SAMPLECTRL2: u32 = 0x11;
    /// Within-block offset of DPn channel enable: one bit per channel;
    /// nonzero enables the port's payload channel(s) on the wire.
    pub const DPN_CHANNELEN: u32 = 0x20;
}

/// Device number every unenumerated peripheral listens on.
pub const ENUM_DEV_NUM: u8 = 0;
/// Device number for broadcast writes (all peripherals).
pub const BROADCAST_DEV_NUM: u8 = 15;
/// Highest assignable peripheral device number (SDW addresses 1..=11).
pub const MAX_DEV_NUM: u8 = 11;
/// Number of DevID registers read during enumeration.
pub const NUM_DEV_ID_REGISTERS: u32 = 6;
/// Channel-prepare poll budget. The MIPI DisCo recommendation is that
/// prepare completes in milliseconds; 100 ms matches the bounded waits
/// used by the other native audio paths in this crate.
pub const PREP_TIMEOUT_MS: u64 = 100;

/// Failure modes of a bus operation. Every variant fails closed: no
/// variant is ever treated as success by callers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SdwError {
    /// The manager never completed the command within its poll budget.
    Timeout,
    /// The command was ignored or NAKed: no peripheral acknowledged it.
    /// During enumeration this is the normal end-of-bus signal.
    NoResponse,
    /// Transport-level failure (manager register handshake failed).
    Transport,
    /// Device number outside 0..=15 (or 1..=11 where an assigned
    /// peripheral is required).
    InvalidDevice,
    /// Register address the transport cannot encode.
    InvalidAddress,
    /// Data port number outside 1..=14.
    InvalidPort,
    /// Stream parameters the generic codec conversation cannot express.
    InvalidParams,
}

/// The 48-bit peripheral identity from the DevID registers.
///
/// Layout (MIPI DisCo for SoundWire; Linux `sdw_extract_slave_id`):
/// DevId_0 [7:4] = sdw_version, DevId_0 [3:0] = unique_id,
/// DevId_1/2 = mfg_id, DevId_3/4 = part_id, DevId_5 = class_id, with
/// DevId_0 the most significant byte of the 48-bit value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SlaveId {
    /// MIPI manufacturer ID.
    pub mfg_id: u16,
    /// Vendor part ID.
    pub part_id: u16,
    /// MIPI class ID (SoundWire 1.2+; 0 on 1.1 peripherals).
    pub class_id: u8,
    /// Strap-selected unique ID distinguishing identical parts.
    pub unique_id: u8,
    /// SoundWire version implemented by the peripheral.
    pub sdw_version: u8,
}

impl SlaveId {
    /// Parse the six DevID register bytes in read order (DevId_0 first).
    pub fn from_devid_bytes(bytes: [u8; 6]) -> Self {
        let addr = ((bytes[0] as u64) << 40)
            | ((bytes[1] as u64) << 32)
            | ((bytes[2] as u64) << 24)
            | ((bytes[3] as u64) << 16)
            | ((bytes[4] as u64) << 8)
            | (bytes[5] as u64);
        Self {
            mfg_id: ((addr >> 24) & 0xFFFF) as u16,
            part_id: ((addr >> 8) & 0xFFFF) as u16,
            class_id: (addr & 0xFF) as u8,
            unique_id: ((addr >> 40) & 0xF) as u8,
            sdw_version: ((addr >> 44) & 0xF) as u8,
        }
    }
}

/// One enumerated peripheral: its assigned device number and identity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Peripheral {
    /// Assigned device number, 1..=11.
    pub dev_num: u8,
    /// Identity read at enumeration time.
    pub id: SlaveId,
}

/// The manager-side command path a bus binding provides.
///
/// One `xfer` is one SoundWire command frame: a byte read or write to a
/// peripheral register, with the response classified the way the SDW
/// spec defines it (ACK / ignored-or-NAK / no completion). Address
/// width is `u32` so paged and SDCA addresses fit; a transport that can
/// only encode part of the space rejects the rest with
/// [`SdwError::InvalidAddress`] rather than truncating.
pub trait Transport: Send + Sync + core::fmt::Debug {
    /// Read one register byte from `dev`. Ok(Some(byte)) on ACK.
    /// Write one register byte when `write` is Some; Ok(None) on ACK.
    /// [`SdwError::NoResponse`] when no peripheral ACKs.
    fn xfer(&self, dev: u8, addr: u32, write: Option<u8>) -> Result<Option<u8>, SdwError>;
    /// Reset the bus: every peripheral drops its assigned number and
    /// returns to the enumeration address.
    fn bus_reset(&self) -> Result<(), SdwError>;
    /// Frame shape (rows, columns) the manager is programmed with.
    fn frame_shape(&self) -> (u32, u32);
}

/// Transport parameters for one audio data port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Bits per payload sample (word length programmed into
    /// `DPn_BLOCKCTRL1` as `word_length - 1`).
    pub word_length: u8,
    /// Payload slot interval between consecutive samples of one channel,
    /// in bus bit-slots (programmed into `DPn_SAMPLECTRL1/2`). The
    /// binding derives it from its manager clock and frame shape; e.g.
    /// a 4.8 Mbit/s bus carrying 48 kHz audio uses 100.
    pub sample_interval: u16,
}

/// A SoundWire bus behind one manager transport.
#[derive(Debug)]
pub struct Bus<T: Transport> {
    transport: T,
    peripherals: Vec<Peripheral>,
}

impl<T: Transport> Bus<T> {
    /// Wrap a transport whose manager is already initialised (enabled,
    /// bus reset, frame shape programmed).
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            peripherals: Vec::new(),
        }
    }

    /// The underlying transport (bindings use it for manager-specific
    /// sequencing such as re-running enumeration after a bus reset).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Peripherals found by the last successful [`Bus::enumerate`].
    pub fn peripherals(&self) -> &[Peripheral] {
        &self.peripherals
    }

    /// Read one register byte from an assigned peripheral.
    pub fn read_reg(&self, dev: u8, addr: u32) -> Result<u8, SdwError> {
        if !(1..=MAX_DEV_NUM).contains(&dev) {
            return Err(SdwError::InvalidDevice);
        }
        self.transport
            .xfer(dev, addr, None)?
            .ok_or(SdwError::Transport)
    }

    /// Write one register byte to an assigned peripheral, or broadcast
    /// the write to every peripheral with [`BROADCAST_DEV_NUM`].
    pub fn write_reg(&self, dev: u8, addr: u32, value: u8) -> Result<(), SdwError> {
        if !(1..=MAX_DEV_NUM).contains(&dev) && dev != BROADCAST_DEV_NUM {
            return Err(SdwError::InvalidDevice);
        }
        match self.transport.xfer(dev, addr, Some(value))? {
            None => Ok(()),
            Some(_) => Err(SdwError::Transport),
        }
    }

    /// Enumerate the bus per the MIPI model: repeatedly read the DevID
    /// block from the enumeration address and assign device numbers
    /// until no peripheral answers. The bus must be freshly reset (all
    /// peripherals unassigned) when this runs.
    ///
    /// Succeeds with an empty list on a bus with no peripherals; the
    /// caller decides whether that is fatal (the ACP binding publishes
    /// nothing in that case). Any other transport failure aborts
    /// enumeration and is propagated: a half-enumerated bus is never
    /// reported as a clean result.
    pub fn enumerate(&mut self) -> Result<&[Peripheral], SdwError> {
        self.peripherals.clear();
        for next in 1..=MAX_DEV_NUM {
            let mut bytes = [0u8; 6];
            for (i, byte) in bytes.iter_mut().enumerate() {
                let addr = regs::SCP_DEVID_0 + (i as u32);
                match self.transport.xfer(ENUM_DEV_NUM, addr, None) {
                    Ok(Some(value)) => *byte = value,
                    // No peripheral left at the enumeration address:
                    // enumeration is complete.
                    Err(SdwError::NoResponse) if i == 0 => return Ok(&self.peripherals),
                    // A peripheral that answers part of its DevID and
                    // then vanishes is a broken bus, not an empty one.
                    Err(error) => return Err(error),
                    Ok(None) => return Err(SdwError::Transport),
                }
            }
            let id = SlaveId::from_devid_bytes(bytes);
            // Program the number while the peripheral still listens on
            // the enumeration address, then confirm it answers there.
            self.transport
                .xfer(ENUM_DEV_NUM, regs::SCP_DEVNUMBER, Some(next))?;
            let assigned = self.transport.xfer(next, regs::SCP_DEVNUMBER, None)?;
            if assigned != Some(next & regs::SCP_DEVNUMBER_MASK) {
                return Err(SdwError::Transport);
            }
            self.peripherals.push(Peripheral { dev_num: next, id });
        }
        Ok(&self.peripherals)
    }

    /// Program a data port's transport parameters and run channel
    /// prepare: word length and sample interval first, then the
    /// prepare mask, polling the NotFinished bits until they clear.
    /// A peripheral that never finishes preparing fails with
    /// [`SdwError::Timeout`]; the port is left unprepared-or-unknown
    /// and must be deprepared before reuse.
    pub fn port_prepare(
        &self,
        dev: u8,
        port: u8,
        ch_mask: u8,
        config: StreamConfig,
    ) -> Result<(), SdwError> {
        let base = port_base(port)?;
        if ch_mask == 0 || !(8..=32).contains(&config.word_length) {
            return Err(SdwError::InvalidParams);
        }
        self.write_reg(dev, base + regs::DPN_BLOCKCTRL1, config.word_length - 1)?;
        self.write_reg(
            dev,
            base + regs::DPN_SAMPLECTRL1,
            (config.sample_interval & 0xFF) as u8,
        )?;
        self.write_reg(
            dev,
            base + regs::DPN_SAMPLECTRL2,
            ((config.sample_interval >> 8) & 0xFF) as u8,
        )?;
        self.write_reg(dev, base + regs::DPN_PREPARE, ch_mask)?;
        let mut failure = None;
        let finished = narf_scheduler::responsive_spin_until(
            || match self.read_reg(dev, base + regs::DPN_PREPARE) {
                Ok(value) => value & ch_mask == 0,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            Deadline::after_ms(PREP_TIMEOUT_MS),
        );
        if let Some(error) = failure {
            return Err(error);
        }
        if !finished {
            return Err(SdwError::Timeout);
        }
        Ok(())
    }

    /// Enable a prepared port's channels: payload starts flowing on
    /// the wire. (Moving host memory to and from the wire is the
    /// platform DMA engine's job; this is the bus-side enable.)
    pub fn port_enable(&self, dev: u8, port: u8, ch_mask: u8) -> Result<(), SdwError> {
        if ch_mask == 0 {
            return Err(SdwError::InvalidParams);
        }
        self.write_reg(dev, port_base(port)? + regs::DPN_CHANNELEN, ch_mask)
    }

    /// Disable a port's channels (payload stops at the next frame
    /// boundary on the wire).
    pub fn port_disable(&self, dev: u8, port: u8) -> Result<(), SdwError> {
        self.write_reg(dev, port_base(port)? + regs::DPN_CHANNELEN, 0)
    }

    /// De-prepare a port after disable, returning it to its reset
    /// transport state.
    pub fn port_deprepare(&self, dev: u8, port: u8) -> Result<(), SdwError> {
        self.write_reg(dev, port_base(port)? + regs::DPN_PREPARE, 0)
    }
}

fn port_base(port: u8) -> Result<u32, SdwError> {
    if !(1..=14).contains(&port) {
        return Err(SdwError::InvalidPort);
    }
    Ok(regs::dpn_base(port))
}

// ── Generic codec → sound card ──────────────────────────────────────

/// One audio data port of a generic SDW codec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortProfile {
    /// Data port number (1..=14).
    pub port: u8,
    /// Channels the generic conversation drives (stereo by default).
    pub max_channels: u8,
    /// Widest sample word the port accepts, in bits.
    pub max_word: u8,
}

/// The generic codec conversation's view of a peripheral: one sink
/// port (playback) and/or one source port (capture). Vendor codecs
/// with richer topologies layer their own profiles on the same bus;
/// the generic profile is what an otherwise-unknown SDW codec is
/// driven with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CodecProfile {
    /// Playback (sink) port, if the codec can render.
    pub sink: Option<PortProfile>,
    /// Capture (source) port, if the codec can record.
    pub source: Option<PortProfile>,
}

/// The near-universal SDW codec arrangement: DP1 is the primary audio
/// port in both directions (e.g. the Realtek SDW codec family).
pub const GENERIC_CODEC_PROFILE: CodecProfile = CodecProfile {
    sink: Some(PortProfile {
        port: 1,
        max_channels: 2,
        max_word: 32,
    }),
    source: Some(PortProfile {
        port: 1,
        max_channels: 2,
        max_word: 32,
    }),
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Direction {
    Playback,
    Capture,
}

/// A sound card backed by one enumerated SDW peripheral, published
/// through `narf_drivers_sound` next to the HDA and ACP PDM cards.
///
/// The card implements the full PCM lifecycle against the bus
/// (configure → prepare → enable → disable → deprepare). Payload
/// *movement* between host memory and the wire is the platform SDW
/// DMA engine's job; on ACP 6.3 that engine is a separate block whose
/// register model is not in-tree yet, so `write`/`read` report
/// `BadState` until it lands (tracked as a follow-up to #780) instead
/// of pretending samples moved.
#[derive(Debug)]
pub struct CodecCard<T: Transport> {
    bus: Arc<IrqSafeSpinLock<Bus<T>>>,
    dev_num: u8,
    profile: CodecProfile,
    stream: StreamConfig,
    playback_claimed: Arc<IrqSafeSpinLock<bool>>,
    capture_claimed: Arc<IrqSafeSpinLock<bool>>,
}

impl<T: Transport> CodecCard<T> {
    /// Build a card for peripheral `dev_num` on a shared bus.
    pub fn new(
        bus: Arc<IrqSafeSpinLock<Bus<T>>>,
        dev_num: u8,
        profile: CodecProfile,
        stream: StreamConfig,
    ) -> Self {
        Self {
            bus,
            dev_num,
            profile,
            stream,
            playback_claimed: Arc::new(IrqSafeSpinLock::new(false)),
            capture_claimed: Arc::new(IrqSafeSpinLock::new(false)),
        }
    }

    fn port_for(&self, direction: Direction) -> Option<PortProfile> {
        match direction {
            Direction::Playback => self.profile.sink,
            Direction::Capture => self.profile.source,
        }
    }
}

fn sdw_to_sound(error: SdwError) -> SoundError {
    match error {
        SdwError::NoResponse => SoundError::NoSuchDevice,
        _ => SoundError::BadState,
    }
}

impl<T: Transport + 'static> PcmDevice for CodecCard<T> {
    fn default_params(&self, _: bool) -> HwParams {
        HwParams {
            format: SampleFormat::S16LE,
            rate: SampleRate::R48000,
            channels: ChannelCount::Stereo,
            period_size: 1024,
            periods: 4,
        }
    }
    fn capabilities(&self, capture: bool) -> PcmCapabilities {
        PcmCapabilities::fixed(self.default_params(capture))
    }
    fn open(&self, capture: bool, device: u32) -> Result<Box<dyn PcmHardware>, SoundError> {
        let direction = if capture {
            Direction::Capture
        } else {
            Direction::Playback
        };
        if device != 0 || self.port_for(direction).is_none() {
            return Err(SoundError::NoSuchDevice);
        }
        let claim = if capture {
            self.capture_claimed.clone()
        } else {
            self.playback_claimed.clone()
        };
        {
            let mut claimed = claim.lock();
            if *claimed {
                return Err(SoundError::DeviceBusy);
            }
            *claimed = true;
        }
        Ok(Box::new(SdwPcm {
            card: SdwCardRef {
                bus: self.bus.clone(),
                dev_num: self.dev_num,
                stream: self.stream,
            },
            claim,
            port: self.port_for(direction).unwrap().port,
            params: None,
            enabled: false,
        }))
    }
}

/// The slice of a [`CodecCard`] a stream lease needs.
#[derive(Debug)]
struct SdwCardRef<T: Transport> {
    bus: Arc<IrqSafeSpinLock<Bus<T>>>,
    dev_num: u8,
    stream: StreamConfig,
}

#[derive(Debug)]
struct SdwPcm<T: Transport> {
    card: SdwCardRef<T>,
    claim: Arc<IrqSafeSpinLock<bool>>,
    port: u8,
    params: Option<HwParams>,
    enabled: bool,
}

impl<T: Transport> SdwPcm<T> {
    fn ch_mask(&self) -> u8 {
        // The generic profile drives stereo ports (mask 0b11); the
        // configured channel count is validated against the profile
        // in `configure`, and only stereo is accepted there.
        0b11
    }
    fn bus_op(&self, op: impl FnOnce(&Bus<T>) -> Result<(), SdwError>) -> Result<(), SoundError> {
        let bus = self.card.bus.lock();
        op(&bus).map_err(sdw_to_sound)
    }
}

impl<T: Transport> PcmHardware for SdwPcm<T> {
    fn configure(&mut self, params: HwParams) -> Result<(), SoundError> {
        if params.format != SampleFormat::S16LE
            || params.rate != SampleRate::R48000
            || params.channels != ChannelCount::Stereo
            || params.periods != 4
            || !(512..=1024).contains(&params.period_size)
        {
            return Err(SoundError::InvalidParams);
        }
        if self.enabled {
            return Err(SoundError::BadState);
        }
        self.params = Some(params);
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        if self.params.is_none() {
            return Err(SoundError::BadState);
        }
        if self.enabled {
            self.bus_op(|bus| bus.port_disable(self.card.dev_num, self.port))?;
            self.enabled = false;
        }
        let config = self.card.stream;
        let mask = self.ch_mask();
        self.bus_op(|bus| bus.port_prepare(self.card.dev_num, self.port, mask, config))
    }
    fn start(&mut self) -> Result<(), SoundError> {
        if self.params.is_none() {
            return Err(SoundError::BadState);
        }
        let mask = self.ch_mask();
        self.bus_op(|bus| bus.port_enable(self.card.dev_num, self.port, mask))?;
        self.enabled = true;
        Ok(())
    }
    fn stop(&mut self) -> Result<(), SoundError> {
        if self.enabled {
            self.bus_op(|bus| bus.port_disable(self.card.dev_num, self.port))?;
            self.enabled = false;
        }
        Ok(())
    }
    fn pointer(&self) -> u64 {
        0
    }
    fn write(&mut self, _: &[u8]) -> Result<usize, SoundError> {
        // Payload movement is the platform SDW DMA engine's job; see
        // the CodecCard doc. Failing here keeps a stream that cannot
        // actually carry samples from reporting progress.
        Err(SoundError::BadState)
    }
    fn read(&mut self, _: &mut [u8]) -> Result<usize, SoundError> {
        Err(SoundError::BadState)
    }
    fn drain(&mut self) -> Result<(), SoundError> {
        self.stop()
    }
}

impl<T: Transport> Drop for SdwPcm<T> {
    fn drop(&mut self) {
        {
            let bus = self.card.bus.lock();
            if self.enabled {
                let _ = bus.port_disable(self.card.dev_num, self.port);
            }
            let _ = bus.port_deprepare(self.card.dev_num, self.port);
        }
        *self.claim.lock() = false;
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// One transfer on the model bus, recorded for framing assertions.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct Xfer {
        dev: u8,
        addr: u32,
        write: Option<u8>,
    }

    #[derive(Debug)]
    struct ModelPeripheral {
        id: [u8; 6],
        regs: BTreeMap<u32, u8>,
        stuck_prepare: bool,
    }

    impl ModelPeripheral {
        fn new(id: [u8; 6]) -> Self {
            let mut regs = BTreeMap::new();
            for (i, byte) in id.iter().enumerate() {
                regs.insert(regs::SCP_DEVID_0 + i as u32, *byte);
            }
            regs.insert(regs::SCP_PORTSTATE, 1);
            Self {
                id,
                regs,
                stuck_prepare: false,
            }
        }
    }

    /// A modelled manager: peripherals wait at the enumeration address
    /// in queue order; a DEVNUMBER write to device 0 assigns the front
    /// peripheral. Prepare completes instantly unless `stuck_prepare`.
    #[derive(Debug)]
    struct ModelTransport {
        pending: IrqSafeSpinLock<Vec<ModelPeripheral>>,
        assigned: IrqSafeSpinLock<BTreeMap<u8, ModelPeripheral>>,
        log: IrqSafeSpinLock<Vec<Xfer>>,
        fail_devid_byte: IrqSafeSpinLock<Option<usize>>,
    }

    impl ModelTransport {
        fn new(ids: &[[u8; 6]]) -> Self {
            Self {
                pending: IrqSafeSpinLock::new(
                    ids.iter().map(|id| ModelPeripheral::new(*id)).collect(),
                ),
                assigned: IrqSafeSpinLock::new(BTreeMap::new()),
                log: IrqSafeSpinLock::new(Vec::new()),
                fail_devid_byte: IrqSafeSpinLock::new(None),
            }
        }
        fn log(&self) -> Vec<Xfer> {
            self.log.lock().clone()
        }
    }

    impl Transport for ModelTransport {
        fn xfer(&self, dev: u8, addr: u32, write: Option<u8>) -> Result<Option<u8>, SdwError> {
            self.log.lock().push(Xfer { dev, addr, write });
            if dev == ENUM_DEV_NUM {
                if let Some(value) = write {
                    if addr == regs::SCP_DEVNUMBER {
                        let mut pending = self.pending.lock();
                        if pending.is_empty() {
                            return Err(SdwError::NoResponse);
                        }
                        let mut peripheral = pending.remove(0);
                        peripheral.regs.insert(regs::SCP_DEVNUMBER, value);
                        self.assigned.lock().insert(value, peripheral);
                        return Ok(None);
                    }
                    return Err(SdwError::NoResponse);
                }
                // A read at the enumeration address is served by the
                // next unassigned peripheral, if any.
                if let Some(fail) = *self.fail_devid_byte.lock() {
                    if addr == regs::SCP_DEVID_0 + fail as u32 {
                        return Err(SdwError::NoResponse);
                    }
                }
                let pending = self.pending.lock();
                let Some(peripheral) = pending.first() else {
                    return Err(SdwError::NoResponse);
                };
                if (regs::SCP_DEVID_0..regs::SCP_DEVID_0 + NUM_DEV_ID_REGISTERS).contains(&addr) {
                    return Ok(Some(peripheral.id[(addr - regs::SCP_DEVID_0) as usize]));
                }
                return Ok(Some(peripheral.regs.get(&addr).copied().unwrap_or(0)));
            }
            if dev == BROADCAST_DEV_NUM {
                // Broadcast writes land on every assigned peripheral;
                // with none assigned the command goes unanswered.
                let Some(value) = write else {
                    return Err(SdwError::NoResponse);
                };
                let mut assigned = self.assigned.lock();
                if assigned.is_empty() {
                    return Err(SdwError::NoResponse);
                }
                for peripheral in assigned.values_mut() {
                    peripheral.regs.insert(addr, value);
                }
                return Ok(None);
            }
            let mut assigned = self.assigned.lock();
            let Some(peripheral) = assigned.get_mut(&dev) else {
                return Err(SdwError::NoResponse);
            };
            if let Some(value) = write {
                peripheral.regs.insert(addr, value);
                return Ok(None);
            }
            // Prepare reads report NotFinished only for a stuck port.
            let is_prepare =
                (0..=14u8).any(|port| addr == regs::dpn_base(port) + regs::DPN_PREPARE);
            if is_prepare && !peripheral.stuck_prepare {
                return Ok(Some(0));
            }
            Ok(Some(peripheral.regs.get(&addr).copied().unwrap_or(0)))
        }
        fn bus_reset(&self) -> Result<(), SdwError> {
            let mut assigned = self.assigned.lock();
            let mut pending = self.pending.lock();
            for (_, peripheral) in assigned.iter() {
                pending.push(ModelPeripheral::new(peripheral.id));
            }
            assigned.clear();
            Ok(())
        }
        fn frame_shape(&self) -> (u32, u32) {
            (50, 10)
        }
    }

    // Realtek-flavoured identities: rt711 (headset codec) and rt1316
    // (speaker amp), encoded per the DisCo layout.
    const RT711: [u8; 6] = [0x10, 0x02, 0x5D, 0x07, 0x11, 0x00];
    const RT1316: [u8; 6] = [0x11, 0x02, 0x5D, 0x13, 0x16, 0x00];

    fn enumeration_assigns_numbers_and_reads_ids() -> TestResult {
        let mut bus = Bus::new(ModelTransport::new(&[RT711, RT1316]));
        let found = match bus.enumerate() {
            Ok(found) => found,
            Err(_) => return TestResult::Fail("enumeration failed"),
        };
        if found.len() != 2 || found[0].dev_num != 1 || found[1].dev_num != 2 {
            return TestResult::Fail("device numbers not assigned in order");
        }
        let first = found[0].id;
        if first.mfg_id != 0x025D
            || first.part_id != 0x0711
            || first.sdw_version != 1
            || first.unique_id != 0
            || first.class_id != 0
        {
            return TestResult::Fail("rt711 DevID misparsed");
        }
        let second = found[1].id;
        if second.mfg_id != 0x025D || second.part_id != 0x1316 || second.unique_id != 1 {
            return TestResult::Fail("rt1316 DevID misparsed");
        }
        // The conversation itself: six DevID reads at device 0, the
        // DEVNUMBER write at device 0, a verify read at the new number,
        // then the same again for the second peripheral, and a final
        // unanswered DevID read that ends enumeration.
        let log = bus.transport().log();
        let mut expected: Vec<Xfer> = Vec::new();
        for (num, _) in [(1u8, RT711), (2u8, RT1316)] {
            for i in 0..NUM_DEV_ID_REGISTERS {
                expected.push(Xfer {
                    dev: 0,
                    addr: regs::SCP_DEVID_0 + i,
                    write: None,
                });
            }
            expected.push(Xfer {
                dev: 0,
                addr: regs::SCP_DEVNUMBER,
                write: Some(num),
            });
            expected.push(Xfer {
                dev: num,
                addr: regs::SCP_DEVNUMBER,
                write: None,
            });
        }
        expected.push(Xfer {
            dev: 0,
            addr: regs::SCP_DEVID_0,
            write: None,
        });
        if log != expected {
            return TestResult::Fail("enumeration conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire", enumeration_assigns_numbers_and_reads_ids);

    fn register_read_write_framing() -> TestResult {
        let mut bus = Bus::new(ModelTransport::new(&[RT711]));
        if bus.enumerate().map(|found| found.len()) != Ok(1) {
            return TestResult::Fail("enumeration failed");
        }
        let block1 = regs::dpn_base(1) + regs::DPN_BLOCKCTRL1;
        if bus.write_reg(1, block1, 0x0F) != Ok(()) {
            return TestResult::Fail("register write failed");
        }
        if bus.read_reg(1, block1) != Ok(0x0F) {
            return TestResult::Fail("register read-back mismatch");
        }
        let log = bus.transport().log();
        let tail = &log[log.len() - 2..];
        if tail[0]
            != (Xfer {
                dev: 1,
                addr: block1,
                write: Some(0x0F),
            })
            || tail[1]
                != (Xfer {
                    dev: 1,
                    addr: block1,
                    write: None,
                })
        {
            return TestResult::Fail("register framing mismatch");
        }
        // Broadcast writes are legal; broadcast reads are not a thing,
        // and unassigned device numbers are rejected before transport.
        if bus.write_reg(BROADCAST_DEV_NUM, regs::SCP_CONTROL, 0) != Ok(()) {
            return TestResult::Fail("broadcast write rejected");
        }
        if bus.read_reg(9, regs::SCP_PORTSTATE) != Err(SdwError::NoResponse) {
            return TestResult::Fail("absent peripheral read must fail");
        }
        if bus.read_reg(0, regs::SCP_PORTSTATE) != Err(SdwError::InvalidDevice) {
            return TestResult::Fail("enumeration-address read must be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire", register_read_write_framing);

    fn stream_prepare_enable_disable_sequence() -> TestResult {
        let mut bus = Bus::new(ModelTransport::new(&[RT711]));
        if bus.enumerate().map(|found| found.len()) != Ok(1) {
            return TestResult::Fail("enumeration failed");
        }
        let config = StreamConfig {
            word_length: 16,
            sample_interval: 100,
        };
        let base = regs::dpn_base(1);
        let before = bus.transport().log().len();
        if bus.port_prepare(1, 1, 0b11, config) != Ok(()) {
            return TestResult::Fail("port prepare failed");
        }
        if bus.port_enable(1, 1, 0b11) != Ok(()) {
            return TestResult::Fail("port enable failed");
        }
        if bus.port_disable(1, 1) != Ok(()) {
            return TestResult::Fail("port disable failed");
        }
        if bus.port_deprepare(1, 1) != Ok(()) {
            return TestResult::Fail("port deprepare failed");
        }
        let log = bus.transport().log();
        let expected = [
            Xfer {
                dev: 1,
                addr: base + regs::DPN_BLOCKCTRL1,
                write: Some(15),
            },
            Xfer {
                dev: 1,
                addr: base + regs::DPN_SAMPLECTRL1,
                write: Some(100),
            },
            Xfer {
                dev: 1,
                addr: base + regs::DPN_SAMPLECTRL2,
                write: Some(0),
            },
            Xfer {
                dev: 1,
                addr: base + regs::DPN_PREPARE,
                write: Some(0b11),
            },
            Xfer {
                dev: 1,
                addr: base + regs::DPN_PREPARE,
                write: None,
            },
            Xfer {
                dev: 1,
                addr: base + regs::DPN_CHANNELEN,
                write: Some(0b11),
            },
            Xfer {
                dev: 1,
                addr: base + regs::DPN_CHANNELEN,
                write: Some(0),
            },
            Xfer {
                dev: 1,
                addr: base + regs::DPN_PREPARE,
                write: Some(0),
            },
        ];
        if log[before..] != expected {
            return TestResult::Fail("stream conversation mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire", stream_prepare_enable_disable_sequence);

    fn absent_and_stuck_peripherals_fail_closed() -> TestResult {
        // Empty bus: enumeration completes with no peripherals.
        let mut empty = Bus::new(ModelTransport::new(&[]));
        match empty.enumerate() {
            Ok(found) if found.is_empty() => {}
            _ => return TestResult::Fail("empty bus must enumerate clean"),
        }
        // A peripheral that stops answering mid-DevID aborts
        // enumeration rather than producing a phantom identity.
        let transport = ModelTransport::new(&[RT711]);
        *transport.fail_devid_byte.lock() = Some(3);
        let mut broken = Bus::new(transport);
        if broken.enumerate() != Err(SdwError::NoResponse) {
            return TestResult::Fail("mid-DevID failure must abort enumeration");
        }
        // A port whose prepare never finishes times out.
        let transport = ModelTransport::new(&[RT711]);
        transport.pending.lock().first_mut().unwrap().stuck_prepare = true;
        let mut bus = Bus::new(transport);
        if bus.enumerate().map(|found| found.len()) != Ok(1) {
            return TestResult::Fail("enumeration failed");
        }
        let config = StreamConfig {
            word_length: 16,
            sample_interval: 100,
        };
        if bus.port_prepare(1, 1, 0b11, config) != Err(SdwError::Timeout) {
            return TestResult::Fail("stuck prepare must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/soundwire", absent_and_stuck_peripherals_fail_closed);
}
