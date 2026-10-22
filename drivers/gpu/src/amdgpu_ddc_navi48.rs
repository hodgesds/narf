//! Native DCN4 HDMI DDC, using Linux dce_i2c_hw.c and DCN4.1 register headers.
//! Owns the shared I2C buffer/arbitrator; no clock, encoder or timing programming.
use crate::{amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_psp_ring::bank};
use alloc::vec::Vec;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Readback,
    Timeout,
    Protocol,
    Nack,
    InvalidEdid,
    EdidTooLarge,
    InvalidMccs,
    MccsUnsupported,
}
impl Error {
    pub(crate) fn local(self) -> bool {
        matches!(
            self,
            Self::Nack
                | Self::InvalidEdid
                | Self::EdidTooLarge
                | Self::InvalidMccs
                | Self::MccsUnsupported
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Acquiring,
    Reading,
    Releasing,
    Failed(Error),
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    clock: u64,
    dio: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none() {
            return Err(Error::Unsupported);
        }
        bank(gpu, ip::HW_ID_GC, crate::amdgpu_rdna4::GC_VERSIONS, 0, 0)
            .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            clock: bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 1, 0x7b)
                .map_err(|_| Error::Unsupported)?,
            dio: bank(gpu, ip::HW_ID_DCN, &[(4, 0, 1), (4, 1, 0)], 2, 0x291d)
                .map_err(|_| Error::Unsupported)?,
        })
    }
    fn at(self, index: u64) -> u64 {
        self.dio + index * 4
    }
}
trait Io: Send {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn delay(&mut self, us: u64) -> impl core::future::Future<Output = ()> + Send {
        async move {
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
        }
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: bounded discovery banks, exclusive DDC owner, live invocation.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same bounds, ownership and current capability authority.
        unsafe { self.0.write32(address, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn read(io: &mut impl Io, at: u64) -> Result<u32, Error> {
    match io.read(at) {
        u32::MAX => Err(Error::DeviceGone),
        value => Ok(value),
    }
}
fn update(io: &mut impl Io, at: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, at)?;
    io.write(at, (old & !mask) | (value & mask));
    if read(io, at)? & mask != value & mask {
        return Err(Error::Readback);
    }
    Ok(())
}
// Arbitration request/done and CONTROL GO/status-reset are commands and may
// self-clear. Never require them to echo their written value.
fn command(io: &mut impl Io, at: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, at)?;
    io.write(at, (old & !mask) | (value & mask));
    read(io, at)?;
    Ok(())
}
fn prescale(div: u32, crystal_khz: u32) -> Result<u32, Error> {
    let base = div & 0x7f;
    let xtal = (div >> 8) & 0x7f;
    let clock = if base == 0 { crystal_khz } else { base * 1000 };
    let value = clock / if xtal == 0 { 2 } else { xtal } / 100;
    if !(1..=0xffff).contains(&value) {
        return Err(Error::Invalid);
    }
    Ok((value << 16) | 0x202)
}
/// E-DDC EDID and HDMI SCDC 7-bit addresses.
const EDID: u8 = 0x50;
pub const SCDC: u8 = 0x54;
#[derive(Clone, Copy, Debug)]
enum Op2 {
    Segment(u8),
    Read(u8),
    Write(u8, u8),
    RawRead(u8),
    RawWrite(u8),
}
#[derive(Clone, Copy, Debug)]
struct Saved {
    index: u64,
    mask: u32,
    value: u32,
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    crystal_khz: u32,
    saved: Option<[Saved; 7]>,
    state: State,
}
impl<I: Io + Send> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    async fn wait(&mut self, index: u64, mask: u32, value: u32) -> Result<(), Error> {
        let at = self.layout.at(index);
        let deadline = narf_time::Deadline::after_ms(50);
        loop {
            if self.access(|io| read(io, at))? & mask == value {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.io.delay(100).await;
        }
    }
    async fn acquire(&mut self, channel: u8) -> Result<(), Error> {
        let l = self.layout;
        let n = u64::from(channel);
        let crystal = self.crystal_khz;
        let (saved, speed) = self.access(|io| {
            // A new owner must not adopt an inherited SW claim, a DMCU claim,
            // an autonomous EDID poll or an in-progress transaction on any port.
            if read(io, l.at(0x1e99))? & 0x0130110c != 0
                || read(io, l.at(0x1e9b))? & 3 != 0
                || read(io, l.at(0x1e98))? & 7 != 0
            {
                return Err(Error::Busy);
            }
            for port in 0..4 {
                if read(io, l.at(0x1e9c + port))? & 0x30003 != 0
                    || read(io, l.at(0x1ea3 + port * 2))? & 0x10 != 0
                {
                    return Err(Error::Busy);
                }
            }
            let speed = prescale(read(io, l.clock + 0x7b * 4)?, crystal)?;
            let mut saved = [Saved {
                index: 0,
                mask: 0,
                value: 0,
            }; 7];
            for (slot, (index, mask)) in saved.iter_mut().zip([
                (0x1e98, 0x00300700),
                (0x1e99, 0x10),
                (0x1ea3 + n * 2, 0xffffffc7),
                (0x1ea2 + n * 2, 0xffff0303),
                (0x28d0 + n * 4, 0x00011111),
                (0x28ff, 3 << (10 + channel * 2)),
                (0x291d, 1 << (12 + channel)),
            ]) {
                *slot = Saved {
                    index,
                    mask,
                    value: read(io, l.at(index))?,
                };
            }
            Ok((saved, speed))
        })?;
        // Save before the first write. Cancellation/error retains ownership;
        // there is no Drop-time MMIO with potentially revoked authority.
        self.saved = Some(saved);
        self.access(|io| {
            update(io, l.at(0x1ede), 1, 0)?;
            update(io, l.at(0x1ea3 + n * 2), 8, 8)
        })?;
        self.wait(0x1edd, 1, 0).await?;
        self.access(|io| command(io, l.at(0x1e99), 0x00300000, 0x00100000))?;
        self.wait(0x1e99, 12, 4).await?;
        self.access(|io| {
            update(io, l.at(0x28d0 + n * 4), 0x1111, 0x1010)?;
            update(io, l.at(0x1ea2 + n * 2), 0xffff0303, speed)
        })?;
        // Allow inherited GPIO/AUX drive to discharge before switching pads.
        self.io.delay(2000).await;
        self.access(|io| {
            update(io, l.at(0x28d0 + n * 4), 0x10000, 0)?;
            update(io, l.at(0x291d), 1 << (12 + channel), 1 << (12 + channel))?;
            update(
                io,
                l.at(0x28ff),
                3 << (10 + channel * 2),
                1 << (10 + channel * 2),
            )?;
            update(io, l.at(0x1ea3 + n * 2), 0xffffffc7, 0x03000044)?;
            update(io, l.at(0x1e99), 0x10, 0)?;
            command(io, l.at(0x1e98), 0x0030070f, u32::from(channel) << 8 | 8)
        })?;
        self.state = State::Reading;
        Ok(())
    }
    /// One DDC operation on the claimed channel. `Segment` writes the E-DDC
    /// segment pointer; `Read` writes `block[0]` as the offset to 7-bit
    /// `address` then reads `block.len()` bytes into `block` (repeated START);
    /// `Write` sends the offset and one data byte in a single transaction.
    async fn transfer(&mut self, channel: u8, op: Op2, block: &mut [u8]) -> Result<(), Error> {
        let l = self.layout;
        self.access(|io| {
            if read(io, l.at(0x1e99))? & 12 != 4 || read(io, l.at(0x1e9b))? & 3 != 0 {
                return Err(Error::Protocol);
            }
            command(io, l.at(0x1e98), 15, 8)?;
            if read(io, l.at(0x1e9b))? & 0xf1f7 != 0 {
                return Err(Error::Protocol);
            }
            let count = match op {
                Op2::Segment(segment) => {
                    io.write(l.at(0x1eae), 0x00013100); // one byte, START+STOP
                    io.write(l.at(0x1eb2), 0x80006000); // segment address 0x30 write
                    io.write(l.at(0x1eb2), u32::from(segment) << 8);
                    0
                }
                Op2::Read(address) => {
                    let len = u32::try_from(block.len()).map_err(|_| Error::Invalid)?;
                    io.write(l.at(0x1eae), 0x00011100); // offset write, repeated START
                    io.write(l.at(0x1eaf), len << 16 | 0x3101); // read + STOP
                    io.write(l.at(0x1eb2), 0x80000000 | u32::from(address) << 9);
                    io.write(l.at(0x1eb2), u32::from(block[0]) << 8);
                    io.write(l.at(0x1eb2), (u32::from(address) << 1 | 1) << 8);
                    1
                }
                Op2::RawRead(address) | Op2::RawWrite(address) => {
                    let len = u32::try_from(block.len()).map_err(|_| Error::Invalid)?;
                    if len == 0 || len > 128 || address >= 128 {
                        return Err(Error::Invalid);
                    }
                    let reading = matches!(op, Op2::RawRead(_));
                    io.write(l.at(0x1eae), len << 16 | 0x3100 | u32::from(reading));
                    io.write(
                        l.at(0x1eb2),
                        0x80000000 | (u32::from(address) << 1 | u32::from(reading)) << 8,
                    );
                    if !reading {
                        for &byte in block.iter() {
                            io.write(l.at(0x1eb2), u32::from(byte) << 8);
                        }
                    }
                    0
                }
                Op2::Write(address, value) => {
                    io.write(l.at(0x1eae), 0x00023100); // offset + data, START+STOP
                    io.write(l.at(0x1eb2), 0x80000000 | u32::from(address) << 9);
                    io.write(l.at(0x1eb2), u32::from(block[0]) << 8);
                    io.write(l.at(0x1eb2), u32::from(value) << 8);
                    0
                }
            };
            command(
                io,
                l.at(0x1e98),
                0x0030070f,
                u32::from(channel) << 8 | count << 20,
            )?;
            command(io, l.at(0x1e98), 1, 1)
        })?;
        let deadline = narf_time::Deadline::after_ms(50);
        loop {
            let status = self.access(|io| {
                if read(io, l.at(0x1e99))? & 12 != 4 {
                    return Err(Error::Protocol);
                }
                read(io, l.at(0x1e9b))
            })?;
            if status & 3 == 0 {
                if status & 0xf0 != 0 {
                    return Err(Error::Protocol);
                }
                if status & 0xf100 != 0 {
                    return Err(Error::Nack);
                }
                if status & 4 != 0 {
                    break;
                }
            } else if status & 3 != 1 {
                return Err(Error::Protocol);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.io.delay(100).await;
        }
        if matches!(op, Op2::Read(_) | Op2::RawRead(_)) {
            self.access(|io| {
                // Offset reads have three preceding bytes; raw DDC/CI has
                // only the read address and no synthetic register offset.
                let index = if matches!(op, Op2::RawRead(_)) { 1 } else { 3 };
                io.write(l.at(0x1eb2), 0x80000001 | index << 16);
                for byte in block {
                    *byte = (read(io, l.at(0x1eb2))? >> 8) as u8;
                }
                Ok(())
            })?;
        }
        Ok(())
    }
    async fn release(&mut self) -> Result<(), Error> {
        self.state = State::Releasing;
        let l = self.layout;
        let saved = self.saved.ok_or(Error::Protocol)?;
        self.access(|io| {
            if read(io, l.at(0x1e9b))? & 3 != 0 || read(io, l.at(0x1e99))? & 12 != 4 {
                return Err(Error::Protocol);
            }
            command(io, l.at(0x1e98), 15, 8)?;
            for s in saved.iter().rev() {
                update(io, l.at(s.index), s.mask, s.value)?;
            }
            command(io, l.at(0x1e99), 0x00300000, 0x00200000)?;
            // Linux's DCN4 boot-without-HDMI workaround: a second DONE releases
            // a spuriously reacquired SW claim. No reset/abort of another owner.
            if read(io, l.at(0x1e99))? & 12 == 4 {
                command(io, l.at(0x1e99), 0x00300000, 0x00200000)?;
            }
            let arbitration = read(io, l.at(0x1e99))?;
            if arbitration & 4 != 0 || arbitration & 0x00100000 != 0 {
                return Err(Error::Protocol);
            }
            Ok(())
        })?;
        self.saved = None;
        Ok(())
    }
    /// One SCDC register read (`write` None) or write, in its own claim with
    /// the same release rule as EDID reads: only known-terminal bus results
    /// restore the pins and release arbitration.
    async fn scdc(&mut self, channel: u8, offset: u8, write: Option<u8>) -> Result<u8, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        if channel >= 4 {
            return Err(Error::Invalid);
        }
        self.state = State::Acquiring;
        let result: Result<u8, Error> = async {
            self.acquire(channel).await?;
            let mut byte = [offset];
            match write {
                Some(value) => {
                    self.transfer(channel, Op2::Write(SCDC, value), &mut byte)
                        .await?;
                    Ok(value)
                }
                None => {
                    self.transfer(channel, Op2::Read(SCDC), &mut byte).await?;
                    Ok(byte[0])
                }
            }
        }
        .await;
        let result = if !result.as_ref().is_err_and(|e| !e.local()) {
            self.release().await.and(result)
        } else {
            result
        };
        self.state = match &result {
            Ok(_) => State::Ready,
            Err(e) if e.local() => State::Ready,
            Err(e) => State::Failed(*e),
        };
        result
    }
    async fn mccs(
        &mut self,
        channel: u8,
        generation: u64,
        metadata: crate::amdgpu_freesync::AmdVsdb,
    ) -> Result<mccs::Negotiated, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        if channel >= 4 || generation == 0 {
            return Err(Error::Invalid);
        }
        self.state = State::Acquiring;
        let result = async {
            self.acquire(channel).await?;
            mccs::negotiate(
                &mut MccsBus {
                    engine: self,
                    channel,
                },
                generation,
                metadata,
            )
            .await
        }
        .await;
        let result = if !result.as_ref().is_err_and(|e| !e.local()) {
            self.release().await.and(result)
        } else {
            result
        };
        self.state = match result {
            Ok(_) => State::Ready,
            Err(e) if e.local() => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn edid(&mut self, channel: u8) -> Result<Vec<u8>, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        if channel >= 4 {
            return Err(Error::Invalid);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(32 * 128)
            .map_err(|_| Error::Allocation)?;
        self.state = State::Acquiring;
        let result = async {
            self.acquire(channel).await?;
            // Old EDID-only sinks can NACK segment zero; any nonzero segment
            // must be accepted or the advertised extension is unreadable.
            match self.transfer(channel, Op2::Segment(0), &mut []).await {
                Ok(()) | Err(Error::Nack) => {}
                Err(e) => return Err(e),
            }
            let mut blocks = 1;
            let mut index = 0;
            while index < blocks {
                if index >= 2 && index % 2 == 0 {
                    self.transfer(channel, Op2::Segment((index / 2) as u8), &mut [])
                        .await?;
                }
                let mut block = [0; 128];
                block[0] = ((index % 2) * 128) as u8;
                self.transfer(channel, Op2::Read(EDID), &mut block).await?;
                if index == 0 {
                    narf_edid::Block::parse(&block).map_err(|_| Error::InvalidEdid)?;
                    blocks = usize::from(block[126]) + 1;
                    if blocks > 32 {
                        return Err(Error::EdidTooLarge);
                    }
                } else if block.iter().fold(0u8, |s, b| s.wrapping_add(*b)) != 0 {
                    return Err(Error::InvalidEdid);
                }
                bytes.extend_from_slice(&block);
                index += 1;
            }
            Ok(bytes)
        }
        .await;
        // Only known-terminal bus results permit restoration and release.
        // Timeout, revocation and cancellation retain the claim and pin state.
        let result = if !result.as_ref().is_err_and(|e| !e.local()) {
            self.release().await.and(result)
        } else {
            result
        };
        self.state = match &result {
            Ok(_) => State::Ready,
            Err(e) if e.local() => State::Ready,
            Err(e) => State::Failed(*e),
        };
        result
    }
}
#[path = "amdgpu_ddc_mccs.rs"]
pub mod mccs;
struct MccsBus<'a, I: Io> {
    engine: &'a mut Engine<I>,
    channel: u8,
}
impl<I: Io + Send> mccs::Bus for MccsBus<'_, I> {
    async fn write(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.engine
            .transfer(self.channel, Op2::RawWrite(0x37), bytes)
            .await
    }
    async fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.engine
            .transfer(self.channel, Op2::RawRead(0x37), bytes)
            .await
    }
    async fn delay(&mut self, us: u64) {
        self.engine.io.delay(us).await;
    }
}
#[derive(Debug)]
pub struct Ddc(Engine<Mmio>);
impl Ddc {
    /// # Safety
    /// Own this physical GPU, permanent MMIO mapping, every DDC/AUX pin and
    /// shared I2C buffer, and all reset/PM transitions. Serialize with DMUB/AUX.
    /// Retain this owner until reset after failure or cancellation.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        crystal_khz: u32,
    ) -> Result<Self, Error> {
        prescale(0, crystal_khz)?;
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            layout: Layout::resolve(gpu)?,
            crystal_khz,
            saved: None,
            state: State::Ready,
        }))
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Complete validated E-EDID through a board-resolved DDC channel at 100kHz.
    /// Successful/local-error completion restores selected pin and speed fields.
    /// I2C SRAM and the selected channel clock remain awake for later accesses.
    pub async fn edid(&mut self, channel: u8) -> Result<Vec<u8>, Error> {
        self.0.edid(channel).await
    }
    /// Negotiate AMD's advertised vendor VCP through DDC/CI. The shared
    /// claim remains retained across waits and on uncertainty/cancellation;
    /// a successful proof belongs only to this fresh sink generation.
    pub async fn mccs(
        &mut self,
        channel: u8,
        generation: u64,
        metadata: crate::amdgpu_freesync::AmdVsdb,
    ) -> Result<mccs::Negotiated, Error> {
        self.0.mccs(channel, generation, metadata).await
    }
    /// Read one HDMI SCDC register (I2C 0x54) on a board-resolved channel.
    /// A sink without SCDC NACKs: a local error that leaves the owner Ready.
    pub async fn scdc_read(&mut self, channel: u8, offset: u8) -> Result<u8, Error> {
        self.0.scdc(channel, offset, None).await
    }
    /// Write one HDMI SCDC register (I2C 0x54).
    pub async fn scdc_write(&mut self, channel: u8, offset: u8, value: u8) -> Result<(), Error> {
        self.0.scdc(channel, offset, Some(value)).await.map(|_| ())
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_ddc_navi48_tests.rs"]
mod tests;
