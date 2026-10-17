//! Navi22 connector detection over the native DCN3.0 DDC owner.
//!
//! The board's connectors come from the VBIOS display-object table
//! (`amdgpu_dcn_inventory::display_paths`): each path names its transmitter,
//! its DDC line (decoded from the I2C record through the GPIO pin LUT) and its
//! one-based HPD selector. Nothing is defaulted from the connector's position.
//!
//! Detection follows Linux `link_detection.c::detect_link_and_local_sink`: HPD
//! first; then for DisplayPort the receiver capability field and an EDID over
//! I2C-over-AUX, for HDMI an EDID over the hardware I2C engine
//! (`link_query_ddc_data` / `drm_do_probe_ddc_edid`, E-DDC segment pointer at
//! 0x30 for blocks past the first two). Detection only reads the sink; it
//! never changes a stream, so it is safe while the GOP's scanout is live.
pub use crate::amdgpu_dcn30_ddc::{Message, Mode, Signal};
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn30_ddc::{self as ddc, Engine, Io},
    amdgpu_dcn_inventory::{Connector as Kind, Path},
};
use alloc::vec::Vec;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};
use narf_edid::DetailedTiming;

/// One base block plus up to four extensions, as `amdgpu_ddc` bounds them.
const MAX_BLOCKS: usize = 1 + crate::amdgpu_ddc::MAX_EXT_BLOCKS as usize;
const BLOCK: usize = 128;
/// `drm_do_get_edid` retries a block that fails its checksum four times.
const BLOCK_TRIES: u32 = 4;
const DDC_EDID: u8 = 0x50;
const DDC_SEGMENT: u8 = 0x30;
/// HDMI 2.0 SCDC.
pub const DDC_SCDC: u8 = 0x54;
/// DPCD receiver capability field, `DP_DPCD_REV` .. `DP_RECEIVE_PORT_1_CAP_1`.
const DPCD_CAPS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Allocation,
    Ddc(ddc::Error),
    /// The VBIOS connector table could not be read.
    Inventory(crate::amdgpu_dcn_inventory::Error),
    /// The EDID header was wrong or a block kept failing its checksum.
    Edid(narf_edid::EdidError),
}
impl From<ddc::Error> for Error {
    fn from(error: ddc::Error) -> Self {
        Error::Ddc(error)
    }
}

/// A board connector this path can detect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connector {
    pub path: Path,
    pub signal: Signal,
    /// Zero-based DDC line, which is also the AUX engine index.
    pub line: u8,
    /// Zero-based HPD block (`hpd_source`).
    pub hpd: Option<u8>,
}
impl Connector {
    fn from_path(path: Path) -> Option<Self> {
        let signal = match path.connector {
            Kind::HdmiTypeA => Signal::Hdmi,
            Kind::DisplayPort => Signal::DisplayPort,
            _ => return None,
        };
        Some(Self {
            path,
            signal,
            line: path.aux?,
            hpd: path.hpd.checked_sub(1),
        })
    }
}

/// What a connected sink reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sink {
    pub edid: Vec<u8>,
    pub preferred: Option<DetailedTiming>,
    /// A CTA extension carries the HDMI Licensing VSDB: an HDMI, not DVI, sink.
    pub hdmi: bool,
    /// DisplayPort receiver capabilities, also what link training starts from.
    pub dpcd: Option<[u8; DPCD_CAPS]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detection {
    Disconnected,
    Connected(Sink),
    /// HPD is asserted but the sink could not be read.
    Failed(Error),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub connector: Connector,
    pub detection: Detection,
}

/// Bind every usable path, refusing a board whose routing is ambiguous: two
/// connectors on one DDC line or HPD block would let detection read one
/// connector's sink and report it as another's.
fn connectors(paths: &[Path]) -> Result<Vec<Connector>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(paths.len())
        .map_err(|_| Error::Allocation)?;
    for connector in paths.iter().copied().filter_map(Connector::from_path) {
        if connector.line >= ddc::LINES || connector.hpd.is_some_and(|h| h >= ddc::LINES) {
            return Err(Error::Invalid);
        }
        if out.iter().any(|c: &Connector| {
            c.line == connector.line || (c.hpd.is_some() && c.hpd == connector.hpd)
        }) {
            return Err(Error::Invalid);
        }
        out.push(connector);
    }
    if out.is_empty() {
        return Err(Error::Unsupported);
    }
    Ok(out)
}

pub(crate) struct Detector<I: Io> {
    engine: Engine<I>,
    connectors: Vec<Connector>,
    bound: bool,
}
impl<I: Io> Detector<I> {
    pub(crate) fn new_with(engine: Engine<I>, paths: &[Path]) -> Result<Self, Error> {
        Ok(Self {
            engine,
            connectors: connectors(paths)?,
            bound: false,
        })
    }
    /// The link-encoder AUX init and HPD filter for every connector. Once.
    fn bind(&mut self) -> Result<(), Error> {
        if self.bound {
            return Ok(());
        }
        for c in self.connectors.clone() {
            ddc::bind(&mut self.engine, c.line, c.hpd, c.signal)?;
        }
        self.bound = true;
        Ok(())
    }
    async fn detect(&mut self, index: usize) -> Result<Detection, Error> {
        self.bind()?;
        let c = *self.connectors.get(index).ok_or(Error::Invalid)?;
        // A connector without HPD wiring is probed by DDC alone, as Linux
        // does for HPD_SOURCEID_UNKNOWN: a NACK then means disconnected.
        if let Some(hpd) = c.hpd {
            if !ddc::hpd(&mut self.engine, hpd)? {
                return Ok(Detection::Disconnected);
            }
        }
        let (mode, dpcd) = match c.signal {
            Signal::DisplayPort => {
                let mut caps = [0; DPCD_CAPS];
                if let Err(error) = ddc::dpcd(&mut self.engine, c.line, 0, &mut caps, false).await {
                    return Ok(Detection::Failed(error.into()));
                }
                (Mode::Aux, Some(caps))
            }
            Signal::Hdmi => (Mode::I2c, None),
        };
        match read_edid(&mut self.engine, c.line, mode).await {
            Ok(edid) => Ok(Detection::Connected(sink(edid, dpcd))),
            Err(Error::Ddc(ddc::Error::I2cNack)) if c.hpd.is_none() => Ok(Detection::Disconnected),
            Err(Error::Ddc(
                error @ (ddc::Error::DeviceGone | ddc::Error::Revoked | ddc::Error::Busy),
            )) => Err(Error::Ddc(error)),
            Err(error) => Ok(Detection::Failed(error)),
        }
    }
    async fn detect_all(&mut self) -> Result<Vec<Report>, Error> {
        let mut reports = Vec::new();
        reports
            .try_reserve_exact(self.connectors.len())
            .map_err(|_| Error::Allocation)?;
        for index in 0..self.connectors.len() {
            let detection = self.detect(index).await?;
            reports.push(Report {
                connector: self.connectors[index],
                detection,
            });
        }
        Ok(reports)
    }
}

fn sink(edid: Vec<u8>, dpcd: Option<[u8; DPCD_CAPS]>) -> Sink {
    let preferred = narf_edid::Block::parse(&edid[..BLOCK])
        .ok()
        .and_then(|block| block.preferred_mode());
    let hdmi = edid[BLOCK..].chunks_exact(BLOCK).any(|ext| {
        ext[0] == 0x02
            && narf_edid::cta861::CtaExtension::parse(ext)
                .ok()
                .and_then(|cta| cta.hdmi_vsdb())
                .is_some()
    });
    Sink {
        edid,
        preferred,
        hdmi,
        dpcd,
    }
}

fn checksum_ok(block: &[u8]) -> bool {
    block.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)) == 0
}

/// One EDID block through the E-DDC segment pointer when it is needed.
async fn read_block<I: Io>(
    engine: &mut Engine<I>,
    line: u8,
    mode: Mode,
    index: usize,
    out: &mut [u8],
) -> Result<(), Error> {
    let segment = (index / 2) as u8;
    let mut segment_byte = [segment];
    let mut offset = [((index % 2) * BLOCK) as u8];
    for attempt in 0..BLOCK_TRIES {
        let result = if segment == 0 {
            let mut messages = [
                Message {
                    address: DDC_EDID,
                    write: true,
                    data: &mut offset,
                },
                Message {
                    address: DDC_EDID,
                    write: false,
                    data: out,
                },
            ];
            ddc::i2c(engine, line, mode, &mut messages).await
        } else {
            let mut messages = [
                Message {
                    address: DDC_SEGMENT,
                    write: true,
                    data: &mut segment_byte,
                },
                Message {
                    address: DDC_EDID,
                    write: true,
                    data: &mut offset,
                },
                Message {
                    address: DDC_EDID,
                    write: false,
                    data: out,
                },
            ];
            ddc::i2c(engine, line, mode, &mut messages).await
        };
        result?;
        if checksum_ok(out) {
            return Ok(());
        }
        let _ = attempt;
    }
    Err(Error::Edid(narf_edid::EdidError::BadChecksum))
}

/// `drm_do_get_edid`: the base block, then each declared extension.
pub(crate) async fn read_edid<I: Io>(
    engine: &mut Engine<I>,
    line: u8,
    mode: Mode,
) -> Result<Vec<u8>, Error> {
    let mut edid = Vec::new();
    edid.try_reserve_exact(MAX_BLOCKS * BLOCK)
        .map_err(|_| Error::Allocation)?;
    edid.resize(BLOCK, 0);
    read_block(engine, line, mode, 0, &mut edid[..BLOCK]).await?;
    if edid[..8] != [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0] {
        return Err(Error::Edid(narf_edid::EdidError::BadHeader));
    }
    let blocks = (1 + usize::from(edid[126])).min(MAX_BLOCKS);
    edid.resize(blocks * BLOCK, 0);
    for index in 1..blocks {
        read_block(
            engine,
            line,
            mode,
            index,
            &mut edid[index * BLOCK..][..BLOCK],
        )
        .await?;
    }
    Ok(edid)
}

/// The board's connectors on the native DDC owner.
pub struct Display(Detector<ddc::Mmio>);
impl core::fmt::Debug for Display {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Display")
            .field("connectors", &self.0.connectors)
            .field("bound", &self.0.bound)
            .finish()
    }
}
impl Display {
    /// # Safety
    /// As [`ddc::Ddc::new`]: exclusive, permanent ownership of every DDC, AUX
    /// and HPD block and pad. `paths` must be this GPU's validated VBIOS routes
    /// and `crystal_khz` its VBIOS crystal.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        paths: &[Path],
        crystal_khz: u32,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded unchanged.
        let ddc = unsafe { ddc::Ddc::new(gpu, authority, crystal_khz) }?;
        Ok(Self(Detector::new_with(ddc.into_engine(), paths)?))
    }
    pub fn connectors(&self) -> &[Connector] {
        &self.0.connectors
    }
    pub async fn detect(&mut self, index: usize) -> Result<Detection, Error> {
        self.0.detect(index).await
    }
    /// Detect every connector in table order. A sink that cannot be read is a
    /// per-connector `Failed`; only owner loss fails the whole probe.
    pub async fn detect_all(&mut self) -> Result<Vec<Report>, Error> {
        self.0.detect_all().await
    }
    /// SCDC/other DDC access on an HDMI connector's hardware I2C engine.
    pub async fn i2c(&mut self, index: usize, messages: &mut [Message<'_>]) -> Result<(), Error> {
        self.0.bind()?;
        let c = *self.0.connectors.get(index).ok_or(Error::Invalid)?;
        let mode = match c.signal {
            Signal::Hdmi => Mode::I2c,
            Signal::DisplayPort => Mode::Aux,
        };
        Ok(ddc::i2c(&mut self.0.engine, c.line, mode, messages).await?)
    }
    /// Native DPCD access on a DisplayPort connector.
    pub async fn dpcd_read(
        &mut self,
        index: usize,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        self.0.bind()?;
        let c = *self.0.connectors.get(index).ok_or(Error::Invalid)?;
        if c.signal != Signal::DisplayPort {
            return Err(Error::Unsupported);
        }
        Ok(ddc::dpcd(&mut self.0.engine, c.line, address, data, false).await?)
    }
    pub async fn dpcd_write(
        &mut self,
        index: usize,
        address: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        self.0.bind()?;
        let c = *self.0.connectors.get(index).ok_or(Error::Invalid)?;
        if c.signal != Signal::DisplayPort || data.len() > ddc::AUX_MAX_BYTES {
            return Err(Error::Unsupported);
        }
        let mut copy = [0; ddc::AUX_MAX_BYTES];
        copy[..data.len()].copy_from_slice(data);
        Ok(ddc::dpcd(
            &mut self.0.engine,
            c.line,
            address,
            &mut copy[..data.len()],
            true,
        )
        .await?)
    }
    pub fn hpd_ack(&mut self, index: usize) -> Result<bool, Error> {
        let c = *self.0.connectors.get(index).ok_or(Error::Invalid)?;
        let hpd = c.hpd.ok_or(Error::Unsupported)?;
        Ok(ddc::hpd_ack(&mut self.0.engine, hpd)?)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_display_tests.rs"]
mod tests;
