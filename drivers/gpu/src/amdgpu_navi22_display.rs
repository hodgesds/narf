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
const MAX_BLOCKS: usize = 1 + crate::amdgpu_ddc::MAX_EXT_BLOCKS as usize; // linux: n/a (NARF bound)
const BLOCK: usize = 128; // linux: n/a (EDID_LENGTH 128, include/drm/drm_edid.h)
/// `drm_do_get_edid` retries a block that fails its checksum four times.
const BLOCK_TRIES: u32 = 4; // linux: n/a (literal 4 in drm_edid.c:drm_do_get_edid)
const DDC_EDID: u8 = 0x50; // linux: n/a (DDC_ADDR 0x50, include/drm/drm_edid.h)
const DDC_SEGMENT: u8 = 0x30; // linux: n/a (DDC_SEGMENT_ADDR 0x30, local in drm_edid.c)
/// HDMI 2.0 SCDC.
pub const DDC_SCDC: u8 = 0x54; // linux: n/a (HDMI_SCDC_ADDRESS 0x54, dc/dc_hdmi_types.h)
/// DPCD receiver capability field, `DP_DPCD_REV` .. `DP_RECEIVE_PORT_1_CAP_1`.
const DPCD_CAPS: usize = 16; // linux: DP_ADAPTER_CAP - DP_DPCD_REV + 1

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
    /// `connector_obj_id.id` (`grph_object_id.h`): CONNECTOR_ID_HDMI_TYPE_A
    /// and CONNECTOR_ID_DISPLAY_PORT, as the VBIOS transmitter table takes it.
    pub fn object_id(&self) -> u8 {
        match self.signal {
            Signal::Hdmi => 12,        // linux-lit: 12=CONNECTOR_ID_HDMI_TYPE_A
            Signal::DisplayPort => 19, // linux-lit: 19=CONNECTOR_ID_DISPLAY_PORT
        }
    }
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
    /// HPD blocks this owner had to switch on, and when: their debounced
    /// sense reads low until the connect filter (500 ms HDMI, 80 ms DP)
    /// has passed.
    settling: u8,
    settle_until: Option<narf_time::Deadline>,
    /// Per connector: the receiver caps a DP sink reported when its link was
    /// verified, and that `verified_link_cap` (`amdgpu_dcn30_dp_link`).
    links: [Option<([u8; DPCD_CAPS], crate::amdgpu_navi22_modeset::DpLink)>; ddc::LINES as usize],
}
/// How long a freshly enabled HPD block may read disconnected before the
/// filter has run: the longest connect delay plus margin.
const HPD_SETTLE_MS: u64 = 1000; // linux: n/a (NARF policy)
const HPD_SETTLE_POLL_MS: u64 = 10; // linux: n/a (NARF policy)
impl<I: Io> Detector<I> {
    pub(crate) fn new_with(engine: Engine<I>, paths: &[Path]) -> Result<Self, Error> {
        Ok(Self {
            engine,
            connectors: connectors(paths)?,
            bound: false,
            settling: 0,
            settle_until: None,
            links: [None; ddc::LINES as usize],
        })
    }
    /// The link-encoder AUX init and HPD filter for every connector. Once.
    fn bind(&mut self) -> Result<(), Error> {
        if self.bound {
            return Ok(());
        }
        for c in self.connectors.clone() {
            if ddc::bind(&mut self.engine, c.line, c.hpd, c.signal)? {
                self.settling |= 1 << c.hpd.unwrap_or(0);
            }
        }
        if self.settling != 0 {
            self.settle_until = Some(narf_time::Deadline::after_ms(HPD_SETTLE_MS));
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
            if !self.sense(hpd).await? {
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
    /// Debounced HPD sense; a block this owner just enabled is polled until
    /// it reads connected or its filter has certainly run (bounded).
    async fn sense(&mut self, hpd: u8) -> Result<bool, Error> {
        loop {
            if ddc::hpd(&mut self.engine, hpd)? {
                return Ok(true);
            }
            let settling = self.settling & 1 << hpd != 0;
            match self.settle_until {
                Some(deadline) if settling && !deadline.expired() => {
                    narf_time::SleepUntil::new(
                        narf_time::Deadline::after_ms(HPD_SETTLE_POLL_MS).as_instant(),
                    )
                    .await;
                }
                _ => {
                    self.settling &= !(1 << hpd);
                    return Ok(false);
                }
            }
        }
    }
    /// `amdgpu_dm_hpd_init` over DCN3.0's irq service: every HPD and HPD_RX
    /// source set off (ack, then the enable cleared), then HPD on for every
    /// connector with an HPD block and HPD_RX on for DisplayPort ones. The
    /// owner binds (AUX init, HPD filter) first. Call after subscribing to
    /// the IH source, so the first edge cannot be lost.
    pub(crate) fn arm_hpd(&mut self) -> Result<(), Error> {
        self.bind()?;
        for index in 0..ddc::LINES {
            ddc::hpd_irq_set(&mut self.engine, index, false, false)?;
            ddc::hpd_irq_set(&mut self.engine, index, true, false)?;
        }
        for c in self.connectors.clone() {
            if let Some(hpd) = c.hpd {
                ddc::hpd_irq_set(&mut self.engine, hpd, false, true)?;
                if c.signal == Signal::DisplayPort {
                    ddc::hpd_irq_set(&mut self.engine, hpd, true, true)?;
                }
            }
        }
        Ok(())
    }
    /// One IH HPD vector (`amdgpu_dm_irq_handler`'s `dc_interrupt_ack`):
    /// acknowledge it — re-arming the opposite polarity for HPD — and return
    /// the connector it belongs to.
    pub(crate) fn hpd_event(&mut self, instance: u8, rx: bool) -> Result<Option<usize>, Error> {
        if instance >= ddc::LINES {
            return Err(Error::Invalid);
        }
        if rx {
            ddc::hpd_rx_ack(&mut self.engine, instance)?;
        } else {
            ddc::hpd_ack(&mut self.engine, instance)?;
        }
        Ok(self.connectors.iter().position(|c| c.hpd == Some(instance)))
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
        ext[0] == 0x02 // linux: n/a (CEA_EXT 0x02, include/drm/drm_edid.h)
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
    // linux: n/a (EDID header, drm_edid.c edid_header[])
    if edid[..8] != [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0] {
        return Err(Error::Edid(narf_edid::EdidError::BadHeader));
    }
    // linux: n/a (EDID byte 126 extension count, struct edid.extensions)
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
    /// `amdgpu_dm_hpd_init` over DCN3.0's irq service (see
    /// [`Detector::arm_hpd`]). Call after subscribing to the IH source.
    pub fn arm_hpd_interrupts(&mut self) -> Result<(), Error> {
        self.0.arm_hpd()
    }
    /// One IH HPD vector, acknowledged; returns the connector it belongs to.
    pub fn hpd_event(&mut self, instance: u8, rx: bool) -> Result<Option<usize>, Error> {
        self.0.hpd_event(instance, rx)
    }
    pub fn hpd_ack(&mut self, index: usize) -> Result<bool, Error> {
        let c = *self.0.connectors.get(index).ok_or(Error::Invalid)?;
        let hpd = c.hpd.ok_or(Error::Unsupported)?;
        Ok(ddc::hpd_ack(&mut self.0.engine, hpd)?)
    }
}

/// DP link state and HPD sense for the display monitor
/// (`amdgpu_navi22_platform`) and the DCN30 link layer.
impl Display {
    /// Debounced HPD of connector `index` without the settle wait; None for
    /// a connector without HPD wiring.
    pub fn hpd_sense(&mut self, index: usize) -> Result<Option<bool>, Error> {
        self.0.bind()?;
        let c = *self.0.connectors.get(index).ok_or(Error::Invalid)?;
        match c.hpd {
            Some(hpd) => Ok(Some(ddc::hpd(&mut self.0.engine, hpd)?)),
            None => Ok(None),
        }
    }
    /// The AUX reply timeout of DP connector `index`'s engine.
    pub fn aux_timeout(&mut self, index: usize, us: u32) -> Result<(), Error> {
        self.0.bind()?;
        let c = *self.0.connectors.get(index).ok_or(Error::Invalid)?;
        if c.signal != Signal::DisplayPort {
            return Err(Error::Unsupported);
        }
        Ok(ddc::aux_timeout(&mut self.0.engine, c.line, us)?)
    }
    /// The verified link of connector `index` while its sink still reports
    /// the receiver caps it was verified with.
    pub fn verified_link(
        &self,
        index: usize,
        dpcd: Option<[u8; DPCD_CAPS]>,
    ) -> Option<crate::amdgpu_navi22_modeset::DpLink> {
        let (caps, link) = (*self.0.links.get(index)?)?;
        (Some(caps) == dpcd).then_some(link)
    }
    /// Record (or with None, forget) connector `index`'s verified link.
    pub fn set_verified_link(
        &mut self,
        index: usize,
        dpcd: Option<[u8; DPCD_CAPS]>,
        link: Option<crate::amdgpu_navi22_modeset::DpLink>,
    ) {
        if let Some(slot) = self.0.links.get_mut(index) {
            *slot = dpcd.zip(link);
        }
    }
}

/// Hotplug wake-ups from the IH HPD service to pollers of [`Display`]:
/// a version that each HPD/HPD_RX vector bumps, and the tasks waiting for a
/// newer one. Polling keeps working without it (the wait times out).
#[derive(Debug)]
pub struct Hotplug(narf_lib::sync::IrqSafeSpinLock<(u64, Vec<core::task::Waker>)>);
pub static HOTPLUG: Hotplug = Hotplug(narf_lib::sync::IrqSafeSpinLock::new((0, Vec::new())));
/// A level-triggered source that is not acked would re-fire at once; never
/// return to a poller more often than this.
pub const HOTPLUG_MIN_MS: u64 = 50; // linux: n/a (NARF policy)
impl Hotplug {
    pub fn version(&self) -> u64 {
        self.0.lock().0
    }
    pub fn notify(&self) {
        let wakers = {
            let mut s = self.0.lock();
            s.0 += 1;
            core::mem::take(&mut s.1)
        };
        wakers.into_iter().for_each(core::task::Waker::wake);
    }
    /// Sleep up to `period_ms`, returning early (not before
    /// [`HOTPLUG_MIN_MS`]) once the version moved past `since`, which is
    /// updated. Returns whether an HPD event woke it.
    pub async fn wait(&self, since: &mut u64, period_ms: u64) -> bool {
        let floor = narf_time::Deadline::after_ms(HOTPLUG_MIN_MS.min(period_ms));
        let deadline = narf_time::Deadline::after_ms(period_ms);
        let mut sleep = core::pin::pin!(narf_time::SleepUntil::new(deadline.as_instant()));
        let woke = core::future::poll_fn(|cx| {
            {
                let mut s = self.0.lock();
                if s.0 != *since {
                    *since = s.0;
                    return core::task::Poll::Ready(true);
                }
                if !s.1.iter().any(|w| w.will_wake(cx.waker())) {
                    s.1.push(cx.waker().clone());
                }
            }
            sleep.as_mut().poll(cx).map(|()| false)
        })
        .await;
        narf_time::SleepUntil::new(floor.as_instant()).await;
        woke
    }
}
use core::future::Future as _;

/// The IH HPD service body: for every DCN HPD/HPD_RX vector, `ack` it on
/// the display owner, then wake hotplug pollers. Ends when the subscription
/// closes (device loss, recovery); polling then carries on alone.
pub async fn serve_hpd<F: core::future::Future<Output = ()>>(
    mut subscription: crate::amdgpu_ih_navi22::Subscription,
    mut ack: impl FnMut(crate::amdgpu_ih_navi22::Hpd) -> F,
) {
    while let Ok(iv) = subscription.wait().await {
        if let Some(hpd) = iv.hpd() {
            ack(hpd).await;
            HOTPLUG.notify();
        }
    }
}

/// Native AUX to one DisplayPort connector, for link training.
#[derive(Debug)]
pub struct DisplayAux<'a> {
    pub display: &'a mut Display,
    pub index: usize,
}
impl crate::amdgpu_dcn30_dp::Aux for DisplayAux<'_> {
    async fn set_timeout_us(&mut self, us: u32) -> Result<(), crate::amdgpu_navi22_modeset::Error> {
        self.display
            .aux_timeout(self.index, us)
            .map_err(|_| crate::amdgpu_navi22_modeset::Error::Aux)
    }
    /// HPD low (or unreadable) is a departed sink; unwired HPD is assumed
    /// connected, as the AUX replies decide then.
    async fn connected(&mut self) -> bool {
        !matches!(self.display.hpd_sense(self.index), Ok(Some(false)) | Err(_))
    }
    async fn read(
        &mut self,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), crate::amdgpu_navi22_modeset::Error> {
        for (i, chunk) in data.chunks_mut(ddc::AUX_MAX_BYTES).enumerate() {
            let at = address + (i * ddc::AUX_MAX_BYTES) as u32;
            self.display
                .dpcd_read(self.index, at, chunk)
                .await
                .map_err(|_| crate::amdgpu_navi22_modeset::Error::Aux)?;
        }
        Ok(())
    }
    async fn write(
        &mut self,
        address: u32,
        data: &[u8],
    ) -> Result<(), crate::amdgpu_navi22_modeset::Error> {
        for (i, chunk) in data.chunks(ddc::AUX_MAX_BYTES).enumerate() {
            let at = address + (i * ddc::AUX_MAX_BYTES) as u32;
            self.display
                .dpcd_write(self.index, at, chunk)
                .await
                .map_err(|_| crate::amdgpu_navi22_modeset::Error::Aux)?;
        }
        Ok(())
    }
    /// `link_query_ddc_data(0x54, &offset, 1, &value, 1)` on the HDMI
    /// connector's hardware I2C engine: the offset written, one byte read
    /// back under a repeated start.
    async fn scdc_read(&mut self, offset: u8) -> Result<u8, crate::amdgpu_navi22_modeset::Error> {
        let mut at = [offset];
        let mut value = [0u8];
        self.scdc(&mut [
            Message {
                address: DDC_SCDC,
                write: true,
                data: &mut at,
            },
            Message {
                address: DDC_SCDC,
                write: false,
                data: &mut value,
            },
        ])
        .await?;
        Ok(value[0])
    }
    /// `link_query_ddc_data(0x54, [offset, value], 2, NULL, 0)`.
    async fn scdc_write(
        &mut self,
        offset: u8,
        value: u8,
    ) -> Result<(), crate::amdgpu_navi22_modeset::Error> {
        let mut data = [offset, value];
        self.scdc(&mut [Message {
            address: DDC_SCDC,
            write: true,
            data: &mut data,
        }])
        .await
    }
}
impl DisplayAux<'_> {
    /// SCDC only exists on an HDMI connector's DDC.
    async fn scdc(
        &mut self,
        messages: &mut [Message<'_>],
    ) -> Result<(), crate::amdgpu_navi22_modeset::Error> {
        let scdc = crate::amdgpu_navi22_modeset::Error::Hdmi(crate::amdgpu_dcn30_hdmi::Error::Scdc);
        match self.display.connectors().get(self.index) {
            Some(c) if c.signal == Signal::Hdmi => {}
            _ => return Err(scdc),
        }
        self.display
            .i2c(self.index, messages)
            .await
            .map_err(|_| scdc)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_display_tests.rs"]
mod tests;
