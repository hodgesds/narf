//! Production HDCP: the DRM connectors that carry "Content Protection",
//! the external routes behind them, the HDCP 2.2 firmware transport and
//! the service that runs the HDCP operations, all behind
//! `narf.intel.hdcp=1`.
//!
//! ## Linux's shape and NARF's
//!
//! i915 attaches the property pair to every non-eDP DP and every HDMI
//! connector at init (`intel_hdcp_init`), enables HDCP from the commit
//! (`intel_hdcp_enable` / `intel_hdcp_update_pipe`), disables it from
//! encoder disable, and re-checks the link from `check_work`
//! (`DRM_HDCP_CHECK_PERIOD_MS`, `DRM_HDCP2_CHECK_PERIOD_MS`), reporting
//! DESIRED/ENABLED flips through `prop_work`.
//!
//! NARF's Intel card has one connector for the output that owns it. With
//! the option, the first service pass attaches the pair to that connector
//! unless it is eDP, and binds it to the single live HDCP-capable external
//! route of the function: a Gen12 HPD SST DP or HDMI session, a display
//! 14+ SST DP or HDMI route, or, on a Tiger/Alder Lake card that kept the
//! firmware's display, the route the firmware lit (read back from
//! `TRANS_DDI_FUNC_CTL`). No route, or more than one, leaves the request
//! as it is (`HdcpError::NoRoute`). DP MST is refused.
//!
//! The service runs on the GT runtime actor's external-route pass
//! (`intel_gpu::service_external_sst`), serialized with hotplug and route
//! stop. An operation is an async engine call polled once per pass:
//! sleeps are deadlines, the GSC firmware answers through the GSC
//! worker's mailbox, the MEI client answers synchronously. A route that
//! stops first has its HDCP registers put back to off
//! ([`route_stopping`]); its operation is dropped.
//!
//! ## HDCP 2.2 firmware
//!
//! Display 12/13: the MEI HDCP client bound through
//! `narf_drivers::hdcp_component`. Display 14+: the media GT's GSC
//! (`narf.intel.media_gt=1 narf.intel.gsc=1`), once its proxy is up
//! (`intel_hdcp_gsc_check_status`); the GSC worker submits each framed
//! command as a `GSC_HECI_CMD_PKT` from its packet object. Without either,
//! type-0 content falls back to HDCP 1.4.
//!
//! ## SRM
//!
//! `display_hdcp_srm.bin` is read through the firmware registry at each
//! operation, as `drm_hdcp_check_ksvs_revoked` requests it each check; no
//! SRM (or one that does not parse) revokes nothing, as in Linux.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll};

use narf_lib::sync::IrqSafeSpinLock;

use crate::drm::card::{ConnectorType, ContentProtection};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gmbus::PinPair;
use crate::intel_hdcp::{
    self as hdcp, Commit, CpValue, Ctx, HdcpEnv, HdcpError, HdcpLink, LineRekey, Protocol, Srm,
    Uapi,
};
use crate::intel_hdcp_msg::{GscFraming, GscPacketPort, HdcpFuture, HdcpTransport, MeiTransport};
use crate::intel_hdcp_shim::{AuxDpcd, AuxPort, DpShim, GmbusDdc, HdmiShim};

// ── The option ───────────────────────────────────────────────────────

static OPTION: AtomicU8 = AtomicU8::new(0);

/// `narf.intel.hdcp=1`, parsed once.
pub fn enabled() -> bool {
    match OPTION.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let on = hdcp::opted_in();
            OPTION.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

// ── Routes ───────────────────────────────────────────────────────────

/// How the transmitter reaches the sink.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RouteLink {
    Dp(AuxPort),
    Hdmi(PinPair),
}

/// One live external SST route, as HDCP needs it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RouteDesc {
    /// Identity of the route (its port and pipe); a different key is a
    /// different route.
    pub key: u64,
    pub protocol: Protocol,
    /// The CPU transcoder, A–D (0..=3).
    pub transcoder: u8,
    pub link: RouteLink,
    /// Display IP major version (12, 13, 14, 20, 30, 35).
    pub display_ver: u8,
    pub rekey: LineRekey,
}

/// A display-14+ route as `intel_gpu_xelpg_external::hdcp_route` reports
/// it: port index, CPU transcoder, protocol and sink link.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct XelpgRoute {
    pub port: u8,
    pub transcoder: u8,
    pub protocol: Protocol,
    pub link: RouteLink,
}

/// The key of a Gen12 route on `ddi`.
pub const fn gen12_key(ddi: Ddi) -> u64 {
    0x12 << 32 | ddi as u64
}

/// The key of a display-14+ route on port index `port`, pipe `pipe`.
pub const fn xelpg_key(port: u8, pipe: u8) -> u64 {
    0x14 << 32 | (pipe as u64) << 8 | port as u64
}

/// `TRANS_DDI_FUNC_CTL` fields of the Gen12 readout.
const TRANS_DDI_FUNC_ENABLE: u32 = 1 << 31;
const TGL_TRANS_DDI_PORT_SHIFT: u32 = 27;
const TRANS_DDI_MODE_SHIFT: u32 = 24;
const MODE_HDMI: u32 = 0;
const MODE_DVI: u32 = 1;
const MODE_DP_SST: u32 = 2;
/// `DP_EDP_CONFIGURATION_CAP`: nonzero only on eDP sinks.
const DP_EDP_CONFIGURATION_CAP: u32 = 0x00d;

/// The Gen12 route a Tiger Lake or Alder Lake-P firmware display lit:
/// the one enabled transcoder A–D in HDMI, DVI or DP SST mode
/// (`intel_ddi_get_config`'s `TRANS_DDI_FUNC_CTL` readout). A DP route is
/// taken only on a combo DDI (native AUX) whose sink is not eDP; an HDMI
/// route needs the DDI's default DDC pin.
pub fn inherited_gen12_route<M: MmioWindow + Sync + ?Sized>(
    io: &M,
    family: crate::intel_gpu_gt::Gen12Platform,
) -> Result<Option<RouteDesc>, HdcpError> {
    use crate::intel_gpu_gt::Gen12Platform as P;
    if !matches!(family, P::TigerLake | P::AlderLakeP) {
        return Err(HdcpError::Unsupported);
    }
    const DDIS: [Ddi; 9] = [
        Ddi::A,
        Ddi::B,
        Ddi::C,
        Ddi::D,
        Ddi::E,
        Ddi::F,
        Ddi::G,
        Ddi::H,
        Ddi::I,
    ];
    let mut found = None;
    for t in 0u8..4 {
        let v = io.read32(hdcp::trans_ddi_func_ctl(t));
        if v == u32::MAX || v & TRANS_DDI_FUNC_ENABLE == 0 {
            continue;
        }
        if found.is_some() {
            return Err(HdcpError::NoRoute);
        }
        let select = (v >> TGL_TRANS_DDI_PORT_SHIFT) & 0xf;
        let Some(&ddi) = select.checked_sub(1).and_then(|i| DDIS.get(i as usize)) else {
            return Err(HdcpError::Unsupported);
        };
        let route = match (v >> TRANS_DDI_MODE_SHIFT) & 7 {
            MODE_HDMI | MODE_DVI => {
                let pin = crate::intel_gpu_gmbus::gen12_ddc_pin(family, ddi)
                    .ok_or(HdcpError::Unsupported)?;
                (Protocol::Hdmi, RouteLink::Hdmi(pin))
            }
            MODE_DP_SST if matches!(ddi, Ddi::A | Ddi::B | Ddi::C) => {
                if inherited_edp(io, t, ddi)? {
                    return Err(HdcpError::Unsupported);
                }
                (Protocol::Dp, RouteLink::Dp(AuxPort::Gen12(ddi)))
            }
            _ => return Err(HdcpError::Unsupported),
        };
        found = Some(RouteDesc {
            key: gen12_key(ddi),
            protocol: route.0,
            transcoder: t,
            link: route.1,
            display_ver: 12,
            rekey: LineRekey::None,
        });
    }
    Ok(found)
}

/// The firmware DP route's sink is eDP (`DP_EDP_CONFIGURATION_CAP`
/// nonzero; Linux takes it from the VBT and never protects eDP). Read once
/// per (transcoder, DDI) and kept.
fn inherited_edp<M: MmioWindow + Sync + ?Sized>(
    io: &M,
    transcoder: u8,
    ddi: Ddi,
) -> Result<bool, HdcpError> {
    static SEEN: IrqSafeSpinLock<Option<(u8, Ddi, bool)>> = IrqSafeSpinLock::new(None);
    if let Some((t, d, edp)) = *SEEN.lock() {
        if (t, d) == (transcoder, ddi) {
            return Ok(edp);
        }
    }
    let mut dpcd = AuxDpcd {
        io,
        port: AuxPort::Gen12(ddi),
    };
    let mut cap = [0u8; 1];
    crate::intel_hdcp_shim::Dpcd::read(&mut dpcd, DP_EDP_CONFIGURATION_CAP, &mut cap)?;
    let edp = cap[0] != 0;
    *SEEN.lock() = Some((transcoder, ddi, edp));
    Ok(edp)
}

/// `GMD_ID_DISPLAY` (display 14+): IP version, release and step.
const GMD_ID_DISPLAY: u64 = 0x510a0;

fn display_rekey<M: MmioWindow + ?Sized>(io: &M) -> (u8, LineRekey) {
    let v = io.read32(GMD_ID_DISPLAY);
    if v == u32::MAX || v == 0 {
        return (14, LineRekey::None);
    }
    let ver = (v >> 22) as u8;
    let rel = ((v >> 14) & 0xff) as u8;
    let step = (v & 0x3f) as u8;
    (ver, LineRekey::for_display(ver, rel, step))
}

/// The function's live HDCP-capable routes on `bar`.
fn routes(bar: &narf_bus::MmioRegion) -> Result<Vec<RouteDesc>, HdcpError> {
    let Some(io) = crate::intel_gpu::with_display_info(|g| g.mode_window()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (ddi, transcoder, pin) in crate::intel_gpu::hdcp_gen12_sessions(bar) {
        if transcoder > 3 {
            continue;
        }
        let (protocol, link) = match pin {
            Some(pin) => (Protocol::Hdmi, RouteLink::Hdmi(pin)),
            None => (Protocol::Dp, RouteLink::Dp(AuxPort::Gen12(ddi))),
        };
        out.push(RouteDesc {
            key: gen12_key(ddi),
            protocol,
            transcoder,
            link,
            display_ver: 12,
            rekey: LineRekey::None,
        });
    }
    if let Some(r) = crate::intel_gpu_xelpg_external::hdcp_route() {
        let (ver, rekey) = display_rekey(&io);
        out.push(RouteDesc {
            key: xelpg_key(r.port, r.transcoder),
            protocol: r.protocol,
            transcoder: r.transcoder,
            link: r.link,
            display_ver: ver,
            rekey,
        });
    }
    let firmware = crate::intel_gpu::with_controller(|g| g.firmware_display).unwrap_or(false);
    if out.is_empty() && firmware {
        if let Some(family) = io.gen12_display_family() {
            if let Some(r) = inherited_gen12_route(&io, family)? {
                out.push(r);
            }
        }
    }
    Ok(out)
}

/// The one route a connector binds to.
fn select(routes: Result<Vec<RouteDesc>, HdcpError>) -> Result<Option<RouteDesc>, HdcpError> {
    let routes = routes?;
    match routes.len() {
        0 => Ok(None),
        1 => Ok(Some(routes[0])),
        _ => Err(HdcpError::NoRoute),
    }
}

// ── The environment ──────────────────────────────────────────────────

/// A future ready once `monotonic_ns` reaches `at`.
#[derive(Debug)]
struct Until(u64);

impl Future for Until {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if narf_time::monotonic_ns() >= self.0 {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

fn until_ms(ms: u64) -> Until {
    Until(narf_time::monotonic_ns().saturating_add(ms.saturating_mul(1_000_000)))
}

/// `request_firmware_direct("display_hdcp_srm.bin")`.
fn load_srm() -> Option<Srm> {
    let write = narf_firmware::trusted_loader_authority()?;
    let read: narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read> =
        write.derive().ok()?;
    let blob = narf_firmware::open("display_hdcp_srm.bin", &read).ok()?;
    let view = narf_firmware::view_of(&blob).ok()?;
    Srm::parse(view.bytes)
}

/// The production environment.
#[derive(Debug)]
struct LiveEnv {
    srm: Option<Srm>,
}

impl HdcpEnv for LiveEnv {
    fn now_us(&mut self) -> u64 {
        narf_time::monotonic_ns() / 1000
    }
    fn delay_ms(&mut self, ms: u64) -> HdcpFuture<'_, ()> {
        Box::pin(until_ms(ms))
    }
    fn udelay(&mut self, us: u64) {
        let end = narf_time::monotonic_ns().saturating_add(us * 1000);
        while narf_time::monotonic_ns() < end {
            core::hint::spin_loop();
        }
    }
    fn random_u32(&mut self) -> u32 {
        narf_memory::kaslr::random_u64().0 as u32
    }
    fn revoked(&mut self, ksvs: &[u8]) -> usize {
        self.srm.as_ref().map_or(0, |s| s.revoked_count(ksvs))
    }
}

// ── The GSC mailbox ──────────────────────────────────────────────────

/// One framed command the GSC worker submits for HDCP.
#[derive(Debug)]
enum GscSlot {
    Idle,
    Request {
        ticket: u64,
        input: Vec<u8>,
        out_len: usize,
    },
    InFlight {
        ticket: u64,
    },
    Done {
        ticket: u64,
        result: Result<Vec<u8>, i32>,
    },
}

static GSC: IrqSafeSpinLock<GscSlot> = IrqSafeSpinLock::new(GscSlot::Idle);
static GSC_TICKET: AtomicU64 = AtomicU64::new(1);
static GSC_READY: AtomicBool = AtomicBool::new(false);
/// How long a submission may take end to end (`HZ` for the job, plus the
/// worker's pass interval).
const GSC_JOB_MS: u64 = 2000;

/// The GSC worker publishes `intel_hdcp_gsc_check_status`.
pub(crate) fn gsc_set_ready(ready: bool) {
    GSC_READY.store(ready, Ordering::Release);
}

/// The GSC worker takes the pending command: (ticket, framed input,
/// output length).
pub(crate) fn gsc_take() -> Option<(u64, Vec<u8>, usize)> {
    let mut slot = GSC.lock();
    match core::mem::replace(&mut *slot, GscSlot::Idle) {
        GscSlot::Request {
            ticket,
            input,
            out_len,
        } => {
            *slot = GscSlot::InFlight { ticket };
            Some((ticket, input, out_len))
        }
        other => {
            *slot = other;
            None
        }
    }
}

/// The GSC worker finished `ticket`: the output (GSC header and reply) or
/// a negative errno.
pub(crate) fn gsc_complete(ticket: u64, result: Result<Vec<u8>, i32>) {
    let mut slot = GSC.lock();
    if matches!(&*slot, GscSlot::InFlight { ticket: t } if *t == ticket) {
        *slot = GscSlot::Done { ticket, result };
    }
}

/// The production `GscPacketPort`.
#[derive(Debug)]
struct LiveGsc;

impl GscPacketPort for LiveGsc {
    fn submit<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
    ) -> HdcpFuture<'a, Result<(), i32>> {
        Box::pin(async move {
            let ticket = GSC_TICKET.fetch_add(1, Ordering::Relaxed);
            {
                let mut slot = GSC.lock();
                // A completion nobody waits for any more (its operation was
                // dropped) gives way; a request or job in flight does not.
                if matches!(&*slot, GscSlot::Request { .. } | GscSlot::InFlight { .. }) {
                    return Err(-(narf_lib::errno::EBUSY as i32));
                }
                *slot = GscSlot::Request {
                    ticket,
                    input: input.to_vec(),
                    out_len: output.len(),
                };
            }
            let deadline = narf_time::monotonic_ns().saturating_add(GSC_JOB_MS * 1_000_000);
            loop {
                {
                    let mut slot = GSC.lock();
                    if matches!(&*slot, GscSlot::Done { ticket: t, .. } if *t == ticket) {
                        let GscSlot::Done { result, .. } =
                            core::mem::replace(&mut *slot, GscSlot::Idle)
                        else {
                            unreachable!()
                        };
                        let reply = result?;
                        let n = reply.len().min(output.len());
                        output[..n].copy_from_slice(&reply[..n]);
                        return Ok(());
                    }
                    if narf_time::monotonic_ns() >= deadline {
                        // Withdraw a request the worker never took; a job in
                        // flight is left to complete into a slot nobody
                        // waits on, which the next submission replaces.
                        *slot = GscSlot::Idle;
                        return Err(-(narf_lib::errno::ETIME as i32));
                    }
                }
                until_ms(1).await;
            }
        })
    }
    fn ready(&mut self) -> bool {
        GSC_READY.load(Ordering::Acquire)
    }
    fn delay_ms(&mut self, ms: u64) -> HdcpFuture<'_, ()> {
        Box::pin(until_ms(ms))
    }
}

/// The HDCP 2.2 firmware for a route, when it is there: MEI on display
/// 12/13, the GSC on 14+.
fn firmware(display_ver: u8) -> Option<Box<dyn HdcpTransport>> {
    if display_ver < 14 {
        let me = crate::intel_gpu_gt::media::gsc::load::INTEL_DISPLAY_COMPONENT;
        narf_drivers::hdcp_component::lookup(&me)
            .map(|b| Box::new(MeiTransport(b)) as Box<dyn HdcpTransport>)
    } else {
        let mut port = LiveGsc;
        if !port.ready() {
            return None;
        }
        let random = narf_memory::kaslr::random_u64().0;
        Some(Box::new(GscFraming::new(port, random)))
    }
}

// ── Connectors and operations ────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OpKind {
    Enable,
    Disable,
    /// `intel_hdcp_update_pipe`'s type change: disable, DESIRED, enable.
    Retype,
    Check,
}

#[derive(Debug)]
struct OpDone {
    link: HdcpLink,
    kind: OpKind,
    result: Result<(), HdcpError>,
}

type Op = Pin<Box<dyn Future<Output = OpDone> + Send>>;

struct Slot {
    card: u32,
    connector: u32,
    uapi: Uapi,
    dirty: bool,
    route: Option<RouteDesc>,
    /// `None` while an operation owns it.
    link: Option<HdcpLink>,
    op: Option<Op>,
    next_check_ns: u64,
    last: Option<HdcpError>,
}

impl core::fmt::Debug for Slot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Slot")
            .field("card", &self.card)
            .field("connector", &self.connector)
            .field("uapi", &self.uapi)
            .field("route", &self.route)
            .field("busy", &self.op.is_some())
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

static SLOTS: IrqSafeSpinLock<Vec<Slot>> = IrqSafeSpinLock::new(Vec::new());
static ATTACHED: IrqSafeSpinLock<Vec<u32>> = IrqSafeSpinLock::new(Vec::new());

/// The DRM card of the probed Intel function.
fn card_for_bar(bar: &narf_bus::MmioRegion) -> Option<u32> {
    let (vendor, device) =
        crate::intel_gpu::with_display_info(|g| (g.gtt_mmadr.phys == bar.phys).then(|| g.pci_id()))
            .flatten()?;
    (0..crate::drm_registry::count() as u32).find(|&i| {
        crate::drm_registry::driver_name(i) == Some("intel-gpu")
            && crate::drm_registry::pci_id(i) == Some((vendor, device))
            && crate::drm_registry::mode_state(i).is_some()
    })
}

/// `drm_connector_attach_content_protection_property` on the card's
/// non-eDP DP, HDMI or firmware-display connectors, once per card.
fn attach(card: u32) {
    if ATTACHED.lock().contains(&card) {
        return;
    }
    let Some(mode) = crate::drm_registry::mode_state(card) else {
        return;
    };
    let mut new = Vec::new();
    {
        let mut kms = mode.lock();
        let ids: Vec<u32> = kms
            .connectors
            .iter()
            .filter(|c| {
                matches!(
                    c.connector_type,
                    ConnectorType::DisplayPort
                        | ConnectorType::HdmiA
                        | ConnectorType::HdmiB
                        | ConnectorType::Unknown
                )
            })
            .map(|c| c.id)
            .collect();
        for id in ids {
            if kms.content_protection(id).is_none() {
                kms.content_protection.push(ContentProtection {
                    connector: id,
                    value: CpValue::Undesired as u8,
                    content_type: Some(0),
                });
                new.push(id);
            }
        }
    }
    ATTACHED.lock().push(card);
    let mut slots = SLOTS.lock();
    for connector in new {
        slots.push(Slot {
            card,
            connector,
            uapi: Uapi {
                cp: CpValue::Undesired,
                content_type: 0,
            },
            dirty: false,
            route: None,
            link: None,
            op: None,
            next_check_ns: 0,
            last: None,
        });
    }
}

/// The DRM side changed a connector's uAPI values (legacy SETPROPERTY or
/// an atomic commit); the next service pass acts on them.
pub fn request(card: u32, connector: u32, value: u8, content_type: u8) {
    let Some(cp) = CpValue::from_u64(u64::from(value)) else {
        return;
    };
    let mut slots = SLOTS.lock();
    if let Some(s) = slots
        .iter_mut()
        .find(|s| s.card == card && s.connector == connector)
    {
        s.uapi = Uapi { cp, content_type };
        s.dirty = true;
    }
}

/// Write a driver-side flip into the card's uAPI state
/// (`drm_hdcp_update_content_protection`).
fn publish(card: u32, connector: u32, value: CpValue) {
    if let Some(mode) = crate::drm_registry::mode_state(card) {
        if let Some(cp) = mode
            .lock()
            .content_protection
            .iter_mut()
            .find(|c| c.connector == connector)
        {
            cp.value = value as u8;
        }
    }
}

fn start(kind: OpKind, mut link: HdcpLink, route: RouteDesc, content_type: u8) -> Op {
    Box::pin(async move {
        let Some(io) = crate::intel_gpu::with_display_info(|g| g.mode_window()) else {
            return OpDone {
                link,
                kind,
                result: Err(HdcpError::NoRoute),
            };
        };
        let mut env = LiveEnv { srm: load_srm() };
        let mut fw = firmware(route.display_ver);
        let result = match route.link {
            RouteLink::Dp(port) => {
                let mut shim = DpShim::new(AuxDpcd { io: &io, port });
                let mut cx = Ctx {
                    io: &io,
                    shim: &mut shim,
                    fw: fw.as_deref_mut(),
                    env: &mut env,
                };
                run(kind, &mut link, &mut cx, content_type).await
            }
            RouteLink::Hdmi(pin) => {
                let mut shim = HdmiShim::new(GmbusDdc { io: &io, pin });
                let mut cx = Ctx {
                    io: &io,
                    shim: &mut shim,
                    fw: fw.as_deref_mut(),
                    env: &mut env,
                };
                run(kind, &mut link, &mut cx, content_type).await
            }
        };
        OpDone { link, kind, result }
    })
}

/// One operation on the link.
async fn run<M, S, T, E>(
    kind: OpKind,
    link: &mut HdcpLink,
    cx: &mut Ctx<'_, M, S, T, E>,
    content_type: u8,
) -> Result<(), HdcpError>
where
    M: MmioWindow + Sync + ?Sized,
    S: hdcp::HdcpShim,
    T: HdcpTransport + ?Sized,
    E: HdcpEnv,
{
    match kind {
        OpKind::Enable => link.enable(cx, content_type).await,
        OpKind::Disable => link.disable(cx).await,
        OpKind::Retype => {
            let _ = link.disable(cx).await;
            link.value = CpValue::Desired;
            link.enable(cx, content_type).await
        }
        OpKind::Check => link.check_link(cx).await,
    }
}

fn poll_once(op: &mut Op) -> Poll<OpDone> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    op.as_mut().poll(&mut cx)
}

fn noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
    const RAW: RawWaker = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: every vtable entry ignores the null data pointer.
    unsafe { Waker::from_raw(RAW) }
}

/// A route on `key` is about to stop: drop its operation and put its HDCP
/// registers back to off before the transcoder goes down
/// (`intel_hdcp_disable` from encoder disable). An enabled connector goes
/// back to DESIRED (`intel_hdcp_atomic_check`'s CRTC-less rule) and
/// re-enables when a route returns. Inert without the option.
pub fn route_stopping<M: MmioWindow + ?Sized>(io: &M, key: u64) {
    if !enabled() {
        return;
    }
    let mut flips = Vec::new();
    {
        let mut slots = SLOTS.lock();
        for s in slots.iter_mut() {
            if s.route.map(|r| r.key) != Some(key) {
                continue;
            }
            // A dropped operation takes its link with it; the registers it
            // may have left on are the route's transcoder's either way.
            let cancelled = s.op.take().is_some();
            match (s.link.take(), s.route) {
                (Some(mut link), _) => {
                    link.force_off(io);
                }
                (None, Some(r)) if cancelled => {
                    HdcpLink::new(r.protocol, r.transcoder, r.rekey, true).force_off(io);
                }
                _ => {}
            }
            s.route = None;
            hdcp::route_lost(&mut s.uapi);
            flips.push((s.card, s.connector, s.uapi.cp));
        }
    }
    for (card, connector, value) in flips {
        publish(card, connector, value);
    }
}

/// [`route_stopping`] for the Gen12 route on `ddi`.
pub fn route_stopping_gen12<M: MmioWindow + ?Sized>(io: &M, ddi: Ddi) {
    route_stopping(io, gen12_key(ddi));
}

/// One service pass for the function on `bar`: attach the properties,
/// follow the route, advance the running operation, start the next one.
pub fn service(bar: &narf_bus::MmioRegion) {
    if !enabled() {
        return;
    }
    let Some(card) = card_for_bar(bar) else {
        return;
    };
    attach(card);
    // Route discovery (MMIO, and one AUX read for a firmware DP route)
    // only while some connector wants protection or still holds it.
    let wanted = SLOTS.lock().iter().any(|s| {
        s.card == card
            && (s.uapi.cp != CpValue::Undesired
                || s.op.is_some()
                || s.link
                    .as_ref()
                    .is_some_and(|l| l.value != CpValue::Undesired))
    });
    if !wanted {
        return;
    }
    let route = select(routes(bar));
    let count = SLOTS.lock().len();
    for i in 0..count {
        service_slot(i, card, route);
    }
}

fn service_slot(i: usize, card: u32, route: Result<Option<RouteDesc>, HdcpError>) {
    // 1. The running operation.
    let op = {
        let mut slots = SLOTS.lock();
        match slots.get_mut(i) {
            Some(s) if s.card == card => s.op.take(),
            _ => return,
        }
    };
    if let Some(mut op) = op {
        match poll_once(&mut op) {
            Poll::Pending => {
                if let Some(s) = SLOTS.lock().get_mut(i) {
                    s.op = Some(op);
                }
                return;
            }
            Poll::Ready(done) => finish(i, done),
        }
    }
    // 2. Route changes, then the next operation.
    let io = crate::intel_gpu::with_display_info(|g| g.mode_window());
    let flipped = {
        let mut slots = SLOTS.lock();
        let Some(s) = slots.get_mut(i) else {
            return;
        };
        let mut flip = None;
        let (current, error) = match route {
            Ok(r) => (r, None),
            Err(e) => (None, Some(e)),
        };
        let next: Option<(OpKind, RouteDesc)> = if s.route.map(|r| r.key) != current.map(|r| r.key)
        {
            if let Some(mut link) = s.link.take() {
                if let Some(io) = io.as_ref() {
                    link.force_off(io);
                }
                hdcp::route_lost(&mut s.uapi);
                flip = Some(s.uapi.cp);
            }
            s.route = current;
            s.last = error;
            match current {
                Some(r) => {
                    let link = HdcpLink::new(r.protocol, r.transcoder, r.rekey, true);
                    // intel_hdcp_enable at the route's encoder enable.
                    let enable = hdcp::enable_on_route(&link, s.uapi);
                    s.link = Some(link);
                    s.dirty = false;
                    enable.then_some((OpKind::Enable, r))
                }
                None => None,
            }
        } else if let (Some(r), Some(link)) = (s.route, s.link.as_ref()) {
            if s.dirty {
                s.dirty = false;
                match hdcp::update_pipe(link, s.uapi) {
                    Commit::Keep => None,
                    Commit::Report => {
                        if hdcp::report(&mut s.uapi, link.value) {
                            flip = Some(s.uapi.cp);
                        }
                        None
                    }
                    Commit::Disable => Some((OpKind::Disable, r)),
                    Commit::Enable {
                        disable_first: true,
                    } => Some((OpKind::Retype, r)),
                    Commit::Enable { .. } => Some((OpKind::Enable, r)),
                }
            } else if link.value == CpValue::Enabled && narf_time::monotonic_ns() >= s.next_check_ns
            {
                Some((OpKind::Check, r))
            } else {
                None
            }
        } else {
            None
        };
        if let Some((kind, r)) = next {
            if let Some(link) = s.link.take() {
                if kind == OpKind::Retype && hdcp::report(&mut s.uapi, CpValue::Desired) {
                    // The type change's DESIRED reaches userspace first.
                    flip = Some(s.uapi.cp);
                }
                s.op = Some(start(kind, link, r, s.uapi.content_type));
            }
        }
        flip.map(|v| (s.card, s.connector, v))
    };
    if let Some((card, connector, value)) = flipped {
        publish(card, connector, value);
    }
}

/// An operation ended: keep its link, schedule the next check, report the
/// DESIRED/ENABLED flip.
fn finish(i: usize, done: OpDone) {
    let flip = {
        let mut slots = SLOTS.lock();
        let Some(s) = slots.get_mut(i) else {
            return;
        };
        let now = narf_time::monotonic_ns();
        if let (Ok(()), OpKind::Enable | OpKind::Retype | OpKind::Check) =
            (&done.result, done.kind)
        {
            s.next_check_ns = now + done.link.check_period_ms() * 1_000_000;
        }
        s.last = done.result.err();
        let changed = hdcp::report(&mut s.uapi, done.link.value);
        s.link = Some(done.link);
        changed.then_some((s.card, s.connector, s.uapi.cp))
    };
    if let Some((card, connector, value)) = flip {
        publish(card, connector, value);
    }
}

/// The last refusal or failure on `connector` of `card`, for diagnostics.
pub fn last_error(card: u32, connector: u32) -> Option<HdcpError> {
    SLOTS
        .lock()
        .iter()
        .find(|s| s.card == card && s.connector == connector)
        .and_then(|s| s.last)
}

/// Test-only: queue a framed command for the GSC worker as the GSC
/// transport does; returns its ticket.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn __gsc_post_for_test(input: Vec<u8>, out_len: usize) -> u64 {
    let ticket = GSC_TICKET.fetch_add(1, Ordering::Relaxed);
    *GSC.lock() = GscSlot::Request {
        ticket,
        input,
        out_len,
    };
    ticket
}

/// Test-only: take `ticket`'s completion, if the worker finished it.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn __gsc_result_for_test(ticket: u64) -> Option<Result<Vec<u8>, i32>> {
    let mut slot = GSC.lock();
    match core::mem::replace(&mut *slot, GscSlot::Idle) {
        GscSlot::Done { ticket: t, result } if t == ticket => Some(result),
        other => {
            *slot = other;
            None
        }
    }
}

#[doc(hidden)]
/// Test-only: how many connectors carry the properties.
pub fn __connector_count() -> usize {
    SLOTS.lock().len()
}

#[doc(hidden)]
/// Test-only: forget every connector and the GSC mailbox.
pub fn __reset_for_test() {
    SLOTS.lock().clear();
    ATTACHED.lock().clear();
    *GSC.lock() = GscSlot::Idle;
    GSC_READY.store(false, Ordering::Release);
}
