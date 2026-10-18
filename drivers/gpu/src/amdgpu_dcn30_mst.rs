//! Navi22 DCN3.0 DisplayPort MST over 8b/10b on the DIO: one link trained
//! in MST mode carries up to four streams, each from its own DIG frontend,
//! as Linux's `link_set_dpms_on` → `allocate_mst_payload` and
//! `link_set_dpms_off` → `deallocate_mst_payload` drive DC and DRM's MST
//! helpers:
//!
//! - the source side: `dcn10_link_encoder_update_mst_stream_allocation_table`
//!   (the link's VC payload table `DP_MSE_SAT0/1`, then the allocation
//!   change trigger, waiting out the 16-MTP keepout) and
//!   `enc1_stream_encoder_set_throttled_vcp_size` (the stream's VC rate in
//!   time slots per MTP, `DP_MSE_RATE_CNTL`);
//! - the sink side over the shared [`crate::dp_mst_mgr`]: the payload table
//!   entry (`drm_dp_add_payload_part1`), ACT handled
//!   (`drm_dp_check_act_status`) and ALLOCATE_PAYLOAD to the end device's
//!   branch (`drm_dp_add_payload_part2`), and their removal.
//!
//! Offsets are `dcn_3_0_0_offset.h` at DCN base index 2 (DP0..DP5, stride
//! 0x100); the SAT lives in the transmitter's DP block, the VC rate in the
//! frontend's. Scope: one branch tree on one connector, RGB 8 bpc, no DSC
//! over MST.
use crate::{
    amdgpu_dcn30_dp::Aux,
    amdgpu_dcn30_takeover::Regs,
    amdgpu_navi22_modeset::Error,
    dp_mst::{Reply, Request},
    dp_mst_mgr::{self, Manager, MstAux, MstError, Topology},
};
use alloc::vec::Vec;

const STRIDE: u64 = 0x100; // linux: mmDP1_DP_MSE_RATE_CNTL - mmDP0_DP_MSE_RATE_CNTL
const DP_MSE_RATE_CNTL: u64 = 0x2137; // linux: mmDP0_DP_MSE_RATE_CNTL
const DP_MSE_RATE_Y: u32 = 0x03ff_ffff; // linux: DP0_DP_MSE_RATE_CNTL__DP_MSE_RATE_Y_MASK
const DP_MSE_RATE_X_SHIFT: u32 = 26; // linux: DP0_DP_MSE_RATE_CNTL__DP_MSE_RATE_X__SHIFT
const DP_MSE_RATE_UPDATE: u64 = 0x2139; // linux: mmDP0_DP_MSE_RATE_UPDATE
const DP_MSE_RATE_UPDATE_PENDING: u32 = 1 << 0; // linux: DP0_DP_MSE_RATE_UPDATE__DP_MSE_RATE_UPDATE_PENDING_MASK
const DP_MSE_SAT0: u64 = 0x213a; // linux: mmDP0_DP_MSE_SAT0
const DP_MSE_SAT1: u64 = 0x213b; // linux: mmDP0_DP_MSE_SAT1
const DP_MSE_SAT_UPDATE: u64 = 0x213d; // linux: mmDP0_DP_MSE_SAT_UPDATE
const SAT_UPDATE: u32 = 0x3; // linux: DP0_DP_MSE_SAT_UPDATE__DP_MSE_SAT_UPDATE_MASK
const SAT_16_MTP_KEEPOUT: u32 = 1 << 8; // linux: DP0_DP_MSE_SAT_UPDATE__DP_MSE_16_MTP_KEEPOUT_MASK
/// `DP_MST_UPDATE_MAX_RETRY` polls, 10 us apart.
const UPDATE_RETRIES: u32 = 50; // linux: n/a (DP_MST_UPDATE_MAX_RETRY, dcn10_link_encoder.c)
/// The highest dword this module touches, for the bank bound.
pub(crate) const LAST_REG: u32 = (DP_MSE_SAT_UPDATE + 5 * STRIDE) as u32;
/// `DP_PAYLOAD_ACT_HANDLED` in `DP_PAYLOAD_TABLE_UPDATE_STATUS`.
const ACT_HANDLED: u8 = 2; // linux: DP_PAYLOAD_ACT_HANDLED
/// Streams the DIO SAT holds.
pub const MAX_STREAMS: usize = 4; // linux: n/a (four DP_MSE_SAT rows)
/// `DP_MST_TOTAL_SLOTS` less the 8b/10b MTP header slot.
pub const SLOTS: u8 = 63; // linux: n/a (DP_MST total 64 slots less the MTP header)

/// One VC payload as the source's table holds it: the DIG frontend (DC's
/// `stream_enc->id`, ENGINE_ID_DIGA + n) and its time slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    pub stream: u8,
    pub slots: u8,
}

/// The MST registers of the DIO blocks.
#[derive(Clone, Copy, Debug)]
pub struct Source {
    regs: Regs,
    dcn2: u64,
}
impl Source {
    pub(crate) fn new(regs: Regs, dcn2: u64) -> Self {
        Self { regs, dcn2 }
    }
    fn reg(&self, block: u8, r: u64) -> u64 {
        self.dcn2 + (r + u64::from(block) * STRIDE) * 4
    }
    /// `dcn10_link_encoder_update_mst_stream_allocation_table` on
    /// `transmitter`'s link: rows 0..3 (unused rows source 0, no slots),
    /// the update with trigger, then up to 50 polls 10 us apart for the
    /// update to land and the 16-MTP keepout to pass. Linux carries on
    /// after the polls; so does this.
    pub async fn allocation(&mut self, transmitter: u8, table: &[Allocation]) -> Result<(), Error> {
        if transmitter >= 6 || table.len() > MAX_STREAMS {
            return Err(Error::Invalid);
        }
        let row = |n: usize| {
            table.get(n).map_or(0, |a| {
                u32::from(a.stream) & 0x7 | (u32::from(a.slots) & 0x3f) << 8
            })
        };
        if table.iter().any(|a| a.stream >= 6 || a.slots > SLOTS) {
            return Err(Error::Invalid);
        }
        let (sat0, sat1) = (
            self.reg(transmitter, DP_MSE_SAT0),
            self.reg(transmitter, DP_MSE_SAT1),
        );
        self.regs.update(sat0, 0x3f07_3f07, row(0) | row(1) << 16)?;
        self.regs.update(sat1, 0x3f07_3f07, row(2) | row(3) << 16)?;
        let update = self.reg(transmitter, DP_MSE_SAT_UPDATE);
        self.regs.update(update, SAT_UPDATE, 1)?;
        for _ in 0..UPDATE_RETRIES {
            sleep_us(10).await;
            if self.regs.read(update)? & (SAT_UPDATE | SAT_16_MTP_KEEPOUT) == 0 {
                break;
            }
        }
        Ok(())
    }
    /// `enc1_stream_encoder_set_throttled_vcp_size` on frontend `fe`: X.Y
    /// time slots per MTP (Y in 1/2^26), then up to 50 polls 10 us apart
    /// for the rate to reach the link.
    pub async fn vc_rate(&mut self, fe: u8, rate: (u32, u32)) -> Result<(), Error> {
        let (x, y) = rate;
        if fe >= 6 || x > 0x3f || y > DP_MSE_RATE_Y {
            return Err(Error::Invalid);
        }
        let cntl = self.reg(fe, DP_MSE_RATE_CNTL);
        self.regs.write(cntl, y | x << DP_MSE_RATE_X_SHIFT)?;
        let update = self.reg(fe, DP_MSE_RATE_UPDATE);
        self.regs
            .wait(update, DP_MSE_RATE_UPDATE_PENDING, 0, 10, UPDATE_RETRIES)
            .await?;
        Ok(())
    }
}

async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

/// The connector's native AUX as the MST manager's DPCD transport.
pub struct NativeAux<'a, A: Aux>(pub &'a mut A);
impl<A: Aux> core::fmt::Debug for NativeAux<'_, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeAux")
    }
}
impl<A: Aux + Send> MstAux for NativeAux<'_, A> {
    type Error = Error;
    async fn read(&mut self, address: u32, buf: &mut [u8]) -> Result<(), Error> {
        for (i, piece) in buf.chunks_mut(16).enumerate() {
            self.0.read(address + 16 * i as u32, piece).await?;
        }
        Ok(())
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Error> {
        for (i, piece) in data.chunks(16).enumerate() {
            self.0.write(address + 16 * i as u32, piece).await?;
        }
        Ok(())
    }
    async fn delay(&mut self, us: u64) {
        sleep_us(us).await;
    }
}

/// One stream's VC payload on the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payload {
    pub sink: dp_mst_mgr::Sink,
    /// VCPI (1..=63), the lowest free.
    pub vcpi: u8,
    pub start: u8,
    pub slots: u8,
    pub pbn: u16,
    /// DIG frontend carrying it.
    pub stream: u8,
}

/// A payload change that started and has not finished; retained after an
/// error or cancellation and refusing further changes. Never replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Adding(u8),
    Removing(u8),
}

/// The MST session of one connector: manager, topology and payloads.
#[derive(Debug, Default)]
pub struct Link {
    pub manager: Manager,
    pub topology: Topology,
    pub payloads: Vec<Payload>,
    change: Option<Change>,
}

/// The PBN, time slots and VC rate of an 8-bpc RGB stream at `pixel_khz` on
/// an 8b/10b link of `link_kbps` (`dc_link_bandwidth_kbps`):
/// `drm_dp_calc_pbn_mode`, `dm_mst_get_pbn_divider` and
/// `drm_dp_atomic_find_time_slots`, and the source's X.Y
/// (`get_pbn_per_slot` / `enc1_stream_encoder_set_throttled_vcp_size`).
/// None past the link's 63 slots.
pub fn budget(pixel_khz: u32, link_kbps: u32) -> Option<(u16, u8, (u32, u32))> {
    let pbn = crate::dp_mst::calc_pbn_mode(pixel_khz, 24 * 16);
    let div = crate::dp_mst::pbn_div(link_kbps);
    if div == 0 || pbn > u32::from(u16::MAX) {
        return None;
    }
    let slots = crate::dp_mst::time_slots(pbn, div);
    if slots == 0 || slots > u32::from(SLOTS) {
        return None;
    }
    let rate = crate::amdgpu_dcn401_otg::vc_rate(pixel_khz.checked_mul(24)?, link_kbps)?;
    Some((pbn as u16, slots as u8, rate))
}

/// `dc_link_bandwidth_kbps` of an 8b/10b link: rate code x 27 MHz x 8 bits
/// per lane, less FEC's 3% when it runs.
pub fn link_kbps(rate: u8, lanes: u8, fec: bool) -> u32 {
    let efficiency = if fec { 8000 / 100 * 97 } else { 8000 };
    (u64::from(rate) * 27_000 * 10 * u64::from(lanes) / 10_000 * efficiency) as u32
}

fn mst<E>(e: MstError<E>) -> Error
where
    Error: From<E>,
{
    match e {
        MstError::Aux(e) => e.into(),
        _ => Error::Aux,
    }
}

/// `drm_dp_check_act_status`: up to 3 s for ACT handled, 200 us apart.
async fn act_handled<A: MstAux<Error = Error>>(aux: &mut A) -> Result<(), Error> {
    for _ in 0..15_000 {
        let mut status = [0];
        aux.read(dp_mst_mgr::PAYLOAD_TABLE_UPDATE_STATUS, &mut status)
            .await?;
        if status[0] & ACT_HANDLED != 0 {
            return Ok(());
        }
        aux.delay(200).await;
    }
    Err(Error::Aux)
}

impl Link {
    /// The change in flight, if one never completed.
    pub fn change(&self) -> Option<Change> {
        self.change
    }
    /// `drm_dp_mst_topology_mgr_set_mst(true)` then the link probe.
    pub async fn start<A: MstAux<Error = Error>>(
        &mut self,
        aux: &mut A,
        dpcd: &[u8; 16],
    ) -> Result<(), Error> {
        self.manager.start(aux, dpcd).await.map_err(mst)?;
        self.topology = self.manager.probe(aux).await.map_err(mst)?;
        Ok(())
    }
    /// The source's table: every payload by start slot.
    fn table(&self) -> Vec<Allocation> {
        let mut p: Vec<&Payload> = self.payloads.iter().collect();
        p.sort_by_key(|x| x.start);
        p.iter()
            .map(|x| Allocation {
                stream: x.stream,
                slots: x.slots,
            })
            .collect()
    }
    /// `allocate_mst_payload` for frontend `stream` to `sink` on
    /// `transmitter`'s link: the lowest free VCPI at the next start slot
    /// (`drm_dp_add_payload_part1`: the payload table entry), the source
    /// table with ACT, ACT handled, ALLOCATE_PAYLOAD to the sink's branch
    /// (`drm_dp_add_payload_part2`), then the stream's VC rate.
    #[allow(clippy::too_many_arguments)]
    pub async fn add<A: MstAux<Error = Error>>(
        &mut self,
        aux: &mut A,
        source: &mut Source,
        transmitter: u8,
        sink: dp_mst_mgr::Sink,
        stream: u8,
        pbn: u16,
        slots: u8,
        rate: (u32, u32),
    ) -> Result<Payload, Error> {
        if self.change.is_some() {
            return Err(Error::Busy);
        }
        let port = self.topology.port(sink).copied().ok_or(Error::Invalid)?;
        let branch = self
            .topology
            .branches
            .get(sink.branch)
            .cloned()
            .ok_or(Error::Invalid)?;
        let used: u32 = self.payloads.iter().map(|p| u32::from(p.slots)).sum();
        if pbn == 0
            || slots == 0
            || pbn > port.available_pbn
            || self.payloads.len() >= MAX_STREAMS
            || self
                .payloads
                .iter()
                .any(|p| p.stream == stream || p.sink == sink)
            || used + u32::from(slots) > u32::from(SLOTS)
        {
            return Err(Error::Invalid);
        }
        let vcpi = (1..=63u8)
            .find(|v| self.payloads.iter().all(|p| p.vcpi != *v))
            .ok_or(Error::Invalid)?;
        let payload = Payload {
            sink,
            vcpi,
            start: 1 + used as u8,
            slots,
            pbn,
            stream,
        };
        // Recorded before the first sink write: a failure or a dropped future
        // may leave the receiver ahead of this bookkeeping.
        self.change = Some(Change::Adding(stream));
        dp_mst_mgr::write_payload(aux, vcpi, payload.start, slots)
            .await
            .map_err(mst)?;
        self.payloads.push(payload);
        source.allocation(transmitter, &self.table()).await?;
        act_handled(aux).await?;
        let request = Request::AllocatePayload {
            port: port.info.port,
            vcpi,
            pbn,
            sdp_stream_sinks: (0..port.info.sdp_streams).collect(),
        };
        match self
            .manager
            .transact(aux, branch.lct, &branch.rad, &request)
            .await
            .map_err(mst)?
        {
            Reply::AllocatePayload { .. } => {}
            _ => return Err(Error::Aux),
        }
        source.vc_rate(stream, rate).await?;
        self.change = None;
        Ok(payload)
    }
    /// `deallocate_mst_payload` for frontend `stream`: VC rate zero, the
    /// branch's and the sink table's allocation removed
    /// (`drm_dp_remove_payload_part1`, failures tolerated as Linux does),
    /// the source table without it and ACT (unchecked), later payloads
    /// moved down (`drm_dp_remove_payload_part2`). `connected` is false for
    /// a sink already gone: nothing is sent to it.
    pub async fn remove<A: MstAux<Error = Error>>(
        &mut self,
        aux: &mut A,
        source: &mut Source,
        transmitter: u8,
        stream: u8,
        connected: bool,
    ) -> Result<(), Error> {
        if self.change.is_some() {
            return Err(Error::Busy);
        }
        let index = self
            .payloads
            .iter()
            .position(|p| p.stream == stream)
            .ok_or(Error::Invalid)?;
        let payload = self.payloads[index];
        self.change = Some(Change::Removing(stream));
        source.vc_rate(stream, (0, 0)).await?;
        if connected {
            if let (Some(branch), Some(port)) = (
                self.topology.branches.get(payload.sink.branch).cloned(),
                self.topology.port(payload.sink).copied(),
            ) {
                let request = Request::AllocatePayload {
                    port: port.info.port,
                    vcpi: payload.vcpi,
                    pbn: 0,
                    sdp_stream_sinks: (0..port.info.sdp_streams).collect(),
                };
                let _ = self
                    .manager
                    .transact(aux, branch.lct, &branch.rad, &request)
                    .await;
            }
            let _ = dp_mst_mgr::write_payload(aux, payload.vcpi, payload.start, 0).await;
        }
        self.payloads.remove(index);
        source.allocation(transmitter, &self.table()).await?;
        if connected {
            let _ = act_handled(aux).await;
        }
        for p in self.payloads.iter_mut().filter(|p| p.start > payload.start) {
            p.start -= payload.slots;
        }
        self.change = None;
        Ok(())
    }
    /// Read end device `sink`'s EDID base block and its first extension.
    pub async fn edid<A: MstAux<Error = Error>>(
        &mut self,
        aux: &mut A,
        sink: dp_mst_mgr::Sink,
    ) -> Result<Vec<u8>, Error> {
        let base = self
            .manager
            .read_edid_block(aux, &self.topology, sink, 0)
            .await
            .map_err(mst)?;
        let mut out = Vec::new();
        out.try_reserve_exact(256).map_err(|_| Error::Allocation)?;
        out.extend_from_slice(&base);
        if base[126] != 0 {
            let ext = self
                .manager
                .read_edid_block(aux, &self.topology, sink, 1)
                .await
                .map_err(mst)?;
            out.extend_from_slice(&ext);
        }
        Ok(out)
    }
    /// `drm_dp_mst_topology_mgr_set_mst(false)`.
    pub async fn stop<A: MstAux<Error = Error>>(&mut self, aux: &mut A) {
        self.manager.stop(aux).await;
        self.payloads.clear();
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_mst_tests.rs"]
mod tests;
