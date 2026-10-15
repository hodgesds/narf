//! Native DCN401 8b/10b MST stream allocation, as Linux's
//! allocate_mst_payload programs the source:
//! dcn10_link_encoder_update_mst_stream_allocation_table (the link's VC
//! payload table, then the allocation change trigger) and
//! enc1_stream_encoder_set_throttled_vcp_size (each stream's VC rate in
//! time slots per MTP). The sink side (payload table DPCD, ACT handled,
//! ALLOCATE_PAYLOAD) belongs to the MST manager.
use super::*;
use crate::amdgpu_dsc::Fixed;

/// DP_MSE_SAT0/1 and DP_MSE_SAT_UPDATE in the link's DP block.
const SAT0: u64 = 0x2150;
const SAT1: u64 = 0x2151;
const SAT_UPDATE: u64 = 0x2153;
/// DP_MSE_RATE_CNTL and DP_MSE_RATE_UPDATE in the stream's DP block.
const RATE_CNTL: u64 = 0x214d;
const RATE_UPDATE: u64 = 0x214f;
/// DP_MST_UPDATE_MAX_RETRY polls, 10 us apart.
const UPDATE_RETRIES: u32 = 50;

/// One VC payload: the DIO stream encoder (engine id) and its time slots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MstAllocation {
    pub stream: u8,
    pub slots: u8,
}

/// allocate_mst_payload's average time slots per MTP for a stream of
/// `stream_kbps` (dc_bandwidth_in_kbps_from_timing) on a link of
/// `link_kbps` (dp_link_bandwidth_kbps), as DP_MSE_RATE X.Y:
/// get_pbn_from_bw_in_kbps over get_pbn_per_slot, then
/// enc1_stream_encoder_set_throttled_vcp_size's split with Y in 26 bits.
pub fn vc_rate(stream_kbps: u32, link_kbps: u32) -> Option<(u32, u32)> {
    let per_slot = Fixed::int((link_kbps / 8000) as i32).div_int(54);
    if per_slot.0 == 0 {
        return None;
    }
    let pbn = Fixed::fraction(i64::from(stream_kbps) * 64, 54 * 8 * 1000);
    let avg = pbn.div(per_slot);
    let mut x = avg.floor() as u32;
    let mut y = Fixed(avg.sub_int(x as i32).0 << 26).ceil() as u32;
    if y >> 26 != 0 {
        x += 1;
        y = 0;
    }
    Some((x, y))
}

impl<I: Io> Engine<I> {
    /// Attach the selected display to the running 8b/10b MST link on
    /// `transmitter` that another display trained (Linux's MST streams
    /// share their link's encoder): its link record is copied, so this
    /// display's frontend, video and allocation work on it, but never
    /// trains or stops it.
    pub(in crate::amdgpu_dcn401_otg) fn attach_mst_link(
        &mut self,
        transmitter: u8,
    ) -> Result<DpLinkTrained, Error> {
        if !self.status.state.reusable() || self.status.mst_owner.is_some() {
            return Err(Error::Busy);
        }
        let selected = self.displays.selected;
        let (owner, link) = (0..4u8)
            .filter(|&k| k != selected)
            .find_map(|k| {
                let s = &self.displays.parked[usize::from(k)];
                let link = s.dp_video_running?.frontend.link;
                (s.mst_owner.is_none()
                    && link.phy.settings.mst
                    && link.phy.path.transmitter == transmitter)
                    .then_some((k, link))
            })
            .ok_or(Error::Invalid)?;
        if self.displays.siblings.mst & bit(transmitter) == 0 {
            return Err(Error::Invalid);
        }
        // The owner's link as it runs, minus its frontend's selection.
        let mut link = link;
        link.phy.controls[1] &= !0x7f00;
        self.status.dp_link_trained = Some(link);
        self.status.mst_owner = Some(owner);
        self.status.state = State::DpLinkTrained(transmitter);
        if let Err(e) = self.dp_training_verify(link) {
            self.status.dp_link_trained = None;
            self.status.mst_owner = None;
            self.status.state = State::Ready;
            return Err(e);
        }
        Ok(link)
    }
    /// Detach the selected display from the MST link it rides; its stream
    /// must be stopped. The link keeps running for its owner.
    pub(in crate::amdgpu_dcn401_otg) fn detach_mst_link(
        &mut self,
        transmitter: u8,
    ) -> Result<(), Error> {
        if self.status.state != State::DpLinkTrained(transmitter) || self.status.mst_owner.is_none()
        {
            return Err(Error::Busy);
        }
        self.status.dp_link_trained = None;
        self.status.mst_owner = None;
        self.status.state = State::Ready;
        Ok(())
    }
    /// Hand the MST link on `transmitter`, which the selected display
    /// trained and no longer streams on (its frontend stopped), to
    /// display `to`, attached to it: `to` owns it from now on, the other
    /// attached displays ride `to`'s link, and the selected display lets it
    /// go, the link left running (Linux's link outlives any one stream).
    pub(in crate::amdgpu_dcn401_otg) fn hand_over_mst_link(
        &mut self,
        transmitter: u8,
        to: u8,
    ) -> Result<(), Error> {
        let selected = self.displays.selected;
        let ours = self
            .status
            .dp_link_trained
            .is_some_and(|l| l.phy.settings.mst && l.phy.path.transmitter == transmitter);
        if self.status.state != State::DpLinkTrained(transmitter)
            || self.status.mst_owner.is_some()
            || !ours
        {
            return Err(Error::Busy);
        }
        if to == selected
            || self
                .displays
                .parked
                .get(usize::from(to))
                .is_none_or(|s| s.mst_owner != Some(selected))
        {
            return Err(Error::Invalid);
        }
        for (k, s) in self.displays.parked.iter_mut().enumerate() {
            if k != usize::from(selected) && s.mst_owner == Some(selected) {
                s.mst_owner = (k != usize::from(to)).then_some(to);
            }
        }
        self.status.dp_link_trained = None;
        self.status.state = State::Ready;
        Ok(())
    }
    /// The trained MST link of the selected display on `transmitter`.
    fn mst_link(&self, transmitter: u8) -> Result<DpLinkTrained, Error> {
        let link = self.status.dp_link_trained.ok_or(Error::Invalid)?;
        let live = matches!(
            self.status.state,
            State::DpLinkTrained(t) if t == transmitter
        ) || matches!(
            self.status.state,
            State::DpFrontendReady(_) | State::DpVideoRunning(_)
        );
        if link.phy.path.transmitter != transmitter || !link.phy.settings.mst || !live {
            return Err(Error::Busy);
        }
        Ok(link)
    }
    /// dcn10_link_encoder_update_mst_stream_allocation_table: the first
    /// four payloads into SAT0/SAT1 (source, slot count; the rest
    /// cleared), then SAT_UPDATE 1 (update with ACT) and the wait for it
    /// and the 16-MTP keepout to clear. Like Linux, a wait that runs out
    /// is not an error.
    pub(in crate::amdgpu_dcn401_otg) async fn update_mst_allocation(
        &mut self,
        transmitter: u8,
        table: &[MstAllocation],
    ) -> Result<(), Error> {
        self.mst_link(transmitter)?;
        let total: u32 = table.iter().map(|a| u32::from(a.slots)).sum();
        if table.len() > 4 || total > 63 || table.iter().any(|a| a.stream >= 4 || a.slots > 63) {
            return Err(Error::Invalid);
        }
        let l = self.layout;
        let at = |r| DpStream::Dio(transmitter).at(l, r);
        let row = |i: usize| {
            table
                .get(i)
                .map_or(0, |a| u32::from(a.stream) | u32::from(a.slots) << 8)
        };
        self.update(at(SAT0), 0x3f07_3f07, row(0) | row(1) << 16)?;
        self.update(at(SAT1), 0x3f07_3f07, row(2) | row(3) << 16)?;
        self.update_trigger(at(SAT_UPDATE))?;
        for _ in 0..UPDATE_RETRIES {
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
            if self.read(at(SAT_UPDATE))? & 0x103 == 0 {
                break;
            }
        }
        Ok(())
    }
    /// SAT_UPDATE 1: a trigger the hardware clears, so no readback.
    fn update_trigger(&mut self, at: u64) -> Result<(), Error> {
        self.access(|io| {
            let old = checked(io.read(at))?;
            io.write(at, (old & !3) | 1);
            Ok(())
        })
    }
    /// enc1_stream_encoder_set_throttled_vcp_size on DIO stream `stream`
    /// of the selected display's MST link, then the wait for the rate
    /// update to leave pending (10 us x 50; REG_WAIT only logs a timeout).
    pub(in crate::amdgpu_dcn401_otg) async fn set_mst_vc_rate(
        &mut self,
        transmitter: u8,
        stream: u8,
        (x, y): (u32, u32),
    ) -> Result<(), Error> {
        self.mst_link(transmitter)?;
        if stream >= 4 || x > 63 || y >> 26 != 0 {
            return Err(Error::Invalid);
        }
        let l = self.layout;
        let at = |r| DpStream::Dio(stream).at(l, r);
        self.update(at(RATE_CNTL), u32::MAX, x << 26 | y)?;
        for _ in 0..UPDATE_RETRIES {
            if self.read(at(RATE_UPDATE))? & 1 == 0 {
                break;
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
        }
        Ok(())
    }
}
impl Otg {
    /// Program the selected display's MST link's VC payload table and
    /// trigger ACT.
    /// # Safety
    /// The table must match the sink's payload table (the MST manager's
    /// DPCD writes); exclude other writers of the link.
    pub(crate) async unsafe fn update_mst_allocation(
        &mut self,
        transmitter: u8,
        table: &[MstAllocation],
    ) -> Result<(), Error> {
        self.0.update_mst_allocation(transmitter, table).await
    }
    /// Set DIO stream `stream`'s VC rate on the selected display's MST
    /// link.
    /// # Safety
    /// As for `update_mst_allocation`; `stream` carries a payload in it.
    pub(crate) async unsafe fn set_mst_vc_rate(
        &mut self,
        transmitter: u8,
        stream: u8,
        rate: (u32, u32),
    ) -> Result<(), Error> {
        self.0.set_mst_vc_rate(transmitter, stream, rate).await
    }
}
impl Otg {
    /// Attach the selected display to the running MST link on
    /// `transmitter` another display trained.
    /// # Safety
    /// The MST manager allocates this display's payload on the link; the
    /// owner keeps the link running until this display detaches.
    pub(crate) unsafe fn attach_mst_link(
        &mut self,
        transmitter: u8,
    ) -> Result<DpLinkTrained, Error> {
        self.0.attach_mst_link(transmitter)
    }
    /// Hand the selected display's MST link on to display `to`.
    /// # Safety
    /// `to` keeps the link running; the MST manager's state follows.
    pub(crate) unsafe fn hand_over_mst_link(
        &mut self,
        transmitter: u8,
        to: u8,
    ) -> Result<(), Error> {
        self.0.hand_over_mst_link(transmitter, to)
    }
    /// Detach the selected display, its stream stopped, from its MST link.
    pub(crate) fn detach_mst_link(&mut self, transmitter: u8) -> Result<(), Error> {
        self.0.detach_mst_link(transmitter)
    }
}
