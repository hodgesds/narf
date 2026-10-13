//! Native DCN401 hot-plug sense and live legacy DP link status.
//! Linux: the HPD GPIO opened in interrupt mode (hw_gpio.c clears the pad
//! MASK so the HPD block owns the pin) and dcn10_link_encoder_enable_hpd;
//! dal_hw_hpd_get_value then reads DC_HPD_SENSE_DELAYED. Link loss follows
//! dp_parse_link_loss_status: every trained lane keeps CR, EQ and symbol
//! lock with interlane alignment, and only a D0 sink counts as lost.
use super::*;

const HPD_INT_STATUS: u64 = 0x175a;
const HPD_INT_CONTROL: u64 = 0x175b;
const HPD_CONTROL: u64 = 0x175c;
const HPD_INT_PENDING: u32 = 1;
const HPD_RX_INT_PENDING: u32 = 0x100;
const HPD_INT_ACK: u32 = 1;
const HPD_INT_POLARITY: u32 = 0x100;
const HPD_INT_EN: u32 = 0x1_0000;
const HPD_RX_INT_ACK: u32 = 0x10_0000;
const HPD_RX_INT_EN: u32 = 0x100_0000;
const HPD_STRIDE: u64 = 8;
const HPD_SENSE_DELAYED: u32 = 0x10;
const HPD_EN: u32 = 0x1000_0000;
const GPIO_HPD_MASK: u64 = 0x28f4;
/// DC_GPIO_HPD_MASK bit of GPIO_HPD_1..4, the pins DCN401's four HPD blocks
/// (HPD0..HPD3) serve; the board path's one-based selector names the pin.
const PAD_MASK: [u32; 4] = [0x1, 0x100, 0x1_0000, 0x10_0000];

/// Sink-side status of a live link: DPCD LANE0_1_STATUS..ADJUST_REQUEST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpLinkStatus {
    pub lanes: [u8; 6],
    /// Every trained lane holds CR, EQ and symbol lock, interlane aligned.
    pub locked: bool,
    /// SET_POWER, read only when the link is not locked.
    pub power: Option<u8>,
}
impl DpLinkStatus {
    /// Linux's retrain condition: lock dropped while the sink is in D0.
    pub fn lost(self) -> bool {
        !self.locked && self.power.is_some_and(|p| p & 7 == 1)
    }
}

fn hpd_block(path: Path) -> Result<usize, Error> {
    usize::from(path.hpd)
        .checked_sub(1)
        .filter(|&n| n < PAD_MASK.len())
        .ok_or(Error::Unsupported)
}
fn link_locked(status: [u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| lane_bits(status, l) & 7 == 7) && status[2] & 1 != 0
}

impl<I: Io> Engine<I> {
    fn hpd_at(&self, n: usize, reg: u64) -> u64 {
        self.layout.base + (reg + n as u64 * HPD_STRIDE) * 4
    }
    fn hpd_pad(&self) -> u64 {
        self.layout.base + GPIO_HPD_MASK * 4
    }
    /// Give the connector's pin to its HPD block and enable the block. Touches
    /// no pipe, stream or link state.
    pub(in crate::amdgpu_dcn401_otg) fn enable_hpd(&mut self, path: Path) -> Result<(), Error> {
        let n = hpd_block(path)?;
        let (pad, control) = (self.hpd_pad(), self.hpd_at(n, HPD_CONTROL));
        self.update(pad, PAD_MASK[n], 0)?;
        self.update(control, HPD_EN, HPD_EN)?;
        if self.read(pad)? & PAD_MASK[n] != 0 {
            return Err(Error::Readback(pad));
        }
        if self.read(control)? & HPD_EN == 0 {
            return Err(Error::Readback(control));
        }
        Ok(())
    }
    /// Linux hpd0_ack: strobe the acknowledgement, then point the interrupt
    /// polarity away from the current debounced sense so the next edge (an
    /// unplug while connected, a plug while not) raises it again.
    fn hpd_ack(&mut self, n: usize) -> Result<bool, Error> {
        let control = self.hpd_at(n, HPD_INT_CONTROL);
        let sense = self.read(self.hpd_at(n, HPD_INT_STATUS))? & HPD_SENSE_DELAYED != 0;
        let value = self.read(control)?;
        // The acknowledgement is a strobe, not state: no readback.
        self.access(|io| {
            io.write(control, value | HPD_INT_ACK);
            Ok(())
        })?;
        self.update(
            control,
            HPD_INT_POLARITY,
            if sense { 0 } else { HPD_INT_POLARITY },
        )?;
        Ok(sense)
    }
    /// Arm the HPD interrupt of a routed, enabled block (and the HPD-RX
    /// short-pulse one for DP), as amdgpu_dm_hpd_init does through
    /// dc_interrupt_set: a stale event is acknowledged and the polarity set
    /// from the current sense first, so the first vector is a real change.
    pub(in crate::amdgpu_dcn401_otg) fn enable_hpd_irq(
        &mut self,
        path: Path,
        rx: bool,
    ) -> Result<(), Error> {
        self.hpd_sense(path)?;
        let n = hpd_block(path)?;
        self.hpd_ack(n)?;
        let enable = HPD_INT_EN | if rx { HPD_RX_INT_EN } else { 0 };
        if rx {
            let control = self.hpd_at(n, HPD_INT_CONTROL);
            let value = self.read(control)?;
            self.access(|io| {
                io.write(control, value | HPD_RX_INT_ACK);
                Ok(())
            })?;
        }
        self.update(self.hpd_at(n, HPD_INT_CONTROL), enable, enable)
    }
    /// Acknowledge whatever the block raised: a plug/unplug edge (re-arming
    /// the opposite polarity) and/or a DP short pulse. Returns the debounced
    /// sense after the acknowledgement.
    pub(in crate::amdgpu_dcn401_otg) fn ack_hpd_irq(&mut self, path: Path) -> Result<bool, Error> {
        let n = hpd_block(path)?;
        let status = self.read(self.hpd_at(n, HPD_INT_STATUS))?;
        if status & HPD_RX_INT_PENDING != 0 {
            let control = self.hpd_at(n, HPD_INT_CONTROL);
            let value = self.read(control)?;
            self.access(|io| {
                io.write(control, value | HPD_RX_INT_ACK);
                Ok(())
            })?;
        }
        if status & HPD_INT_PENDING != 0 {
            return self.hpd_ack(n);
        }
        Ok(status & HPD_SENSE_DELAYED != 0)
    }
    /// Debounced hot-plug sense. Busy until `enable_hpd` routed the pin: a
    /// GPIO-owned or disabled block reports nothing about the sink.
    pub(in crate::amdgpu_dcn401_otg) fn hpd_sense(&mut self, path: Path) -> Result<bool, Error> {
        let n = hpd_block(path)?;
        if self.read(self.hpd_pad())? & PAD_MASK[n] != 0
            || self.read(self.hpd_at(n, HPD_CONTROL))? & HPD_EN == 0
        {
            return Err(Error::Busy);
        }
        Ok(self.read(self.hpd_at(n, HPD_INT_STATUS))? & HPD_SENSE_DELAYED != 0)
    }
    /// The trained link that `path` currently carries, from training through
    /// a running scanout.
    fn live_dp_link(&self, path: Path) -> Result<DpLinkTrained, Error> {
        let s = &self.status;
        let plan = s.dp_link_trained.ok_or(Error::Busy)?;
        let on = |link: DpLinkTrained| link.phy.path == path;
        let live = match s.state {
            State::DpLinkTrained(t) => t == path.transmitter,
            State::DpFrontendReady(_) => s.dp_frontend_ready.is_some_and(|f| on(f.link)),
            State::DpVideoRunning(_) | State::ScanoutRunning(_) => {
                s.dp_video_running.is_some_and(|v| on(v.frontend.link))
            }
            _ => false,
        };
        if !live {
            return Err(Error::Busy);
        }
        if plan.phy.path != path {
            return Err(Error::Invalid);
        }
        Ok(plan)
    }
    /// Read the sink's view of a live link. AUX only: no register is written
    /// and a transport failure leaves the owner's state unchanged.
    pub(in crate::amdgpu_dcn401_otg) async fn dp_link_status(
        &mut self,
        io: &mut impl Transport,
        path: Path,
    ) -> Result<DpLinkStatus, Error> {
        let plan = self.live_dp_link(path)?;
        if !io.ready() {
            return Err(Error::Busy);
        }
        let lanes = read::<6>(io, path, 0x202).await?;
        let locked = link_locked(lanes, plan.phy.settings.lanes);
        let power = if locked {
            None
        } else {
            Some(read::<1>(io, path, 0x600).await?[0])
        };
        Ok(DpLinkStatus {
            lanes,
            locked,
            power,
        })
    }
}

impl Otg {
    /// Route and enable the HPD block of a board connector.
    /// # Safety
    /// The path's HPD selector must name this connector's pin; no other agent
    /// may use that pin as a GPIO.
    pub unsafe fn enable_hpd(&mut self, path: Path) -> Result<(), Error> {
        self.0.enable_hpd(path)
    }
    /// Debounced hot-plug sense of a routed, enabled HPD block.
    pub fn hpd_sense(&mut self, path: Path) -> Result<bool, Error> {
        self.0.hpd_sense(path)
    }
    /// Arm the HPD (and for DP the HPD-RX) interrupt of a routed block.
    /// # Safety
    /// The interrupt service must be ready to receive and route DCN vectors.
    pub unsafe fn enable_hpd_irq(&mut self, path: Path, rx: bool) -> Result<(), Error> {
        self.0.enable_hpd_irq(path, rx)
    }
    /// Acknowledge a raised HPD/HPD-RX interrupt and re-arm the opposite edge.
    pub fn ack_hpd_irq(&mut self, path: Path) -> Result<bool, Error> {
        self.0.ack_hpd_irq(path)
    }
    /// Sink-reported status of this owner's live DP link.
    /// # Safety
    /// Exclude other AUX users of the port for the duration.
    pub(crate) async unsafe fn dp_link_status(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<DpLinkStatus, Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.dp_link_status(io, path).await
    }
}
