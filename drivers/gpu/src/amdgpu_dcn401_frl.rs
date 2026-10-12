//! Native DCN401 FRL stream retirement: hpo_enc401_stop_hdmi_info_packets
//! followed by hpo_enc401_blank. Link/PHY, timing and memory remain owned.
use super::*;

const CLOCK: u64 = 0x8d3;
const SOURCE: u64 = 0x8d5;
const FIFO: u64 = 0x8d6;
const CONTROL: u64 = 0x8df;
const DB: u64 = 0x8f1;
const PACKETS: [u64; 10] = [
    0x8e6, 0x8e9, 0x8ea, 0x8eb, 0x8ec, 0x8e7, 0x8ed, 0x8ee, 0x8ef, 0x8f0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlEncoderRetired {
    /// Inherited input OTG selector, not a physical transmitter identity.
    pub pipe: u8,
    pub was_active: bool,
}
struct Plan {
    result: FrlEncoderRetired,
    clock: u32,
    fifo: u32,
    control: u32,
    route: u32,
    db: u32,
}
impl<I: Io> Engine<I> {
    fn frl_at(&self, reg: u64) -> u64 {
        self.layout.mpc_base + reg * 4
    }
    fn frl_quiet(&mut self) -> Result<(), Error> {
        // Audio/ACR, metadata and immediate packets have independent owners.
        // Leave general-control/AVMUTE packets and all AFMT/VPG registers alone.
        for (reg, mask) in [
            (FIFO, 0x100010),
            (CONTROL, 0x110),
            (0x8e2, 0x1003),     // ACR SEND/CONT/AUTO_SEND
            (0x8e3, 0x3130),     // ISRC, ACP and audio infoframes
            (0x8e8, 0x3fffffff), // all 15 immediate SEND/PENDING pairs
            (DB, 0x8001),
            (0x8ff, 1),      // HDMI metadata enable
            (0x93c, 0x1010), // native FRL DME4, not DIO DME0
        ] {
            if self.read(self.frl_at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn frl_packets_stopped(&mut self) -> Result<(), Error> {
        for reg in PACKETS {
            let at = self.frl_at(reg);
            if self.read(at)? != 0 {
                return Err(Error::Readback(at));
            }
        }
        self.frl_quiet()
    }
    fn frl_plan(&mut self) -> Result<Plan, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        self.frl_quiet()?;
        let source = self.read(self.frl_at(SOURCE))? & 7;
        if source >= 4 {
            return Err(Error::Unsupported);
        }
        let clock = self.read(self.frl_at(CLOCK))? & 0x1111;
        let fifo = self.read(self.frl_at(FIFO))? & 1;
        let control = self.read(self.frl_at(CONTROL))? & 1;
        let route = self.read(self.layout.base + 0x59 * 4)? & 15;
        if !matches!(clock, 0 | 0x1111) || clock == 0 && (fifo | control) != 0 {
            return Err(Error::Busy);
        }
        if (fifo | control) != 0 && route != 8 | source {
            return Err(Error::Invalid);
        }
        if clock == 0 {
            // Never wake a disabled stream to clean up an uncertain inherited
            // packet transaction. A fully retired stream is a read-only no-op.
            self.frl_packets_stopped()?;
        }
        Ok(Plan {
            result: FrlEncoderRetired {
                pipe: source as u8,
                was_active: (fifo | control) != 0,
            },
            clock,
            fifo,
            control,
            route,
            db: self.read(self.frl_at(DB))? & 0x1000,
        })
    }
    fn frl_unchanged(&mut self, plan: &Plan, stopped: bool, gated: bool) -> Result<(), Error> {
        self.frl_quiet()?;
        for (at, mask, value) in [
            (self.frl_at(SOURCE), 7, u32::from(plan.result.pipe)),
            (self.layout.base + 0x59 * 4, 15, plan.route),
            (self.frl_at(DB), 0x1000, plan.db),
            (
                self.frl_at(CLOCK),
                0x1111,
                if gated { 0 } else { plan.clock },
            ),
            (self.frl_at(FIFO), 1, if stopped { 0 } else { plan.fifo }),
            (
                self.frl_at(CONTROL),
                1,
                if stopped { 0 } else { plan.control },
            ),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    async fn frl_retire_inner(&mut self, plan: &Plan) -> Result<(), Error> {
        if plan.clock != 0 {
            // Native REG_SET clears all scheduling, locking and line/EMP fields.
            // FRL has no TMDS-style per-packet EN_DB_PENDING bits in its last
            // line register; use its actual HDMI/VUPDATE double-buffer status.
            for reg in PACKETS {
                self.update(self.frl_at(reg), u32::MAX, 0)?;
            }
            self.wait(self.frl_at(DB), 0x8001, 0, 150_000).await?;
            self.frl_packets_stopped()?;
            self.frl_unchanged(plan, false, false)?;
            self.update(self.frl_at(FIFO), 1, 0)?;
            self.update(self.frl_at(CONTROL), 1, 0)?;
            self.wait(self.frl_at(DB), 0x8001, 0, 150_000).await?;
            self.frl_packets_stopped()?;
            self.frl_unchanged(plan, true, false)?;
            self.update(self.frl_at(CLOCK), 1, 0)?;
            self.wait(self.frl_at(CLOCK), 0x1111, 0, 1000).await?;
        }
        self.frl_packets_stopped()?;
        self.frl_unchanged(plan, true, true)
    }
    pub(super) async fn retire_hdmi_frl_encoder(&mut self) -> Result<FrlEncoderRetired, Error> {
        let plan = self.frl_plan()?;
        self.status.state = State::RetiringHdmiFrl;
        match self.frl_retire_inner(&plan).await {
            Ok(()) => {
                self.status.frl_encoder_retired = Some(plan.result);
                self.status.state = State::HdmiFrlRetired;
                Ok(plan.result)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Retire the single native FRL frontend, retaining link/PHY and timing clocks.
    /// # Safety
    /// Independently handle sink AVMUTE/SCDC/retimers and audio/ACR/metadata/HDCP
    /// teardown. Exclude CPU/firmware/FAMS and concurrent display/packet/link/
    /// clock/power/reset writers. Retain every allocation and translation.
    /// Completion proves only generic-packet, FIFO, tribyte and stream-clock
    /// retirement, never link, PHY, timing, AFMT/VPG, HUBP or memory retirement.
    /// Retain the owner on failure/cancellation until independent reset.
    pub async unsafe fn retire_hdmi_frl_encoder(&mut self) -> Result<FrlEncoderRetired, Error> {
        self.0.retire_hdmi_frl_encoder().await
    }
}
