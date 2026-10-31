//! VCN/JPEG idle transitions under the retained platform owner.
use super::*;
const IDLE_NS: u64 = 1_000_000_000; // Linux VCN_IDLE_TIMEOUT
#[derive(Debug)]
pub(super) struct Idle {
    last_use: [Option<u64>; 2],
    // Stored before hardware/SMU awaits; cancellation never permits replay.
    pending: bool,
}
impl Idle {
    pub const fn new() -> Self {
        Self {
            last_use: [None; 2],
            pending: false,
        }
    }
}
impl Hardware {
    pub(super) async fn configure_media_power(&mut self) -> Result<(), Error> {
        if !crate::amdgpu_navi48_media_power::enabled() {
            return Ok(());
        }
        if self.media_idle.pending {
            return Err(Error::DeviceGone);
        }
        // Only retained client engines need automatic gating. Proof-only
        // owners are already stopped and their registrations retired.
        let ready = self
            .vcn
            .as_ref()
            .is_some_and(|v| v.fence_reader().is_some())
            && self.vcn_owner.is_some();
        if !ready {
            return Ok(());
        }
        self.media_idle.pending = true;
        let psp = self.psp.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: native proofs drained, OWNER retains TMR/GMC/IH and backing.
        let enabled = unsafe {
            self.vcn
                .as_mut()
                .ok_or(Error::Invalid)?
                .enable_dpg(psp)
                .await
        }
        .map_err(Error::Vcn)?;
        if !enabled {
            return Err(Error::Busy);
        }
        if crate::amdgpu_rdna4::Rdna4Chip::of(&self.gpu).is_some_and(|c| c.jpeg_dpg())
            && self.media_jpeg_clients
        {
            // SAFETY: Navi48 only, with proved JRBC and shared NBIO retained.
            if !unsafe {
                self.jpeg
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .enable_dpg(psp)
                    .await
            }
            .map_err(Error::Jpeg)?
            {
                return Err(Error::Busy);
            }
        }
        if let Some(jpeg) = self.jpeg.as_mut() {
            jpeg.allow_clock_sleep();
        }
        // SAFETY: DPG is live; only board-supported media bits are admitted.
        self.power = Some(
            unsafe {
                self.smu
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .configure_media_power(true)
                    .await
            }
            .map_err(Error::Smu)?,
        );
        self.media_idle.pending = false;
        Ok(())
    }
    pub(super) async fn static_media_power(&mut self) -> Result<(), Error> {
        if self.media_idle.pending {
            return Err(Error::DeviceGone);
        }
        if self
            .power
            .is_none_or(|p| p.enabled & crate::amdgpu_navi48_media_power::FEATURES == 0)
        {
            return Ok(());
        }
        self.media_idle.pending = true;
        // SAFETY: OWNER excludes publishers and all engine memory stays pinned.
        self.power = Some(
            unsafe {
                self.smu
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .configure_media_power(false)
                    .await
            }
            .map_err(Error::Smu)?,
        );
        self.media_idle.pending = false;
        Ok(())
    }
    pub(super) async fn begin_media_use(&mut self, jpeg: bool) -> Result<(), Error> {
        let h = self;
        if h.media_idle.pending {
            return Err(Error::DeviceGone);
        }
        h.media_idle.last_use[usize::from(jpeg)] = Some(narf_time::monotonic_ns());
        let asleep = if jpeg {
            h.jpeg
                .as_ref()
                .is_some_and(|j| j.state() == crate::amdgpu_jpeg_navi48::State::Idle)
        } else {
            h.vcn
                .as_ref()
                .is_some_and(|v| v.state() == crate::amdgpu_vcn_navi48::State::Idle)
        };
        if !asleep {
            return Ok(());
        }
        h.media_idle.pending = true;
        let smu = h.smu.as_mut().ok_or(Error::Invalid)?;
        // SAFETY: OWNER retains the stopped hardware, all memory and IRQs;
        // normal idle kept the shared NBIO range and the codec context.
        if jpeg {
            // SAFETY: idle proved JPEG stopped; OWNER retains its backing.
            let power = unsafe { smu.set_jpeg_power(true).await }.map_err(Error::Smu)?;
            h.power = Some(power);
            // SAFETY: matching retained VCN/NBIO/GMC and completed power-up.
            unsafe {
                h.jpeg
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .resume_idle(power, h.psp.as_mut().ok_or(Error::Invalid)?)
                    .await
            }
            .map_err(Error::Jpeg)?;
        } else {
            // SAFETY: idle proved VCN stopped; OWNER retains its backing.
            let power = unsafe { smu.set_vcn_power(true).await }.map_err(Error::Smu)?;
            h.power = Some(power);
            let firmware = h.psp.as_ref().ok_or(Error::Invalid)?.media_firmware();
            // SAFETY: matching TMR/GMC/IRQ owner and completed power-up.
            unsafe {
                h.vcn
                    .as_mut()
                    .ok_or(Error::Invalid)?
                    .resume_idle(firmware, power, h.psp.as_mut().ok_or(Error::Invalid)?)
                    .await
            }
            .map_err(Error::Vcn)?;
        }
        h.media_idle.pending = false;
        Ok(())
    }
}
impl ColdBoot {
    pub(crate) async fn begin_media_use(&mut self, jpeg: bool) -> Result<(), Error> {
        self.sequence.backend.begin_media_use(jpeg).await
    }
    pub(crate) async fn wake_media(&mut self) -> Result<(), Error> {
        self.begin_media_use(false).await?;
        self.begin_media_use(true).await
    }
    pub(crate) async fn idle_media(&mut self, now: u64) -> Result<(), Error> {
        if self.state() != State::MemoryReady {
            return Ok(());
        }
        let h = &mut self.sequence.backend;
        if h.media_idle.pending {
            return Err(Error::DeviceGone);
        }
        // Gate independently. VCN's idle stop deliberately retains the
        // shared range even if JPEG is still executing a client job.
        for jpeg in [true, false] {
            let index = usize::from(jpeg);
            let last = *h.media_idle.last_use[index].get_or_insert(now);
            if now.saturating_sub(last) < IDLE_NS {
                continue;
            }
            h.media_idle.pending = true;
            let stopped = if jpeg {
                match h.jpeg.as_mut() {
                    // SAFETY: OWNER excludes publication and retains NBIO/GMC.
                    Some(j) => unsafe { j.idle().await }.map_err(Error::Jpeg)?,
                    None => false,
                }
            } else {
                match h.vcn.as_mut() {
                    // SAFETY: OWNER excludes publication and retains TMR/GMC.
                    Some(v) => unsafe { v.idle().await }.map_err(Error::Vcn)?,
                    None => false,
                }
            };
            if stopped {
                let smu = h.smu.as_mut().ok_or(Error::Invalid)?;
                // SAFETY: physical fences, RPTR and DMA-clean shutdown
                // completed before the power message; backing stays pinned.
                h.power = Some(
                    if jpeg {
                        // SAFETY: the JPEG hardware stop above proved retirement.
                        unsafe { smu.set_jpeg_power(false).await }
                    } else {
                        // SAFETY: the VCN hardware stop above proved retirement.
                        unsafe { smu.set_vcn_power(false).await }
                    }
                    .map_err(Error::Smu)?,
                );
            }
            h.media_idle.pending = false;
        }
        Ok(())
    }
}
