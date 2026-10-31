//! FAMS2 policy transactions under the native display owner.
use super::*;
impl ColdBoot {
    pub(super) async fn begin_fams2_io(&mut self) -> Result<bool, otg::Error> {
        if self.fams2_pending || self.state() != State::MemoryReady {
            return Err(otg::Error::Busy);
        }
        if !self.fams2_active {
            return Ok(false);
        }
        self.fams2_pending = true;
        if self.sequence.backend.dmub.hw_lock(true).await != Ok(true) {
            return Err(otg::Error::Busy);
        }
        Ok(true)
    }
    pub(super) async fn finish_fams2_io<T>(
        &mut self,
        locked: bool,
        result: Result<T, otg::Error>,
    ) -> Result<T, otg::Error> {
        if locked {
            if self.sequence.backend.dmub.hw_lock(false).await != Ok(true) {
                return Err(otg::Error::Busy);
            }
            self.fams2_pending = false;
        }
        result
    }

    pub(crate) fn fams2_active(&self) -> bool {
        self.fams2_active
    }
    pub(crate) async fn enable_display_fams2(
        &mut self,
        streams: &[dmub::Fams2StreamConfig],
    ) -> Result<(), otg::Error> {
        if self.display_retirement_busy()
            || !self.display_fams2()
            || streams.is_empty()
            || streams.len() > 4
            || !self.display_clock_status().is_ok_and(|s| {
                s.state == clocks::State::Applied
                    && s.dynamic_power
                    && s.watermarks_ready
                    && !s.uclk_switching()
            })
        {
            return Err(otg::Error::Busy);
        }
        if self.display_modesets().into_iter().flatten().any(|m| {
            self.display_status(m.pipe).is_ok_and(|s| {
                s.is_some_and(|s| {
                    s.drr
                        .is_some_and(|a| a.mid.is_some() && !a.firmware_owned())
                })
            })
        }) {
            return Err(otg::Error::Busy);
        }
        let (mut pipes, mut otgs) = (0u8, 0u8);
        for stream in streams {
            let count = usize::from(stream.num_planes);
            if stream.otg_inst >= 4
                || !(1..=4).contains(&count)
                || stream.pipe_mask == 0
                || stream.pipe_mask & !0xf != 0
                || stream.pipe_mask & pipes != 0
                || otgs & (1 << stream.otg_inst) != 0
                || !(1..=3).contains(&stream.base.kind)
                || stream.base.is_drr != stream.drr.is_some()
                || (stream.base.kind == 3 && stream.base.drr_state.is_none())
                || stream.plane_pipe_masks[..count].contains(&0)
                || stream.plane_pipe_masks[count..].iter().any(|&m| m != 0)
                || stream.plane_pipe_masks.iter().fold(0, |m, p| m | p) != stream.pipe_mask
            {
                return Err(otg::Error::Invalid);
            }
            pipes |= stream.pipe_mask;
            otgs |= 1 << stream.otg_inst;
        }
        let global = dmub::Fams2Global {
            max_allow_delay_us: 100_000,
            lock_wait_time_us: 5000,
            num_streams: streams.len() as u32,
            features: dmub::Fams2Features {
                enable: true,
                enable_stall_recovery: true,
                allow_delay_check_mode: 1,
                ..dmub::Fams2Features::default()
            },
            recovery_timeout_us: 5000,
            hwfq_flip_programming_delay_us: 300,
            max_allow_to_target_delta_us: 0,
        };
        self.configure_fams2(true, &global, streams).await
    }
    async fn configure_fams2(
        &mut self,
        enable: bool,
        global: &dmub::Fams2Global,
        streams: &[dmub::Fams2StreamConfig],
    ) -> Result<(), otg::Error> {
        if self.fams2_pending {
            return Err(otg::Error::Busy);
        }
        let commands = dmub::fams2_config_commands(enable, global, streams);
        // Cancellation, missing lock ACK or failed config keep display writes
        // closed. Clocks were pinned before this transaction began.
        self.fams2_pending = true;
        let locked = self.sequence.backend.dmub.hw_lock(true).await;
        let sent = async {
            if locked != Ok(true) {
                return Err(dmub::Error::Busy);
            }
            if !enable {
                for m in self.display_modesets().into_iter().flatten() {
                    let applied = self
                        .display_status(m.pipe)
                        .map_err(|_| dmub::Error::Busy)?
                        .and_then(|s| s.drr);
                    if let Some(a) = applied.filter(|a| a.firmware_owned() && a.mid.is_some()) {
                        self.sequence
                            .backend
                            .dmub
                            .fams2_drr_update(
                                crate::amdgpu_rdna4::pipe_pool().hw(m.pipe),
                                Some(a.adjust),
                                None,
                            )
                            .await?;
                        // SAFETY: request acknowledged under matching HW lock.
                        unsafe {
                            self.otg
                                .as_mut()
                                .map_err(|_| dmub::Error::Busy)?
                                .firmware_mid_cleared(m.pipe)
                        }
                        .map_err(|_| dmub::Error::Busy)?;
                    }
                }
            }
            for stream in streams {
                let pool = crate::amdgpu_rdna4::pipe_pool();
                let pipe = (0..pool.count())
                    .find(|&p| pool.hw(p) == stream.otg_inst)
                    .ok_or(dmub::Error::Invalid)?;
                let applied = self
                    .display_status(pipe)
                    .map_err(|_| dmub::Error::Busy)?
                    .and_then(|s| s.drr);
                self.sequence
                    .backend
                    .dmub
                    .fams2_drr_update(
                        stream.otg_inst,
                        applied.map(|a| a.adjust),
                        applied.and_then(|a| a.mid),
                    )
                    .await?;
            }
            self.sequence
                .backend
                .dmub
                .fams2_update_config(&commands)
                .await
        }
        .await;
        let restore = if sent.is_ok() {
            let pipes: Vec<_> = self
                .display_modesets()
                .into_iter()
                .flatten()
                .map(|m| m.pipe)
                .collect();
            pipes.into_iter().try_for_each(|pipe| {
                // SAFETY: the matching DRR request/config was acknowledged under
                // HW lock; OWNER retains timing, scanout and pinned clocks.
                unsafe {
                    self.otg
                        .as_mut()
                        .map_err(|e| *e)?
                        .firmware_drr(pipe, enable)
                }
            })
        } else {
            Ok(())
        };
        let released = self.sequence.backend.dmub.hw_lock(false).await;
        if locked != Ok(true) || sent.is_err() || released != Ok(true) || restore.is_err() {
            return Err(otg::Error::Busy);
        }
        self.fams2_active = enable;
        self.fams2_pending = false;
        Ok(())
    }
    pub async fn disable_display_fams2(&mut self) -> Result<(), otg::Error> {
        if self.fams2_active || self.fams2_pending {
            return self
                .configure_fams2(false, &dmub::Fams2Global::default(), &[])
                .await;
        }
        if !self.display_fams2() {
            return Ok(());
        }
        // Before FAMS2 has ever been enabled, preserve DC's optional disable.
        let commands = dmub::fams2_config_commands(false, &dmub::Fams2Global::default(), &[]);
        let dmub = &mut self.sequence.backend.dmub;
        let locked = dmub.hw_lock(true).await;
        let sent = dmub.fams2_update_config(&commands).await;
        let released = dmub.hw_lock(false).await;
        if locked.is_err() || sent.is_err() || released.is_err() {
            log_policy(format_args!(
                "FAMS2 disable: lock {locked:?}, config {sent:?}, release {released:?}"
            ));
        }
        Ok(())
    }
}
