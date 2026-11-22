//! Raphael's GFX power gating and GFXOFF: `gfx_v10_0_set_powergating_state`
//! for GC 10.3.6, over PMFW 13.0.5's `AllowGfxOff` / `DisallowGfxOff`
//! (`smu_v13_0_gfx_off_control`).
//!
//! - GATE (`gfx_v10_cntl_pg(true)`, then `amdgpu_gfx_off_ctrl(true)`) once
//!   graphics serves clients, as Linux's late init gates every IP. The
//!   request count drops from 1 to 0, and `AllowGfxOff` follows
//!   `GFX_OFF_DELAY_ENABLE` (100 ms) later. Without `AMD_PG_SUPPORT_GFX_PG`
//!   (`amdgpu.pg_mask`) `gfx_v10_cntl_pg(true)` still runs, clearing the
//!   enable instead, and GFXOFF is allowed all the same.
//! - UNGATE (`amdgpu_gfx_off_ctrl(false)`, then `gfx_v10_cntl_pg(false)`)
//!   before S3 and before a mode 2 reset, as `amdgpu_device_ip_suspend` does.
//! - A driver read of GC registers holds a disable request for the access:
//!   READ_MMR_REG (`amdgpu_info_ioctl`) and the hang snapshot
//!   (`gfx_v10_ip_dump`). Submission writes only memory and the doorbell,
//!   which wakes GFX itself, and takes nothing; nor do soft recovery and the
//!   queue resets, whose engine is busy and so powered, as in Linux.
//!
//! The count is Linux's `amdgpu_gfx_off_ctrl`, through Navi22's controller.
//! Unlike Navi22's single global one, each graphics coordinator lifetime has
//! its own [`GfxOff`] under the display owner's lock: a coordinator re-armed
//! after S3 or a reset gates again, and a delayed allow scheduled before
//! carries an epoch no later [`GfxOff`] has. `amdgpu.ppfeaturemask` without
//! `PP_GFXOFF_MASK` leaves the count inert, as in Linux, while power gating
//! still follows GATE and UNGATE.
use crate::amdgpu_navi22_gfxoff::{Control, Controller};
pub(crate) use crate::amdgpu_navi22_gfxoff::{Error, DELAY_MS};
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

/// Epochs handed to each [`GfxOff`]; never reused.
static EPOCHS: AtomicU64 = AtomicU64::new(1);

/// RLC's GFX power gating, `gfx_v10_cntl_pg`.
pub(crate) trait PowerGating {
    fn set_power_gating(&mut self, enable: bool) -> impl Future<Output = Result<(), ()>> + Send;
}

/// A delayed `AllowGfxOff` (`gfx_off_delay_work`), due [`DELAY_MS`] after
/// the request count reached zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Allow {
    epoch: u64,
    generation: u64,
}

#[derive(Debug)]
pub(crate) struct GfxOff {
    controller: Controller,
    epoch: u64,
    /// `PP_GFXOFF_MASK`: requests reach PMFW.
    enabled: bool,
    /// `AMD_PG_SUPPORT_GFX_PG`: GATE turns RLC's power gating on.
    power_gating: bool,
    /// GATE applied and not yet undone.
    gated: bool,
}
impl GfxOff {
    /// A coordinator lifetime's state: count 1 (GFXOFF disallowed, which
    /// the SMU stage told PMFW), not gated.
    pub(crate) fn new(enabled: bool, power_gating: bool) -> Self {
        Self {
            controller: Controller::new(),
            epoch: EPOCHS.fetch_add(1, Ordering::Relaxed),
            enabled,
            power_gating,
            gated: false,
        }
    }
    /// The next lifetime's state, with the same feature flags.
    pub(crate) fn renewed(&self) -> Self {
        Self::new(self.enabled, self.power_gating)
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn gated(&self) -> bool {
        self.gated
    }
    /// `amdgpu_gfx.gfx_off_req_count`, `gfx_off_state`.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn status(&self) -> crate::amdgpu_navi22_gfxoff::Status {
        self.controller.status()
    }
    fn allow(&self, generation: Option<u64>) -> Option<Allow> {
        generation.map(|generation| Allow {
            epoch: self.epoch,
            generation,
        })
    }
    /// GATE: power gating on (`gfx_v10_cntl_power_gating` sets the enable
    /// only with `AMD_PG_SUPPORT_GFX_PG`), then the count's GATE request.
    /// The returned allow is to be delivered through [`Self::delayed`]
    /// after [`DELAY_MS`]. A second GATE does nothing.
    pub(crate) async fn gate(
        &mut self,
        hw: &mut (impl Control + PowerGating),
    ) -> Result<Option<Allow>, Error> {
        if self.gated {
            return Ok(None);
        }
        hw.set_power_gating(self.power_gating)
            .await
            .map_err(|()| Error::Control)?;
        self.gated = true;
        if self.enabled && !self.controller.status().enabled {
            // The SMU stage sent DisallowGfxOff: the count is 1.
            self.controller.start()?;
        }
        let generation = self.controller.allow()?;
        Ok(self.allow(generation))
    }
    /// UNGATE: a disable request (`DisallowGfxOff` if GFXOFF was in
    /// effect), then power gating off. GFX is powered on `Ok`.
    pub(crate) async fn ungate(
        &mut self,
        hw: &mut (impl Control + PowerGating),
    ) -> Result<(), Error> {
        if !self.gated {
            return Ok(());
        }
        self.controller.disallow(hw).await?;
        self.gated = false;
        hw.set_power_gating(false)
            .await
            .map_err(|()| Error::Control)
    }
    /// A GC access's `amdgpu_gfx_off_ctrl(false)`: GFX is powered on `Ok`
    /// until [`Self::release`].
    pub(crate) async fn hold(&mut self, hw: &mut impl Control) -> Result<(), Error> {
        self.controller.disallow(hw).await
    }
    /// The access's `amdgpu_gfx_off_ctrl(true)`.
    pub(crate) fn release(&mut self) -> Result<Option<Allow>, Error> {
        let generation = self.controller.allow()?;
        Ok(self.allow(generation))
    }
    /// `amdgpu_device_prepare`'s `flush_delayed_work`: a scheduled allow
    /// delivered now, so GFX is in GFXOFF before the suspend goes on. Any
    /// allow already scheduled then lands on nothing.
    pub(crate) async fn flush(&mut self, hw: &mut impl Control) -> Result<bool, Error> {
        self.controller.flush_delayed(hw).await
    }
    /// `amdgpu_device_delay_enable_gfx_off` for `allow`: `Ok(false)` when a
    /// disable request cancelled it or it belongs to another lifetime.
    pub(crate) async fn delayed(
        &mut self,
        allow: Allow,
        hw: &mut impl Control,
    ) -> Result<bool, Error> {
        if allow.epoch != self.epoch {
            return Ok(false);
        }
        self.controller.delayed_allow(allow.generation, hw).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_raphael_gfxoff_tests.rs"]
mod tests;
