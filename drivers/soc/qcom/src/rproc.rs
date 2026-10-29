//! Remote-processor lifecycle shared by [`crate::wcss`] and [`crate::pas`].
//!
//! Linux `remoteproc_core.c` `rproc_boot` = load (`ops->load`) + start
//! (`ops->start`), `rproc_shutdown` = stop. Consumers (ath11k AHB
//! `power_up`/`power_down`) only see [`RprocState`] and [`RprocError`].

use crate::gcc::GccError;
use crate::mdt::MdtError;
use crate::q6v5::Q6Error;
use crate::scm::ScmError;

/// `enum rproc_state` (subset).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RprocState {
    Offline,
    Running,
    Crashed,
}

/// Boot/shutdown failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RprocError {
    /// `request_firmware` found no image.
    NoFirmware,
    /// MDT parse/load failure.
    Firmware(MdtError),
    /// SCM/PAS failure.
    Scm(ScmError),
    /// Start or stop handshake failure (timeout / crash).
    Handshake(Q6Error),
    /// `Q6SS_XO_CBCR` never reported the clock on.
    XoClockTimeout,
    /// `SSCAON_STATUS` never reached 0x400 during WCSS power-down.
    SscaonTimeout(u32),
    /// `Q6SS_BHS_STATUS` never dropped `BHS_EN_REST_ACK`.
    BhsTimeout(u32),
    /// A GCC reset/clock lookup failed.
    Gcc(GccError),
    /// `start` without a loaded image, or `stop` while offline.
    BadState(RprocState),
}

impl From<MdtError> for RprocError {
    fn from(e: MdtError) -> Self {
        RprocError::Firmware(e)
    }
}
impl From<ScmError> for RprocError {
    fn from(e: ScmError) -> Self {
        RprocError::Scm(e)
    }
}
impl From<Q6Error> for RprocError {
    fn from(e: Q6Error) -> Self {
        RprocError::Handshake(e)
    }
}
impl From<GccError> for RprocError {
    fn from(e: GccError) -> Self {
        RprocError::Gcc(e)
    }
}

/// The outbound SMP2P `stop` state (`qcom,smem-state-names = "stop"`),
/// `qcom_smem_state_update_bits(state, BIT(stop_bit), on ? BIT : 0)`.
pub trait StopState {
    fn set_stop(&self, on: bool);
}

/// The reserved-memory carve-out the image is loaded into
/// (`memory-region`, mapped write-combined).
#[derive(Debug)]
pub struct Carveout<'a> {
    pub phys: u64,
    pub mem: &'a mut [u8],
}
