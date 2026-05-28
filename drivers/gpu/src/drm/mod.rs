//! DRM — Direct Rendering Manager kernel-mode-setting framework.
//!
//! This module provides the NARF DRM subsystem — a minimal but
//! structurally faithful analogue of Linux's DRM, sufficient to drive
//! kernel-mode-setting from userspace on Intel and AMD GPUs.
//!
//! ## Submodule layout
//!
//! | module   | responsibility                                      |
//! |----------|-----------------------------------------------------|
//! | `card`   | `Card` — one per GPU, owns connector + CRTC lists  |
//! | `gem`    | GEM buffer-object lifecycle + handle table         |
//! | `ioctl`  | DRM ioctl dispatch + wire-format structs           |
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_drv.c` — card registration + open/release.
//! - `drivers/gpu/drm/drm_gem.c` — GEM object lifecycle.
//! - `drivers/gpu/drm/drm_ioctl.c` — ioctl dispatch table.
//! - `drivers/gpu/drm/drm_prime.c` — DRM ↔ dma-buf bridge (deferred).
//! - `include/uapi/drm/drm.h` + `drm_mode.h` — wire format.
//!
//! ## Deferred
//!
//! - DRM leases (sub-master delegation).
//! - syncobj timelines beyond binary signal/wait.
//! - AMD/NV-specific scheduler hardware integration (these slot in
//!   under the [`scheduler::Sched`] front-end as JobPayload backends).

pub mod card;
pub mod gem;
pub mod ioctl;
pub mod render_node;
pub mod atomic;
pub mod syncobj;
pub mod scheduler;
pub mod prime;

pub use card::{Card, CardError, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder};
pub use gem::{GemError, GemHandle, GemObject};
pub use ioctl::{dispatch, DrmIoctlError, IoctlCmd};
pub use render_node::{
    check_permission, DrmFileCtx, DrmMinor, IoctlFlags, MinorType, PermError,
};
pub use atomic::{AtomicError, AtomicState, ConnectorState, CrtcState, PlaneState};
pub use syncobj::{BinaryFence, DmaFence, SyncError, SyncObj, SyncObjTable};
pub use scheduler::{Job, JobFence, JobPayload, Sched, SchedContext, SchedError};
pub use prime::{PrimeError, PrimeTable};
