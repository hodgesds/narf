//! Turing GSP modeset plan — the ordered sequence of GSP-RM RPCs and
//! NvDisplay pushbuffer kicks that light one head on one output.
//!
//! The individual building blocks already exist — the RM object model
//! ([`crate::gsp_rm_api`]), the DP link-training controls
//! ([`crate::gsp_dp`]), channel allocation ([`crate::gsp_chan`]), and
//! the C57D/C57E method encoders ([`crate::dispc57d`] /
//! [`crate::dispc57e`]). What was missing is the *spine*: the exact
//! order in which they fire for a live modeset. This module assembles
//! that order into a declarative [`Step`] list so the host loop can
//! execute it blind once the RPC-ring transport is wired — each [`Step`]
//! is either a ready-to-send RPC payload (`Rpc`) or a staged pushbuffer
//! to copy into a channel and kick (`Push`).
//!
//! Building the plan is pure (no hardware, no RPC transport), so the
//! ordering and every payload are unit-testable; executing it is the
//! single hardware-gated step.
//!
//! Grounded in the `r535_gsp` display bring-up order
//! (`rm/r535/disp.c`): instance memory → output-path link config →
//! channel allocation → core modeset → window surface.

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::disp::Mode;
use crate::gsp_rm_api::{FUNCTION_GSP_RM_ALLOC, FUNCTION_GSP_RM_CONTROL};
use crate::pb::{PbBuilder, PbError};
use crate::{dispc57d, dispc57e, gsp_chan, gsp_dp};

/// One step of a modeset plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A GSP-RM RPC to send on the command ring: `function` is the
    /// `NV_VGPU_MSG_FUNCTION_*` id (ALLOC/CONTROL) and `payload` the
    /// already-built message body.
    Rpc { function: u32, payload: Vec<u8> },
    /// A staged NvDisplay pushbuffer to copy into channel `class`
    /// (head `head`) at its [`gsp_chan::channel_user_offset`] and kick
    /// by advancing PUT.
    Push { class: u32, head: u8, pb: Vec<u8> },
}

impl Step {
    fn control(cmd_payload: Vec<u8>) -> Self {
        Step::Rpc {
            function: FUNCTION_GSP_RM_CONTROL,
            payload: cmd_payload,
        }
    }
    fn alloc(payload: Vec<u8>) -> Self {
        Step::Rpc {
            function: FUNCTION_GSP_RM_ALLOC,
            payload,
        }
    }
}

/// Everything the plan needs to light one head. The handles come from
/// the boot-time object tree ([`crate::gsp_rm_api`]) and the parsed
/// static info ([`crate::gsp_static`]); the physical addresses are the
/// DMA buffers the caller allocated for the channel pushbuffers, the
/// display instance memory, and the scanout surface.
#[derive(Debug, Clone)]
pub struct ModesetInputs<'a> {
    pub h_client: u32,
    /// Internal subdevice handle (from `GspStaticConfigInfo`).
    pub h_internal_subdevice: u32,
    /// The display output being lit (`NV0073` displayId bitmask).
    pub display_id: u32,

    /// Display engine instance memory (RAMIN) in VRAM.
    pub inst_mem_phys: u64,
    pub inst_mem_size: u64,

    /// DP link: raw lane count (1/2/4/8) and a `gsp_dp::LINK_BW_*` code.
    pub dp_lanes: u32,
    pub dp_bw_code: u32,
    /// Per-lane drive-current / pre-emphasis codes ([`gsp_dp::lane_data`]).
    pub dp_lane_data: &'a [u32],

    /// Core channel pushbuffer (sysmem) physical base + byte limit.
    pub core_pb_phys: u64,
    pub core_pb_limit: u64,
    /// Window channel pushbuffer physical base + byte limit.
    pub window_pb_phys: u64,
    pub window_pb_limit: u64,

    /// The mode to program and the head to drive.
    pub mode: &'a Mode,
    pub head: u8,

    /// Scanout surface: the ISO ctx-dma handle, byte offset, and size.
    pub fb_handle: u32,
    pub fb_offset: u64,
    pub fb_width: u16,
    pub fb_height: u16,
}

/// Render a pushbuffer by staging into a scratch buffer, returning only
/// the bytes written. 1 KiB is ample for a single head's method stream.
fn render_pb<F>(stage: F) -> Result<Vec<u8>, PbError>
where
    F: FnOnce(&mut PbBuilder<'_>) -> Result<(), PbError>,
{
    let mut buf = alloc::vec![0u8; 1024];
    let mut pb = PbBuilder::new(&mut buf);
    stage(&mut pb)?;
    let n = pb.len();
    buf.truncate(n);
    Ok(buf)
}

/// Build the ordered modeset plan. The caller sends each `Rpc` on the
/// GSP command ring (waiting for its reply) and, for each `Push`, copies
/// `pb` into the channel's user MMIO window and advances PUT.
///
/// Order (per `r535_gsp` display bring-up):
/// 1. `WRITE_INST_MEM` — hand GSP the display RAMIN.
/// 2. `DP_CTRL` — set link config + train the link.
/// 3. `DP_SET_LANE_DATA` — program the trained drive/pre-emphasis.
/// 4. core channel: register pushbuffer, then allocate the channel.
/// 5. window channel: register pushbuffer, then allocate the channel.
/// 6. push the C57D core modeset (raster/clock/output) + UPDATE.
/// 7. push the C57E window surface (geometry/format/ctx-dma) + UPDATE.
pub fn build_modeset_plan(inputs: &ModesetInputs) -> Result<Vec<Step>, PbError> {
    let mut steps = Vec::new();

    // 1. Display instance memory.
    steps.push(Step::control(gsp_chan::write_inst_mem_rpc(
        inputs.h_client,
        inputs.h_internal_subdevice,
        inputs.inst_mem_phys,
        inputs.inst_mem_size,
    )));

    // 2. DP link configuration + training.
    let dp_ctrl =
        gsp_dp::set_link_config_params(inputs.display_id, inputs.dp_lanes, inputs.dp_bw_code);
    steps.push(Step::control(gsp_dp::dp_ctrl_rpc(
        inputs.h_client,
        &dp_ctrl,
    )));

    // 3. DP per-lane drive current / pre-emphasis.
    let lane = gsp_dp::set_lane_data_params(inputs.display_id, inputs.dp_lane_data);
    steps.push(Step::control(gsp_dp::set_lane_data_rpc(
        inputs.h_client,
        &lane,
    )));

    // 4. Core channel: register pushbuffer, then allocate.
    steps.push(Step::control(gsp_chan::pushbuffer_rpc(
        inputs.h_client,
        inputs.h_internal_subdevice,
        gsp_chan::ADDR_SYSMEM,
        inputs.core_pb_phys,
        inputs.core_pb_limit,
        gsp_chan::DISP_CORE_CHANNEL_DMA,
        inputs.head as u32,
        true,
    )));
    steps.push(Step::alloc(gsp_chan::alloc_channel_rpc(
        inputs.h_client,
        gsp_chan::DISP_CORE_CHANNEL_DMA,
        inputs.head as u16,
    )));

    // 5. Window channel: register pushbuffer, then allocate.
    steps.push(Step::control(gsp_chan::pushbuffer_rpc(
        inputs.h_client,
        inputs.h_internal_subdevice,
        gsp_chan::ADDR_SYSMEM,
        inputs.window_pb_phys,
        inputs.window_pb_limit,
        gsp_chan::DISP_WINDOW_CHANNEL_DMA,
        inputs.head as u32,
        true,
    )));
    steps.push(Step::alloc(gsp_chan::alloc_channel_rpc(
        inputs.h_client,
        gsp_chan::DISP_WINDOW_CHANNEL_DMA,
        inputs.head as u16,
    )));

    // 6. Core modeset push.
    let core_pb = render_pb(|pb| {
        dispc57d::stage_head_mode(pb, inputs.mode, inputs.head)?;
        dispc57d::stage_update(pb)
    })?;
    steps.push(Step::Push {
        class: gsp_chan::DISP_CORE_CHANNEL_DMA,
        head: inputs.head,
        pb: core_pb,
    });

    // 7. Window surface push.
    let window_pb = render_pb(|pb| {
        dispc57e::stage_surface(
            pb,
            inputs.fb_handle,
            inputs.fb_offset,
            inputs.fb_width,
            inputs.fb_height,
        )?;
        dispc57e::stage_update(pb)
    })?;
    steps.push(Step::Push {
        class: gsp_chan::DISP_WINDOW_CHANNEL_DMA,
        head: inputs.head,
        pb: window_pb,
    });

    Ok(steps)
}
