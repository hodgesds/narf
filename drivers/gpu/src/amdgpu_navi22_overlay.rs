//! The Navi22 slave (overlay) pipe: its lease from the six-pipe pool and its
//! front end (HUBP + DPP + MPCC, no OPP of its own — the overlay's pixels
//! reach the primary's OPP through the MPCC tree).
//!
//! Linux: `dc->caps.max_slave_planes = 2` (`dcn30_resource.c:2313`); the
//! slave comes from `dcn20_acquire_free_pipe_for_layer`, which takes the
//! preferred pipe `(pipe_count - 1) - primary` when free and otherwise scans
//! backwards from the top of the pool
//! (`resource_find_free_secondary_pipe_legacy`, `dc_resource.c`), so a
//! stream's slave never takes a pipe another stream's slave would remap.
//! DCN30 has 6 pipes and Navi22 publishes 4 CRTCs, so 4 primaries + 2
//! overlays is exactly the pool — admission must check the free-pipe pool
//! before leasing (the wiring lane owns that check).
//!
//! The overlay's front end is the ODM secondary's shape ([`Slice`]): the
//! slave HUBP selects the primary's OTG (`hubp2_vtg_sel`), its DPP is
//! programmed for the overlay surface, and its MPCC is inserted above the
//! primary's in the tree. Unlike an ODM slice it has its own scaler and its
//! own surface address, flipped at the same VUPDATE under the OTG's
//! pipe-control lock.

use super::*;

/// How many slave overlays DCN30 admits in total, shared across CRTCs.
pub const MAX_SLAVE_PLANES: usize = 2; // linux: dc->caps.max_slave_planes = 2 (dcn30_resource.c:2313)

/// A leased slave pipe: the overlay's HUBP/DPP/MPCC instance, on the OTG of
/// `primary`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlaveLease {
    pub pipe: u8,
    pub primary: u8,
}

/// `dcn20_acquire_free_pipe_for_layer` for a slave overlay on `primary`:
/// the preferred pipe `(pipes - 1) - primary` when it is free, otherwise the
/// highest free pipe. `used` names every pipe already taken — other streams'
/// primaries, their ODM secondaries, and other streams' slaves — and
/// `primary` itself is never leased. `None` when the pool is exhausted (4
/// primaries + 2 overlays is all 6 pipes).
pub fn lease_slave(pipes: u8, primary: u8, used: &[u8]) -> Option<SlaveLease> {
    if primary >= pipes {
        return None;
    }
    let free = |pipe: u8| pipe != primary && !used.contains(&pipe);
    let preferred = pipes - 1 - primary;
    if free(preferred) {
        return Some(SlaveLease {
            pipe: preferred,
            primary,
        });
    }
    (0..pipes)
        .rev()
        .find(|&pipe| free(pipe))
        .map(|pipe| SlaveLease { pipe, primary })
}

/// A slave overlay pipe's front end: the second plane's HUBP, DPP and MPCC.
/// No OPP: the overlay feeds the primary's OPP through the MPCC tree
/// ([`crate::amdgpu_dcn_plane::Mpc::insert_plane`] above the primary's
/// MPCC).
#[derive(Debug)]
pub struct OverlayPipe {
    pub pipe: u8,
    pub hubp: Hubp,
    pub dpp: Dpp,
    pub mpc: Mpc,
}
impl OverlayPipe {
    /// # Safety
    /// The caller exclusively owns `pipe`'s HUBP, DPP and MPCC as this
    /// stream's slave overlay — the pipe came from [`lease_slave`] and no
    /// other stream, ODM secondary or overlay holds it — with PCI authority
    /// and a permanent mapping.
    pub(super) unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pipe: u8,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded.
        unsafe {
            Ok(Self {
                pipe,
                hubp: Hubp::new(gpu, authority, pipe)?,
                dpp: Dpp::new(gpu, authority, pipe)?,
                mpc: Mpc::new(gpu, authority, pipe)?,
            })
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_overlay_tests.rs"]
mod tests;
