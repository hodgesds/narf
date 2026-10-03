//! USB4 DisplayPort tunnel bandwidth allocation. A tunnelled link shares its
//! host router's bandwidth with USB data and with the other tunnelling
//! endpoints, so the bandwidth a mode needs has to be asked for rather than
//! assumed. Registers and sequencing follow the USB4 DP tunnelling DPCD space
//! (chapter 10.7) and Linux `link_dp_dpia_bw.c`.
//!
//! Every access goes over the sink's AUX channel through the booted firmware,
//! so this needs no registers of its own.
use crate::{
    amdgpu_dio::{AuxError, Phy},
    amdgpu_dmub::Channel,
};

const TUNNELING_CAPABILITIES: u32 = 0xe_000d;
const DRIVER_BW_CAPABILITY: u32 = 0xe_0020;
const BW_GRANULARITY: u32 = 0xe_0022;
const ESTIMATED_BW: u32 = 0xe_0023;
const ALLOCATED_BW: u32 = 0xe_0024;
const TUNNELING_STATUS: u32 = 0xe_0025;
const MAX_LINK_RATE: u32 = 0xe_0028;
const MAX_LANE_COUNT: u32 = 0xe_0029;
const ALLOCATION_MODE_CONTROL: u32 = 0xe_0030;
const REQUESTED_BW: u32 = 0xe_0031;

const CAP_DP_TUNNELING: u8 = 1 << 0;
const CAP_DPIA_BW_ALLOC: u8 = 1 << 7;
const CAP_DRIVER_BW_ALLOC: u8 = 1 << 7;
const MODE_UNMASK_IRQ: u8 = 1 << 6;
const MODE_ENABLE: u8 = 1 << 7;
const STATUS_REQUEST_FAILED: u8 = 1 << 0;
const STATUS_REQUEST_SUCCEEDED: u8 = 1 << 1;
/// One gigabit per second in kbps: the unit the granularity subdivides.
const GBPS_IN_KBPS: u32 = 1_000_000;
/// A deferred AUX reply is retried; anything else aborts.
const AUX_RETRIES: usize = 7;
/// The router answers a request in milliseconds, but it is answering on behalf
/// of a connection manager, so allow it a generous window before giving up.
const STATUS_TIMEOUT_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// This endpoint or its router does not do allocation at all, so the tunnel
    /// carries whatever fixed allocation it was created with.
    Unsupported,
    Aux,
    /// The router refused the request outright.
    Refused,
    Timeout,
    /// The tunnel cannot carry this mode. Reported rather than silently
    /// starving the stream, which would tear instead of failing.
    Insufficient {
        estimated_kbps: u32,
        required_kbps: u32,
    },
}
/// What the router granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    /// Allocation steps per gigabit: 4 is 0.25 Gbps granularity, 1 is 1 Gbps.
    pub granularity_steps_per_gbps: u8,
    pub estimated_kbps: u32,
    pub allocated_kbps: u32,
    /// The endpoint's non-reduced maxima, which bound training independently of
    /// what the sink itself reports.
    pub max_link_rate: u8,
    pub max_lanes: u8,
}

async fn read(phy: &mut impl Phy, aux: u8, address: u32) -> Result<u8, Error> {
    let mut byte = [0u8; 1];
    for _ in 0..AUX_RETRIES {
        match phy.aux(Channel::Dpia, aux, 0x90, address, &mut byte).await {
            Ok(()) => return Ok(byte[0]),
            Err(AuxError::Defer) => continue,
            Err(AuxError::Failed) => return Err(Error::Aux),
        }
    }
    Err(Error::Aux)
}
async fn write(phy: &mut impl Phy, aux: u8, address: u32, value: u8) -> Result<(), Error> {
    for _ in 0..AUX_RETRIES {
        let mut byte = [value];
        match phy.aux(Channel::Dpia, aux, 0x80, address, &mut byte).await {
            Ok(()) => return Ok(()),
            Err(AuxError::Defer) => continue,
            Err(AuxError::Failed) => return Err(Error::Aux),
        }
    }
    Err(Error::Aux)
}
/// `get_bw_granularity`: the register selects how finely bandwidth can be
/// divided. The reserved encoding is refused rather than guessed at, because
/// guessing it wrong scales every request.
fn granularity(register: u8) -> Result<u8, Error> {
    match register & 0x3 {
        0 => Ok(4),
        1 => Ok(2),
        2 => Ok(1),
        _ => Err(Error::Unsupported),
    }
}
fn kbps_from_steps(steps: u8, granularity: u8) -> u32 {
    steps as u32 * (GBPS_IN_KBPS / granularity as u32)
}
/// Round up: a request rounded down would leave the stream short of what it
/// needs by up to one step.
fn steps_from_kbps(kbps: u32, granularity: u8) -> u32 {
    (kbps as u64 * granularity as u64).div_ceil(GBPS_IN_KBPS as u64) as u32
}

/// Ask the host router for enough bandwidth to carry `required_kbps`.
///
/// Returns `Unsupported` when the endpoint does not implement allocation, which
/// is not a failure: the tunnel then carries the fixed allocation it was created
/// with, and the caller may proceed on that. Any other error means the tunnel
/// will not carry this mode, and the mode should not be driven over it.
pub async fn allocate(
    phy: &mut impl Phy,
    aux: u8,
    required_kbps: u32,
) -> Result<Allocation, Error> {
    if required_kbps == 0 {
        return Err(Error::Unsupported);
    }
    // Both the endpoint and the driver-facing capability must claim allocation;
    // Linux checks all three bits before touching the control register.
    let tunnelling = read(phy, aux, TUNNELING_CAPABILITIES).await?;
    if tunnelling & CAP_DP_TUNNELING == 0 || tunnelling & CAP_DPIA_BW_ALLOC == 0 {
        return Err(Error::Unsupported);
    }
    if read(phy, aux, DRIVER_BW_CAPABILITY).await? & CAP_DRIVER_BW_ALLOC == 0 {
        return Err(Error::Unsupported);
    }
    // Take ownership of allocation for this endpoint and let it report changes.
    write(
        phy,
        aux,
        ALLOCATION_MODE_CONTROL,
        MODE_ENABLE | MODE_UNMASK_IRQ,
    )
    .await?;

    let granularity = granularity(read(phy, aux, BW_GRANULARITY).await?)?;
    let estimated_kbps = kbps_from_steps(read(phy, aux, ESTIMATED_BW).await?, granularity);
    let max_link_rate = read(phy, aux, MAX_LINK_RATE).await?;
    let max_lanes = read(phy, aux, MAX_LANE_COUNT).await? & 0x1f;

    let steps = steps_from_kbps(required_kbps, granularity);
    let request_kbps = kbps_from_steps(steps.min(u8::MAX as u32) as u8, granularity);
    // Linux clamps an over-large request down to the estimate. Clamping would
    // put a stream on a tunnel that cannot carry it, so refuse instead.
    if steps > u8::MAX as u32 || request_kbps > estimated_kbps {
        return Err(Error::Insufficient {
            estimated_kbps,
            required_kbps,
        });
    }

    // Clear any stale result before asking: the status bits are
    // write-one-to-clear, and a leftover "succeeded" would be read back as this
    // request's answer. If it cannot be cleared the answer cannot be trusted, so
    // that failure propagates rather than being swallowed.
    write(
        phy,
        aux,
        TUNNELING_STATUS,
        STATUS_REQUEST_FAILED | STATUS_REQUEST_SUCCEEDED,
    )
    .await?;
    write(phy, aux, REQUESTED_BW, steps as u8).await?;

    let deadline = narf_time::Deadline::after_ms(STATUS_TIMEOUT_MS);
    loop {
        let status = read(phy, aux, TUNNELING_STATUS).await?;
        if status & STATUS_REQUEST_FAILED != 0 {
            return Err(Error::Refused);
        }
        if status & STATUS_REQUEST_SUCCEEDED != 0 {
            break;
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
    }
    // Believe the router's own figure rather than the request.
    let allocated_kbps = kbps_from_steps(read(phy, aux, ALLOCATED_BW).await?, granularity);
    if allocated_kbps < required_kbps {
        return Err(Error::Insufficient {
            estimated_kbps: allocated_kbps,
            required_kbps,
        });
    }
    Ok(Allocation {
        granularity_steps_per_gbps: granularity,
        estimated_kbps,
        allocated_kbps,
        max_link_rate,
        max_lanes,
    })
}

/// Give the tunnel's bandwidth back. A stream that has stopped must not keep
/// holding an allocation the other endpoints could use.
pub async fn release(phy: &mut impl Phy, aux: u8) -> Result<(), Error> {
    write(phy, aux, REQUESTED_BW, 0).await
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dp_tunnel_tests.rs"]
mod tests;
