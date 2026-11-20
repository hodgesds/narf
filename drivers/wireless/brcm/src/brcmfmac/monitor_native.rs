// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual native monitor configuration/format receipts, not metadata claims.
//! The public opaque Armed token can only be created after source-qualified
//! firmware capability, monitor-filter and exact channel readbacks.
use super::{
    monitor_scope::{Capture, Received},
    monitor_wire,
};
use crate::cyw43439::{fullmac::Fullmac, ioctl::Direction, runtime::Error};
use alloc::vec::Vec;
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};

pub(super) enum Guard<'a> {
    Program(&'a Capture),
    Stop(&'a super::ap_source::Source),
}
impl Guard<'_> {
    fn current(&self) -> Result<(), Error> {
        match self {
            Self::Program(original) => original.command_current(),
            Self::Stop(native) => native.current().map_err(|_| Error::Authority),
        }
    }
}
async fn command<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    direction: Direction,
    id: u32,
    input: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    guard.current()?;
    let mut future = pin!(runtime.command(direction, id, input, maximum));
    poll_fn(|cx| {
        if let Err(error) = guard.current() {
            return Poll::Ready(Err(error));
        }
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(guard.current().and(result)),
        }
    })
    .await
}
async fn get<R: Fullmac>(runtime: &mut R, guard: &Guard<'_>, id: u32) -> Result<u32, Error> {
    let bytes = command(runtime, guard, Direction::Get, id, &[], 4).await?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| Error::Malformed)?,
    ))
}
async fn set<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    id: u32,
    value: u32,
) -> Result<(), Error> {
    command(runtime, guard, Direction::Set, id, &value.to_le_bytes(), 4)
        .await
        .map(|_| ())
}
async fn get_var<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    name: &[u8],
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    command(runtime, guard, Direction::Get, 262, name, maximum).await
}
async fn get_int<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    name: &[u8],
) -> Result<u32, Error> {
    let bytes = get_var(runtime, guard, name, 4).await?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| Error::Malformed)?,
    ))
}
async fn set_int<R: Fullmac>(
    runtime: &mut R,
    guard: &Guard<'_>,
    name: &[u8],
    value: u32,
) -> Result<(), Error> {
    let mut input = name.to_vec();
    input.extend_from_slice(&value.to_le_bytes());
    command(runtime, guard, Direction::Set, 263, &input, input.len()).await?;
    if get_int(runtime, guard, name).await? != value {
        return Err(Error::Malformed);
    }
    Ok(())
}
#[derive(Clone)]
struct Saved {
    chanspec: u32,
}
#[derive(Clone)]
pub struct Prepared {
    original: Capture,
    saved: Saved,
    capabilities: [u8; 32],
}
impl core::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacNativeMonitorPrepared")
            .finish_non_exhaustive()
    }
}
impl Prepared {
    pub(super) fn original(&self) -> &Capture {
        &self.original
    }
    pub(super) fn accepts(&self, armed: &Armed) -> bool {
        self.original.same_owner(armed.original())
            && self.capabilities == armed.prepared.capabilities
    }
    pub(super) fn belongs_to(&self, native: &super::ap_source::Source) -> bool {
        self.original.native.same_generation(native)
    }
}
/// Native receipt constructor is private. Neither firmware-cap strings nor
/// a copied Source/Channel struct alone can open Runtime raw RX dispatch.
#[derive(Clone)]
pub struct Armed {
    prepared: Prepared,
}
impl core::fmt::Debug for Armed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacNativeMonitorArmed")
            .finish_non_exhaustive()
    }
}
impl Armed {
    pub(super) fn original(&self) -> &Capture {
        &self.prepared.original
    }
    pub(super) fn receive(&self, bytes: &[u8]) -> Result<Option<Received>, Error> {
        // Permission retirement drops the owned copy while continuing actual
        // matching DMA retirement/repost during denial-only native stop.
        if self.original().current().is_err() {
            return Ok(None);
        }
        let bytes = monitor_wire::packet(bytes, self.original().frequency)?;
        self.original().current()?;
        Ok(Some(Received::new(bytes, self.original().clone())))
    }
}
pub(super) async fn prepare<R: Fullmac>(
    runtime: &mut R,
    original: &Capture,
) -> Result<Prepared, Error> {
    let guard = Guard::Program(original);
    let caps = get_var(runtime, &guard, b"cap\0", 768).await?;
    if !monitor_wire::flagged_radiotap(&caps)? {
        return Err(Error::Unsupported);
    }
    if get(runtime, &guard, 107).await? != 0 || get(runtime, &guard, 117).await? != 0 {
        return Err(Error::Busy);
    }
    let peers = command(
        runtime,
        &guard,
        Direction::Get,
        159,
        &32u32.to_le_bytes(),
        196,
    )
    .await?;
    if !super::ap_wire::associations(&peers, 32)?.is_empty() {
        return Err(Error::Busy);
    }
    let saved = Saved {
        chanspec: get_int(runtime, &guard, b"chanspec\0").await?,
    };
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(&caps);
    Ok(Prepared {
        original: original.clone(),
        saved,
        capabilities: hash.finalize(),
    })
}
/// Metadata-only prepublication discovery. Actual monitor operation still
/// re-qualifies this reply through the original user/mode/policy/native owner.
pub(crate) async fn discovery<R: Fullmac>(runtime: &mut R) -> Result<bool, Error> {
    if !R::PRIMARY_MONITOR {
        return Ok(false);
    }
    let Some(native) = runtime.ap_source() else {
        return Ok(false);
    };
    let caps = get_var(runtime, &Guard::Stop(&native), b"cap\0", 768).await?;
    monitor_wire::flagged_radiotap(&caps)
}
pub(super) async fn start<R: Fullmac>(
    runtime: &mut R,
    prepared: &Prepared,
) -> Result<Armed, Error> {
    let original = &prepared.original;
    let guard = Guard::Program(original);
    // Native chanspec20 SET/readback follows brcmf_set_channel, not a BSS,
    // scan or AP authority. No packet/transmit path is enabled.
    set_int(runtime, &guard, b"chanspec\0", u32::from(original.chanspec)).await?;
    set(runtime, &guard, 108, 3).await?;
    if get(runtime, &guard, 107).await? != 3
        || get_int(runtime, &guard, b"chanspec\0").await? != u32::from(original.chanspec)
    {
        return Err(Error::Malformed);
    }
    // Re-read the actual immutable format after native configuration. A
    // policy/source/mode change at any wait cannot become a fresh grant.
    let caps = get_var(runtime, &guard, b"cap\0", 768).await?;
    if !monitor_wire::flagged_radiotap(&caps)? {
        return Err(Error::Unsupported);
    }
    // Reservation identity remains the original source/mode/channel proof.
    // Other capability text or padding is not an invented byte-equality
    // protocol requirement; the actual flag/format must still be present.
    Ok(Armed {
        prepared: prepared.clone(),
    })
}
pub(super) async fn stop<R: Fullmac>(runtime: &mut R, prepared: &Prepared) -> Result<(), Error> {
    let original = &prepared.original;
    let saved = &prepared.saved;
    let guard = Guard::Stop(&original.native);
    set(runtime, &guard, 108, 0).await?;
    if get(runtime, &guard, 107).await? != 0 {
        return Err(Error::Malformed);
    }
    set_int(runtime, &guard, b"chanspec\0", saved.chanspec).await
}
