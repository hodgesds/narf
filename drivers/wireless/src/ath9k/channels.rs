// SPDX-License-Identifier: GPL-2.0-or-later
//! Driver-owned cold channel generations. A public waiter cannot cancel RF
//! reset/calibration after the old generation has been physically retired.
use super::*;
use alloc::{boxed::Box, task::Wake, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
type Error = station::Error;
pub(super) type Successor = Arc<dyn interface::ChannelIface>;
pub(super) type Transition =
    Pin<Box<dyn Future<Output = Result<Successor, Error>> + Send + 'static>>;
struct Completion {
    result: Option<Result<Successor, Error>>,
    waiters: Vec<Waker>,
}
type Slot = Arc<IrqSafeSpinLock<Completion>>;
struct DriverWake(IrqSafeSpinLock<Option<Waker>>);
impl Wake for DriverWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let worker = self.0.lock().clone();
        if let Some(worker) = worker {
            worker.wake();
        }
    }
}
struct Work {
    geometry: channel_width::Geometry,
    source: Option<[u8; 32]>,
    generation: u32,
    result: Slot,
    future: Transition,
    wake: Arc<DriverWake>,
}
static WORK: Mutex<Option<Work>> = Mutex::new(None);
/// IEEE channel of a 20 MHz primary in either band (2.4 GHz 1..=13; the
/// AR9280 5 GHz set of `phy::ar9280::channel_5ghz`). Whether a radio may
/// use it is its `channel_mask`, never this numbering.
pub(super) fn channel(frequency: u16) -> Result<u8, Error> {
    if let Some(channel) = phy::ar9280::channel_5ghz(frequency) {
        return Ok(channel);
    }
    if !(2412..=2472).contains(&frequency) || (frequency - 2412) % 5 != 0 {
        return Err(Error::Profile);
    }
    Ok(((frequency - 2407) / 5) as u8)
}
pub(super) fn frequency(channel: u32) -> Result<u16, Error> {
    if (1..=13).contains(&channel) {
        return Ok(2407 + 5 * channel as u16);
    }
    let channel = u16::try_from(channel).map_err(|_| Error::Profile)?;
    let frequency = channel
        .checked_mul(5)
        .and_then(|f| f.checked_add(5000))
        .ok_or(Error::Profile)?;
    phy::ar9280::channel_5ghz(frequency).ok_or(Error::Profile)?;
    Ok(frequency)
}
/// Number of `channel_mask` bits: 13 at 2.4 GHz, then the 25 5 GHz
/// channels in ascending order.
pub(super) const CHANNEL_BITS: u32 = 38;
/// `channel_mask` bit of a 20 MHz primary: 2.4 GHz channel `n` is bit
/// `n - 1` (the historical AR9285/AR9287 mask), 5 GHz channels follow.
pub(super) fn bit(frequency: u16) -> Option<u32> {
    if let Some(channel) = phy::ar9280::channel_5ghz(frequency) {
        let channel = u32::from(channel);
        return Some(match channel {
            36..=64 => 13 + (channel - 36) / 4,
            100..=144 => 21 + (channel - 100) / 4,
            _ => 33 + (channel - 149) / 4,
        });
    }
    channel(frequency)
        .ok()
        .map(|channel| u32::from(channel) - 1)
}
/// The primary of `channel_mask` bit `bit` (inverse of `bit`).
pub(super) fn bit_frequency(bit: u32) -> Option<u16> {
    let channel = match bit {
        0..=12 => return Some(2412 + 5 * bit as u16),
        13..=20 => 36 + 4 * (bit - 13),
        21..=32 => 100 + 4 * (bit - 21),
        33..=37 => 149 + 4 * (bit - 33),
        _ => return None,
    };
    Some(5000 + 5 * channel as u16)
}
/// Whether `mask` admits the 20 MHz primary `frequency`.
pub(super) fn admits(mask: u64, frequency: u16) -> bool {
    bit(frequency).is_some_and(|bit| mask & (1 << bit) != 0)
}
pub(super) fn request(frequency: u16, generation: u32) -> Result<Transition, Error> {
    channel(frequency)?;
    request_geometry(
        channel_width::Geometry::from_frequency_dual(frequency).map_err(|_| Error::Profile)?,
        generation,
        None,
    )
}
pub(super) fn request_geometry(
    geometry: channel_width::Geometry,
    generation: u32,
    wide: Option<Arc<ht40::Grant>>,
) -> Result<Transition, Error> {
    let source = wide.as_ref().map(|grant| grant.ba_identity().1);
    if geometry.is_wide() != wide.is_some() {
        return Err(Error::Profile);
    }
    let result = {
        let mut slot = WORK.try_lock().ok_or(Error::Busy)?;
        if let Some(work) = slot.as_ref() {
            if work.geometry != geometry || work.source != source || work.generation != generation {
                return Err(Error::Busy);
            }
            work.result.clone()
        } else {
            let ar9285 = CONTROLLER.lock().clone();
            let has_ar9285 = ar9285.is_some();
            let reset: Pin<Box<dyn Future<Output = Result<(), BringUpError>> + Send>> =
                if let Some(owner) = ar9285.filter(|_| !geometry.is_5ghz()) {
                    // Count the accepted original request before it waits for
                    // CONTROL; an idle request cannot retire hardware from
                    // under queued work.
                    let awake = owner.idle.use_awake(false).map_err(|_| Error::Busy)?;
                    Box::pin(async move {
                        let _awake = awake;
                        super::reset_owner_geometry(&owner, Some(geometry), Some(generation), wide)
                            .await
                            .map(|_| ())
                    })
                } else if has_ar9285 {
                    // AR9285 has no 5 GHz path.
                    return Err(Error::Profile);
                } else if wide.is_some() {
                    return Err(Error::Profile);
                } else if let Some(reset) =
                    super::ar9280_owner::transition(geometry.control(), generation)
                {
                    // The dual-band AR9280 owner (either band, 20 MHz).
                    Box::pin(reset)
                } else if let Some(reset) =
                    super::ar5008_owner::transition(geometry.control(), generation)
                {
                    // The AR5416/AR5418/AR9160 owner (bands its map enables).
                    Box::pin(reset)
                } else if !geometry.is_5ghz() {
                    // The chip-generic AR9287 owner (no HT40 owner exists).
                    Box::pin(
                        super::ar9287_owner::transition(geometry.control(), generation)
                            .ok_or(Error::State)?,
                    )
                } else {
                    return Err(Error::Profile);
                };
            let result = Arc::new(IrqSafeSpinLock::new(Completion {
                result: None,
                waiters: Vec::new(),
            }));
            let wake = Arc::new(DriverWake(IrqSafeSpinLock::new(None)));
            *slot = Some(Work {
                geometry,
                source,
                generation,
                result: result.clone(),
                wake: wake.clone(),
                future: Box::pin(async move {
                    reset.await.map_err(|e| match e {
                        BringUpError::Policy => Error::Profile,
                        BringUpError::DeviceGone => Error::Transport(packet::Error::Access),
                        _ => Error::State,
                    })?;
                    let device = interface::current().ok_or(Error::State)?;
                    let correct = device.radio.try_lock().is_some_and(|r| {
                        r.frequency_mhz() == geometry.control()
                            && (r.geometry() == geometry || r.geometry() == geometry.twenty())
                            && r.phase() == station::Phase::Passive
                    });
                    if !correct {
                        return Err(Error::State);
                    }
                    Ok(device as Successor)
                }),
            });
            let completed = result.clone();
            narf_scheduler::spawn(core::future::poll_fn(move |cx| {
                *wake.0.lock() = Some(cx.waker().clone());
                poll(cx);
                if completed.lock().result.is_some() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }));
            result
        }
    };
    Ok(Box::pin(core::future::poll_fn(move |cx| {
        {
            let mut completion = result.lock();
            if let Some(result) = &completion.result {
                return Poll::Ready(result.clone());
            }
            if !completion.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                if completion.waiters.len() == 16 {
                    return Poll::Ready(Err(Error::Busy));
                }
                completion.waiters.push(cx.waker().clone());
            }
        }
        poll(cx);
        let ready = result.lock().result.clone();
        match ready {
            Some(result) => Poll::Ready(result),
            None => Poll::Pending,
        }
    })))
}
/// The physical supervisor calls this even when all public waiters are gone.
/// Only a regular mutex spans the native future poll; no IRQ guard does.
pub(super) fn poll(cx: &mut Context<'_>) {
    let Some(mut slot) = WORK.try_lock() else {
        cx.waker().wake_by_ref();
        return;
    };
    let Some(work) = slot.as_mut() else {
        return;
    };
    let wake = Waker::from(work.wake.clone());
    let mut native = Context::from_waker(&wake);
    if let Poll::Ready(result) = work.future.as_mut().poll(&mut native) {
        let wake = {
            let mut completion = work.result.lock();
            completion.result = Some(result);
            core::mem::take(&mut completion.waiters)
        };
        *slot = None;
        drop(slot);
        for waker in wake {
            waker.wake();
        }
    }
}
