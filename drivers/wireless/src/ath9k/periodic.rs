// SPDX-License-Identifier: GPL-2.0-or-later
//! Current full-program AR9285 periodic calibration and ANI core.
//!
//! Each actual source operation retains a separately current measured P
//! qualification, serialized native ownership and actual live readback.
//! Existing static H1/2/3 and S1 programs remain unchanged and authorize none
//! of these writes. The source ANI owner shares the same retained receipt.
use super::packet::Error;
#[path = "periodic/ani.rs"]
mod ani;
#[path = "periodic/measurement.rs"]
mod measurement;
#[path = "periodic/noise.rs"]
mod noise;
#[path = "periodic/owner.rs"]
mod owner;
#[path = "periodic/pa.rs"]
mod pa;
#[path = "periodic/qualification.rs"]
mod qualification;
#[path = "periodic/receipt.rs"]
mod receipt;
#[path = "periodic/schedule.rs"]
mod schedule;
pub(super) use ani::{Ani, Plan as AniPlan, Rssi as BeaconRssi, Settings as AniSettings};
pub(super) use measurement::{Correction, Mode, Sampler, Step};
pub(super) use noise::Noise;
pub(super) use owner::{Context, Owner};
pub(super) use pa::{Pa, Update as PaUpdate};
pub use qualification::Request;
pub(super) use qualification::{request, Grant, Source};
pub(super) use receipt::{Live, Mutation, Receipt};
pub(super) use schedule::{Due, Schedule};
/// Each actual operation must execute within fresh P/base/PCI invocations.
/// The adapter may not route through a static-IQ readback while mutating the
/// calibration it is responsible for proving. Packet and Native provide the
/// retained current-source adapters; ordinary readback never enters this path.
pub(super) trait Io {
    fn read(&self, register: u64) -> Result<u32, Error>;
    fn write(&self, register: u64, value: u32) -> Result<(), Error>;
    fn now_us(&self) -> u64;
    /// Native adapter uses the scheduler's bounded responsive time primitive;
    /// this finite source sample settling is never a private register spin.
    fn delay_us(&self, microseconds: u64);
}
#[cfg(feature = "kernel-test")]
#[path = "periodic/tests.rs"]
pub(super) mod tests;
fn modify(io: &impl Io, register: u64, clear: u32, set: u32) -> Result<u32, Error> {
    let value = (io.read(register)? & !clear) | set;
    io.write(register, value)?;
    if io.read(register)? != value {
        return Err(Error::Descriptor);
    }
    Ok(value)
}
