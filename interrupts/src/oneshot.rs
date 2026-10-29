// SPDX-License-Identifier: GPL-2.0-or-later
//! Oneshot level-triggered legacy INTx for a device whose interrupt source
//! can only be cleared by its owning task (Linux `request_threaded_irq` with
//! a NULL primary handler and `IRQF_ONESHOT`, delivered by
//! `handle_fasteoi_irq`).
//!
//! The hard half never touches the device: it masks the line at the
//! interrupt controller, counts the delivery and runs the owner's notify
//! callback (which must only wake). The trap's EOI then retires Remote IRR
//! with the line masked, so a still-asserted level line cannot re-fire.
//! The owner services the device, clears its source and calls
//! [`Line::unmask`]; a line still asserted at that point is delivered again.
//!
//! Only an exclusive GSI is supported: masking a line shared with handlers
//! that clear their device synchronously would stall them until this owner
//! unmasks. A live (unmasked) route therefore refuses with
//! [`Error::Shared`], and the caller keeps polling. x86_64 IOAPIC only;
//! other architectures return [`Error::Unsupported`] (no PCI INTx-to-SPI
//! `interrupt-map` exists for aarch64 yet).
use crate::dispatch::{self, IrqStatus};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No IOAPIC oneshot support on this architecture.
    Unsupported,
    /// The GSI already has a live route (another owner or a shared line).
    Shared,
    /// No dispatch vector is available.
    NoVector,
    /// The GSI is outside every MADT IOAPIC.
    Route,
}

type Notify = Arc<dyn Fn() + Send + Sync>;

struct State {
    gsi: u32,
    notify: Notify,
    /// Controller mask state; transitions are serialized so an unmask can
    /// never race a delivery that has just masked the line.
    masked: IrqSafeSpinLock<bool>,
    fires: AtomicU64,
}

/// An exclusively owned oneshot INTx line. Dropping it masks the route,
/// removes the handler, waits for an in-flight handler and frees the vector.
pub struct Line {
    state: Arc<State>,
    vector: u8,
    name: &'static str,
}
impl core::fmt::Debug for Line {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OneshotLine")
            .field("gsi", &self.state.gsi)
            .field("vector", &self.vector)
            .field("fires", &self.fires())
            .finish()
    }
}

#[cfg(target_arch = "x86_64")]
fn set_masked(gsi: u32, masked: bool) {
    // SAFETY: the line was bound from a validated MADT route this owner
    // exclusively holds; only the mask bit changes.
    unsafe {
        narf_acpi::ioapic::set_gsi_masked(gsi, masked);
    }
}
#[cfg(not(target_arch = "x86_64"))]
fn set_masked(_: u32, _: bool) {}

/// Hard-IRQ half: mask at the controller, count, wake the owner.
fn handler(cookie: u64) -> IrqStatus {
    // SAFETY: `cookie` is the `Arc<State>` pointer the `Line` keeps alive
    // until its handler is removed and synchronized.
    let state = unsafe { &*(cookie as *const State) };
    {
        let mut masked = state.masked.lock();
        set_masked(state.gsi, true);
        *masked = true;
    }
    state.fires.fetch_add(1, Ordering::AcqRel);
    (state.notify)();
    IrqStatus::Handled
}

impl Line {
    /// Bind `gsi` level-triggered/active-low (PCI INTx) to a fresh vector,
    /// left **masked**: call [`Self::unmask`] once the device's interrupt
    /// sources are configured.
    ///
    /// # Safety
    /// MADT/IOAPIC initialization precedes this call, and the caller
    /// exclusively owns the device whose interrupt pin routes to `gsi`.
    pub unsafe fn bind_exclusive(
        gsi: u32,
        name: &'static str,
        notify: Notify,
    ) -> Result<Self, Error> {
        #[cfg(target_arch = "x86_64")]
        {
            use narf_acpi::ioapic::{
                gsi_route, route_gsi_to_vector, MASKED, POLARITY_LOW, TRIGGER_LEVEL,
            };
            // SAFETY: caller-asserted live MADT/IOAPIC.
            let (_, _, low) = unsafe { gsi_route(gsi) }.ok_or(Error::Route)?;
            if low & MASKED == 0 {
                return Err(Error::Shared);
            }
            let vector = crate::vector::alloc().map_err(|_| Error::NoVector)?;
            let state = Arc::new(State {
                gsi,
                notify,
                masked: IrqSafeSpinLock::new(true),
                fires: AtomicU64::new(0),
            });
            let cookie = Arc::as_ptr(&state) as u64;
            dispatch::install_handler_named(vector, name, cookie, handler);
            // SAFETY: caller-asserted live interrupt controller.
            let target = unsafe { crate::current_cpu_target_id() } as u8;
            // SAFETY: fresh vector with its handler installed; route masked.
            if !unsafe {
                route_gsi_to_vector(gsi, vector, target, POLARITY_LOW | TRIGGER_LEVEL | MASKED)
            } {
                dispatch::remove_handler(vector, name, cookie);
                dispatch::synchronize_irq(vector);
                let _ = crate::vector::free(vector);
                return Err(Error::Route);
            }
            Ok(Self {
                state,
                vector,
                name,
            })
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (gsi, name, notify);
            Err(Error::Unsupported)
        }
    }
    /// Re-enable delivery after the owner cleared the device source.
    /// Idempotent; a still-asserted line is delivered again.
    pub fn unmask(&self) {
        let mut masked = self.state.masked.lock();
        if *masked {
            set_masked(self.state.gsi, false);
            *masked = false;
        }
    }
    pub fn masked(&self) -> bool {
        *self.state.masked.lock()
    }
    /// Deliveries taken by the hard half.
    pub fn fires(&self) -> u64 {
        self.state.fires.load(Ordering::Acquire)
    }
    pub fn gsi(&self) -> u32 {
        self.state.gsi
    }
    pub fn vector(&self) -> u8 {
        self.vector
    }
    /// Run the hard half exactly as dispatch would (tests and diagnostics).
    pub fn deliver_for_test(&self) -> IrqStatus {
        handler(Arc::as_ptr(&self.state) as u64)
    }
}
impl Drop for Line {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: this owner programmed the route; masking it first stops
        // delivery before the handler is removed.
        unsafe {
            narf_acpi::ioapic::route_gsi_to_vector(
                self.state.gsi,
                self.vector,
                0,
                narf_acpi::ioapic::MASKED,
            );
        }
        let cookie = Arc::as_ptr(&self.state) as u64;
        dispatch::remove_handler(self.vector, self.name, cookie);
        dispatch::synchronize_irq(self.vector);
        let _ = crate::vector::free(self.vector);
    }
}

#[path = "oneshot_tests.rs"]
mod tests;
