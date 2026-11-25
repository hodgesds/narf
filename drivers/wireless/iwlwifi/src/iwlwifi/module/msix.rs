//! MSI-X for the module build: `iwl_msix`'s [`Interrupts`] and [`Activity`]
//! over the KABI.
//!
//! Built in, the transport reserves two MSI-X table entries routed to one
//! kernel vector whose hard-IRQ handler acknowledges and latches the causes.
//! A module gets one kernel vector per `narf_msix_claim` (table entries 0 and
//! 1 in claim order, which is exactly the built-in RX / non-RX entry split)
//! and a task-context callback per vector. Both callbacks run the same
//! acknowledge-and-latch the hard handler runs, count the interrupt and then
//! drive the module's executor, so a waiting [`Activity`] completes on this
//! CPU now instead of at the next 1 ms heartbeat.
//!
//! The latched state lives in a static, not in the owner: the kernel unbinds
//! the callbacks only at device teardown, so a callback can run after the
//! transport dropped its [`Interrupts`]; it then finds no owner and returns.

use super::{acknowledge, configure, mask, set_ivar, Causes};
use super::{CSR_MSIX_AUTOMASK_ST_AD, CSR_MSIX_FH_INT_MASK_AD, CSR_MSIX_RX_IVAR_AD_REG};
use crate::iwlwifi::module::device;
use crate::iwlwifi::module::kernel::narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use crate::iwlwifi::module::kernel::narf_capabilities::{Cap, Write};
use crate::iwlwifi::module::kernel::narf_lib::sync::IrqSafeSpinLock;
use crate::iwlwifi::module::kernel::narf_time::Deadline;
use core::sync::atomic::{AtomicU64, Ordering};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// KABI exports the interrupt owner calls.
mod ffi {
    unsafe extern "C" {
        pub fn narf_msix_enable(dev: u64) -> i32;
        pub fn narf_msix_claim(dev: u64, out_vector: *mut u16) -> i32;
        pub fn narf_irq_set_handler(dev: u64, vector: u16, callback: usize, cookie: u64) -> i32;
    }
}

const FH_ENABLED: u32 = 1 | (1 << 16) | (1 << 17) | (1 << 19) | (1 << 21);

struct Shared {
    mmio: super::super::IwlMmioImpl,
    pending: Causes,
}

/// The bound transport's registers and latched causes; `None` once its
/// owner is gone.
static SHARED: IrqSafeSpinLock<Option<Shared>> = IrqSafeSpinLock::new(None);
/// Callbacks taken (every vector), for [`Activity`].
static FIRES: AtomicU64 = AtomicU64::new(0);

/// Task-context upcall for one vector: acknowledge and latch, count, then run
/// the executor.
extern "C" fn callback(_vector: u64) -> i32 {
    {
        let mut shared = SHARED.lock();
        if let Some(state) = shared.as_mut() {
            let causes = acknowledge(&mut state.mmio);
            state.pending.fh |= causes.fh;
            state.pending.hw |= causes.hw;
        }
    }
    FIRES.fetch_add(1, Ordering::AcqRel);
    let _ = crate::iwlwifi::module::EXEC.run();
    0
}

/// The transport's interrupt owner (module build).
pub struct Interrupts {
    vectors: [u16; 2],
}
impl core::fmt::Debug for Interrupts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlInterrupts")
            .field("vectors", &self.vectors)
            .finish_non_exhaustive()
    }
}
impl Interrupts {
    pub fn new(
        cap: &Cap<BusDeviceCap, Write>,
        _device: &BusDevice,
        region: MmioRegion,
    ) -> Result<Self, &'static str> {
        if region.len < 0x28c0 {
            return Err("Wi-Fi BAR is too short for MSI-X");
        }
        if SHARED.lock().is_some() {
            return Err("Wi-Fi interrupts already owned");
        }
        let mut mmio = super::super::IwlMmioImpl::new(region, *cap);
        // Causes stay masked until `enable` programs the routing.
        mask(&mut mmio);
        // SAFETY: argument-only call on our probe token.
        match unsafe { ffi::narf_msix_enable(device()) } {
            0 => {}
            -95 => return Err("Wi-Fi has no MSI-X table"),
            _ => return Err("Wi-Fi MSI-X table unavailable"),
        }
        let mut vectors = [0u16; 2];
        for vector in &mut vectors {
            // SAFETY: `vector` is live `u16` storage.
            if unsafe { ffi::narf_msix_claim(device(), vector) } != 0 {
                return Err("Wi-Fi MSI-X table too small");
            }
        }
        // `irq_vector()` hands the transport a `u8`; a vector past it is
        // refused rather than truncated onto another device's.
        u8::try_from(vectors[0]).map_err(|_| "Wi-Fi MSI-X vector out of range")?;
        *SHARED.lock() = Some(Shared {
            mmio,
            pending: Causes::default(),
        });
        for vector in vectors {
            // SAFETY: `callback` is a valid `extern "C" fn(u64) -> i32` in
            // this image, which the kernel unbinds before unmapping it.
            if unsafe {
                ffi::narf_irq_set_handler(device(), vector, callback as usize, u64::from(vector))
            } != 0
            {
                *SHARED.lock() = None;
                return Err("cannot route Wi-Fi MSI-X");
            }
        }
        Ok(Self { vectors })
    }

    pub fn enable(&mut self, bz: bool) -> Result<(), &'static str> {
        let mut shared = SHARED.lock();
        let state = shared.as_mut().ok_or("Wi-Fi interrupts released")?;
        state.pending = Causes::default();
        configure(&mut state.mmio, bz);
        Ok(())
    }
    /// Additional RFH rings share the retained RX entry and vector.
    pub(in crate::iwlwifi) fn receive_queues(&mut self, count: u8) -> Result<(), &'static str> {
        if !(1..=16).contains(&count) {
            return Err("RFH interrupt queue count outside native mask");
        }
        let mut shared = SHARED.lock();
        let state = shared.as_mut().ok_or("Wi-Fi interrupts released")?;
        for queue in 1..count {
            set_ivar(&mut state.mmio, CSR_MSIX_RX_IVAR_AD_REG, queue, 0);
        }
        let receive = (1u32 << count) - 1;
        state
            .mmio
            .write(CSR_MSIX_FH_INT_MASK_AD, !(FH_ENABLED | receive));
        state.mmio.write(CSR_MSIX_AUTOMASK_ST_AD, 3);
        Ok(())
    }
    /// Mask every cause at the device. The KABI vectors stay bound until
    /// device teardown; masked causes never fire them.
    pub fn mask(&mut self) -> bool {
        if let Some(state) = SHARED.lock().as_mut() {
            mask(&mut state.mmio);
        }
        true
    }
    pub fn take_causes(&self) -> Causes {
        let mut shared = SHARED.lock();
        let Some(state) = shared.as_mut() else {
            return Causes::default();
        };
        let fresh = acknowledge(&mut state.mmio);
        let pending = core::mem::take(&mut state.pending);
        Causes {
            fh: fresh.fh | pending.fh,
            hw: fresh.hw | pending.hw,
        }
    }
    pub fn vector(&self) -> u8 {
        self.vectors[0] as u8
    }
}
impl Drop for Interrupts {
    fn drop(&mut self) {
        let _ = self.mask();
        *SHARED.lock() = None;
    }
}

use super::super::transport::IwlMmio as _;

/// Construct BEFORE inspecting rings, so a completion between drain and
/// await cannot be lost: it counts the callbacks taken since construction.
/// The deadline also bounds waits for lost interrupts/recovery.
#[derive(Debug)]
pub struct Activity {
    seen: u64,
    irq: bool,
    deadline: Deadline,
    yielded: bool,
}
impl Activity {
    pub fn new(vector: Option<u8>, max_ms: u64) -> Self {
        Self {
            seen: FIRES.load(Ordering::Acquire),
            irq: vector.is_some(),
            deadline: Deadline::after_ms(if vector.is_some() { max_ms } else { 1 }),
            yielded: false,
        }
    }
}
impl Future for Activity {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // As built in: always yield once per wait, so one poll cannot spin
        // through an unbounded sequence of completions.
        if !self.yielded {
            self.yielded = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if (self.irq && FIRES.load(Ordering::Acquire) != self.seen) || self.deadline.expired() {
            return Poll::Ready(());
        }
        // No waker to arm: the vector callbacks and the 1 ms poller run the
        // executor, which re-polls every task.
        Poll::Pending
    }
}
