//! Owned MSI-X routing: entry 0 for admin/fatal causes, entries 1..N for queue pairs.
//! Hard IRQs mask and record; executor tasks drain and rearm. Cookie storage
//! outlives disable/remove/synchronize on every setup failure and teardown.

use super::{irq::*, I40eError};
use alloc::boxed::Box;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, Write};
use narf_interrupts::{dispatch, vector};
use narf_lib::sync::IrqSafeSpinLock;

pub const ADMINQ: u32 = 1 << 30;
pub const FATAL: u32 = (1 << 16) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 26);
// Select no ITR bank while masking/rearming, preserving programmed moderation.
const MASK: u32 = (ITR_IDX_NONE as u32) << 3;
const ARM: u32 = 1 | 2 | MASK;

struct Shared {
    csr: MmioRegion,
    failed: bool,
    queues: u16,
}

impl Shared {
    fn mask(&self) {
        // SAFETY: mapping covers the CSR registers and owner serializes writes.
        unsafe {
            self.csr.write32(REG_PFINT_ICR0_ENA, 0);
            self.csr.write32(REG_PFINT_DYN_CTL0, MASK);
            for q in 0..self.queues {
                self.csr.write32(reg_pfint_dyn_ctln(q), MASK);
            }
            self.csr.read32(REG_PFINT_ICR0_ENA);
        }
    }
}

fn admin_handler(cookie: u64) -> dispatch::IrqStatus {
    // SAFETY: stable Box owned until handler removal and synchronization.
    let shared = unsafe { &*(cookie as *const IrqSafeSpinLock<Shared>) };
    let mut state = shared.lock();
    // SAFETY: exclusively owned, live CSR window; ICR0 is read-to-clear.
    let cause = unsafe {
        state.csr.write32(REG_PFINT_DYN_CTL0, MASK);
        state.csr.read32(REG_PFINT_ICR0)
    };
    if cause & FATAL != 0 {
        state.failed = true;
        state.mask();
    }
    dispatch::IrqStatus::Handled
}

struct QueueCookie {
    shared: *const IrqSafeSpinLock<Shared>,
    queue: u16,
}

fn queue_handler(cookie: u64) -> dispatch::IrqStatus {
    // SAFETY: both boxes remain alive until removal and synchronization.
    let cookie = unsafe { &*(cookie as *const QueueCookie) };
    // SAFETY: cookie and shared owner are released only after synchronize_irq.
    let state = unsafe { &*cookie.shared }.lock();
    // SAFETY: queue was reserved in this PF's vector range.
    unsafe {
        state.csr.write32(reg_pfint_dyn_ctln(cookie.queue), MASK);
    }
    dispatch::IrqStatus::Handled
}

pub(super) struct Interrupts {
    // None only in the memory-backed driver fixture.
    table: Option<MsixTable>,
    vectors: alloc::vec::Vec<u8>,
    // IRQ dispatch holds raw addresses even while the Vec grows.
    #[allow(clippy::vec_box)]
    cookies: alloc::vec::Vec<Box<QueueCookie>>,
    shared: Box<IrqSafeSpinLock<Shared>>,
}

impl Interrupts {
    pub fn new(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
        csr: MmioRegion,
        requested: u16,
    ) -> Result<Self, I40eError> {
        let bad = I40eError::InterruptSetup;
        let mut table = narf_bus::enable_msix(cap, device).map_err(|_| bad)?;
        let count = super::rss::queue_count(
            requested,
            table.size().saturating_sub(1),
            super::MAX_QUEUE_PAIRS,
        )?;
        // SAFETY: exclusive PF ownership, no handlers registered yet.
        unsafe {
            table.disable();
        }
        let mut vectors = alloc::vec::Vec::new();
        for _ in 0..=count {
            match vector::alloc() {
                Ok(v) => vectors.push(v),
                Err(_) => break,
            }
        }
        if vectors.len() < 2 {
            for v in vectors {
                let _ = vector::free(v);
            }
            return Err(bad);
        }
        let count = super::rss::queue_count(count, (vectors.len() - 1) as u16, count)?;
        while vectors.len() > count as usize + 1 {
            let _ = vector::free(vectors.pop().unwrap());
        }
        // Table has enough entries by construction.
        table.alloc_block(count + 1).map_err(|_| bad)?;
        let shared = Box::new(IrqSafeSpinLock::new(Shared {
            csr,
            failed: false,
            queues: count,
        }));
        shared.lock().mask();
        // SAFETY: clear reset-era causes before publishing any DMA state.
        unsafe {
            csr.read32(REG_PFINT_ICR0);
        }
        let ptr = &*shared as *const IrqSafeSpinLock<Shared>;
        let mut cookies = alloc::vec::Vec::new();
        dispatch::install_handler_named(vectors[0], "i40e-admin", ptr as u64, admin_handler);
        dispatch::enable_irq(vectors[0]);
        for q in 0..count {
            let cookie = Box::new(QueueCookie {
                shared: ptr,
                queue: q,
            });
            dispatch::install_handler_named(
                vectors[q as usize + 1],
                "i40e-queue",
                &*cookie as *const QueueCookie as u64,
                queue_handler,
            );
            dispatch::enable_irq(vectors[q as usize + 1]);
            cookies.push(cookie);
        }
        // From here every setup failure runs Drop, removing all installed handlers.
        let mut this = Self {
            table: Some(table),
            vectors,
            cookies,
            shared,
        };
        this.program_table()?;
        Ok(this)
    }

    /// Memory-backed fixture only; bypasses PCI accesses, retaining real IRQ routing.
    pub(super) fn simulated(csr: MmioRegion, count: u16) -> Self {
        let shared = Box::new(IrqSafeSpinLock::new(Shared {
            csr,
            failed: false,
            queues: count,
        }));
        let ptr = &*shared as *const IrqSafeSpinLock<Shared>;
        let mut vectors = alloc::vec::Vec::new();
        let mut cookies = alloc::vec::Vec::new();
        let admin = vector::alloc().unwrap();
        dispatch::install_handler_named(admin, "i40e-admin", ptr as u64, admin_handler);
        dispatch::enable_irq(admin);
        vectors.push(admin);
        for queue in 0..count {
            let v = vector::alloc().unwrap();
            let cookie = Box::new(QueueCookie { shared: ptr, queue });
            dispatch::install_handler_named(
                v,
                "i40e-queue",
                &*cookie as *const QueueCookie as u64,
                queue_handler,
            );
            dispatch::enable_irq(v);
            vectors.push(v);
            cookies.push(cookie);
        }
        Self {
            table: None,
            vectors,
            cookies,
            shared,
        }
    }

    fn program_table(&mut self) -> Result<(), I40eError> {
        let Some(table) = self.table.as_mut() else {
            return Ok(());
        };
        for (index, &vector) in self.vectors.iter().enumerate() {
            #[cfg(target_arch = "x86_64")]
            let cpu = super::rss::queue_cpu(index.saturating_sub(1));
            #[cfg(target_arch = "x86_64")]
            let target = narf_interrupts::apic_id_at(cpu as usize)
                .filter(|&id| id <= 255)
                .or_else(|| {
                    // SAFETY: interrupt controller is initialized before PCI probe.
                    Some(unsafe { narf_interrupts::current_cpu_target_id() })
                })
                .filter(|&id| id <= 255)
                .ok_or(I40eError::InterruptSetup)?;
            #[cfg(target_arch = "aarch64")]
            // The ITS currently publishes only collection 0. Queue workers
            // can still run on any CPU; do not target an unmapped collection.
            let target = 0;
            // SAFETY: reserved entries; table disabled until enable finishes.
            unsafe { table.program_vector(index as u16, target, vector) }
                .map_err(|_| I40eError::InterruptSetup)?;
        }
        Ok(())
    }

    /// Mask PCI/device delivery and wait out in-flight handlers before reset.
    pub fn quiesce(&mut self) {
        self.fail();
        // SAFETY: owned table; handlers and cookies remain installed/alive.
        unsafe {
            if let Some(table) = self.table.as_mut() {
                table.disable();
            }
        }
        for &vector in &self.vectors {
            dispatch::synchronize_irq(vector);
        }
    }

    /// Only the exclusive recovery owner may clear a failure after reset.
    pub fn reset_complete(&mut self) {
        let mut state = self.shared.lock();
        // SAFETY: reset completed, old DMA and cause state are no longer live.
        unsafe {
            state.csr.read32(REG_PFINT_ICR0);
        }
        state.failed = false;
    }

    pub fn enable(&mut self, count: u16) -> Result<(), I40eError> {
        if count == 0 || count > self.queue_count() {
            return Err(I40eError::InterruptSetup);
        }
        self.program_table()?;
        {
            let mut state = self.shared.lock();
            // SAFETY: offsets validated by BAR size and bounded queue count.
            unsafe {
                if state.failed || state.csr.read32(REG_PFINT_ICR0) & FATAL != 0 {
                    state.failed = true;
                    state.mask();
                    return Err(I40eError::DeviceFailed);
                }
                state.csr.write32(REG_PFINT_LNKLST0, QUEUE_END_OF_LIST);
                state.csr.write32(0x0003_8400, 0); // PFINT_STAT_CTL0
                for q in 0..count {
                    state.csr.write32(0x0003_5800 + q as u64 * 4, 0); // PFINT_RATEN(q)
                    for write in build_vector_chain(q + 1, q, 1)
                        .map_err(|_| I40eError::InterruptSetup)?
                        .into_iter()
                        .chain(
                            build_vector_itr(q + 1, ITR_20K, ITR_8K)
                                .map_err(|_| I40eError::InterruptSetup)?,
                        )
                    {
                        state.csr.write32(write.reg, write.value);
                    }
                }
                state.csr.write32(REG_PFINT_ICR0_ENA, ADMINQ | FATAL);
            }
        }
        // SAFETY: table entries and all chains initialized.
        unsafe {
            if let Some(table) = self.table.as_mut() {
                table.enable().map_err(|_| I40eError::InterruptSetup)?;
            }
        }
        self.rearm_admin();
        for q in 0..count {
            self.rearm_queue(q as usize);
        }
        Ok(())
    }

    pub fn queue_count(&self) -> u16 {
        (self.vectors.len() - 1) as u16
    }
    pub fn admin_vector(&self) -> u8 {
        self.vectors[0]
    }
    pub fn queue_vector(&self, queue: usize) -> u8 {
        self.vectors[queue + 1]
    }
    pub fn failed(&self) -> bool {
        self.shared.lock().failed
    }
    pub fn fail(&self) {
        let mut state = self.shared.lock();
        state.failed = true;
        state.mask();
    }
    fn rearm(&self, register: u64) {
        let state = self.shared.lock();
        if !state.failed {
            // SAFETY: validated dynamic-control offsets; preserve ITR banks.
            unsafe {
                state.csr.write32(register, ARM);
                state.csr.read32(REG_PFINT_ICR0_ENA);
            }
        }
    }
    pub fn rearm_admin(&self) {
        self.rearm(REG_PFINT_DYN_CTL0);
    }
    pub fn rearm_queue(&self, queue: usize) {
        self.rearm(reg_pfint_dyn_ctln(queue as u16));
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        self.quiesce();
        for (index, &vector) in self.vectors.iter().enumerate() {
            let (name, cookie) = if index == 0 {
                (
                    "i40e-admin",
                    &*self.shared as *const IrqSafeSpinLock<Shared> as u64,
                )
            } else {
                (
                    "i40e-queue",
                    &*self.cookies[index - 1] as *const QueueCookie as u64,
                )
            };
            dispatch::disable_irq(vector);
            dispatch::remove_handler(vector, name, cookie);
            dispatch::synchronize_irq(vector);
            let _ = vector::free(vector);
        }
    }
}

mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_i40e_irq_mask_wakeup_and_fatal() -> TestResult {
        let mut memory =
            narf_io::alloc_coherent(0x40000, narf_lib::id::DomainId::DRIVER_0).unwrap();
        memory.as_mut_slice().fill(0);
        let csr = MmioRegion {
            phys: memory.phys_addr(),
            virt: memory.as_mut_ptr() as u64,
            len: memory.len() as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let shared = Box::new(IrqSafeSpinLock::new(Shared {
            csr,
            failed: false,
            queues: 1,
        }));
        let cookie = (&*shared as *const IrqSafeSpinLock<Shared>) as u64;
        let queue_cookie = Box::new(QueueCookie {
            shared: &*shared,
            queue: 0,
        });
        let qcookie = &*queue_cookie as *const QueueCookie as u64;
        let vector = vector::alloc().unwrap();
        dispatch::enable_irq(vector);
        dispatch::install_handler_named(vector, "i40e-queue-test", qcookie, queue_handler);
        let mut activity = pin!(narf_interrupts::wait::wait_for_irq(vector));
        // Trigger between the caller's empty-queue observation and first poll.
        dispatch::on_irq(vector);
        let awake = matches!(
            activity
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(_)
        );
        dispatch::disable_irq(vector);
        dispatch::remove_handler(vector, "i40e-queue-test", qcookie);
        dispatch::synchronize_irq(vector);
        let _ = vector::free(vector);
        if !awake {
            return TestResult::Fail("queue IRQ in drain/await gap was lost");
        }
        // SAFETY: backing memory simulates the CSR bank, no host hardware access.
        unsafe {
            if csr.read32(reg_pfint_dyn_ctln(0)) != MASK {
                return TestResult::Fail("queue handler did not mask vector");
            }
            csr.write32(REG_PFINT_ICR0, ADMINQ);
        }
        admin_handler(cookie);
        if shared.lock().failed {
            return TestResult::Fail("admin completion marked PF failed");
        }
        // SAFETY: same test-owned CSR memory.
        unsafe {
            csr.write32(REG_PFINT_ICR0, 1 << 26);
        }
        admin_handler(cookie);
        let state = shared.lock();
        if !state.failed {
            return TestResult::Fail("HMC fatal error did not stop PF");
        }
        // SAFETY: same test-owned CSR memory.
        if unsafe {
            csr.read32(REG_PFINT_ICR0_ENA) != 0
                || csr.read32(REG_PFINT_DYN_CTL0) != MASK
                || csr.read32(reg_pfint_dyn_ctln(0)) != MASK
        } {
            return TestResult::Fail("fatal PF continued interrupt delivery or changed ITR bank");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_irq_mask_wakeup_and_fatal);
}
