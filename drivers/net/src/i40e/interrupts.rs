//! Owned MSI-X routing: entry 0 for admin/fatal causes, entry 1 for queue 0.
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
}

impl Shared {
    fn mask(&self) {
        // SAFETY: mapping covers the CSR registers and owner serializes writes.
        unsafe {
            self.csr.write32(REG_PFINT_ICR0_ENA, 0);
            self.csr.write32(REG_PFINT_DYN_CTL0, MASK);
            self.csr.write32(reg_pfint_dyn_ctln(0), MASK);
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

fn queue_handler(cookie: u64) -> dispatch::IrqStatus {
    // SAFETY: same lifetime as admin_handler.
    let shared = unsafe { &*(cookie as *const IrqSafeSpinLock<Shared>) };
    let state = shared.lock();
    // SAFETY: CSR window is owned until synchronization.
    unsafe {
        state.csr.write32(reg_pfint_dyn_ctln(0), MASK);
    }
    dispatch::IrqStatus::Handled
}

pub(super) struct Interrupts {
    table: MsixTable,
    vectors: [u8; 2],
    shared: Box<IrqSafeSpinLock<Shared>>,
}

impl Interrupts {
    pub fn new(
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
        csr: MmioRegion,
    ) -> Result<Self, I40eError> {
        let bad = I40eError::InterruptSetup;
        let mut table = narf_bus::enable_msix(cap, device).map_err(|_| bad)?;
        table.alloc_block(2).map_err(|_| bad)?;
        // SAFETY: caller owns the PF, no handler has been registered yet.
        unsafe {
            table.disable();
        }
        let admin = vector::alloc().map_err(|_| bad)?;
        let queue = match vector::alloc() {
            Ok(v) => v,
            Err(_) => {
                let _ = vector::free(admin);
                return Err(bad);
            }
        };
        let shared = Box::new(IrqSafeSpinLock::new(Shared { csr, failed: false }));
        shared.lock().mask();
        let cookie = (&*shared as *const IrqSafeSpinLock<Shared>) as u64;
        dispatch::install_handler_named(admin, "i40e-admin", cookie, admin_handler);
        dispatch::install_handler_named(queue, "i40e-queue", cookie, queue_handler);
        dispatch::enable_irq(admin);
        dispatch::enable_irq(queue);
        let mut this = Self {
            table,
            vectors: [admin, queue],
            shared,
        };
        // SAFETY: entries 0 and 1 are reserved and MSI-X is disabled. On ARM
        // the bus layer installs the requester-ID/EventID -> LPI mapping.
        unsafe {
            this.table.program_vector(0, 0, admin).map_err(|_| bad)?;
            this.table.program_vector(1, 0, queue).map_err(|_| bad)?;
        }
        Ok(this)
    }

    pub fn enable(&mut self) -> Result<(), I40eError> {
        {
            let state = self.shared.lock();
            // SAFETY: all offsets are in BAR0, queue is PF-relative queue 0.
            unsafe {
                state.csr.read32(REG_PFINT_ICR0);
                state.csr.write32(REG_PFINT_LNKLST0, QUEUE_END_OF_LIST);
                state.csr.write32(0x0003_8400, 0); // PFINT_STAT_CTL0
                state.csr.write32(0x0003_5800, 0); // PFINT_RATEN(0)
                for write in build_vector_chain(1, 0, 1)
                    .map_err(|_| I40eError::InterruptSetup)?
                    .into_iter()
                    .chain(
                        build_vector_itr(1, ITR_20K, ITR_8K)
                            .map_err(|_| I40eError::InterruptSetup)?,
                    )
                {
                    state.csr.write32(write.reg, write.value);
                }
                state.csr.write32(REG_PFINT_ICR0_ENA, ADMINQ | FATAL);
            }
        }
        // SAFETY: table entries, callbacks and queue chains are initialized.
        unsafe {
            self.table.enable().map_err(|_| I40eError::InterruptSetup)?;
        }
        self.rearm_admin();
        self.rearm_queue();
        Ok(())
    }

    pub fn admin_vector(&self) -> u8 {
        self.vectors[0]
    }
    pub fn queue_vector(&self) -> u8 {
        self.vectors[1]
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
            // SAFETY: only the two dynamic-control offsets are passed here.
            // CLEARPBA followed by enable is the Linux NAPI rearm sequence.
            unsafe {
                state.csr.write32(register, ARM);
                state.csr.read32(REG_PFINT_ICR0_ENA);
            }
        }
    }
    pub fn rearm_admin(&self) {
        self.rearm(REG_PFINT_DYN_CTL0);
    }
    pub fn rearm_queue(&self) {
        self.rearm(reg_pfint_dyn_ctln(0));
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        self.shared.lock().mask();
        // SAFETY: table is owned, cookie still alive, no new device IRQs after disable.
        unsafe {
            self.table.disable();
        }
        let cookie = (&*self.shared as *const IrqSafeSpinLock<Shared>) as u64;
        for (index, name) in ["i40e-admin", "i40e-queue"].iter().enumerate() {
            let vector = self.vectors[index];
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
        let shared = Box::new(IrqSafeSpinLock::new(Shared { csr, failed: false }));
        let cookie = (&*shared as *const IrqSafeSpinLock<Shared>) as u64;
        let vector = vector::alloc().unwrap();
        dispatch::enable_irq(vector);
        dispatch::install_handler_named(vector, "i40e-queue-test", cookie, queue_handler);
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
        dispatch::remove_handler(vector, "i40e-queue-test", cookie);
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
