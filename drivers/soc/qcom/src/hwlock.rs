//! Qualcomm TCSR mutex hardware spinlock.
//!
//! Linux `drivers/hwspinlock/qcom_hwspinlock.c`, `qcom,tcsr-mutex` layout
//! (offset 0, stride 0x1000): lock `n` is the register at `n * stride`.
//! Taking it writes the owner id (`QCOM_MUTEX_APPS_PROC_ID` = 1) and
//! reads it back; the lock is ours iff the read returns our id. SMEM
//! allocation holds lock 3 (`hwlocks = <&tcsr_mutex 3>`).

use crate::io::{Delay, RegIo};

/// `QCOM_MUTEX_APPS_PROC_ID`.
pub const APPS_PROC_ID: u32 = 1;
/// `QCOM_MUTEX_NUM_LOCKS`.
pub const NUM_LOCKS: u32 = 32;
/// `qcom,tcsr-mutex` register stride.
pub const TCSR_MUTEX_STRIDE: u32 = 0x1000;
/// `HWSPINLOCK_TIMEOUT` used by SMEM (ms).
pub const SMEM_LOCK_TIMEOUT_MS: u32 = 1000;

/// Hardware spinlock failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwLockError {
    /// Lock id beyond `NUM_LOCKS`.
    BadId,
    /// Another processor kept the lock past the timeout.
    Timeout,
    /// Unlock of a lock not held by the application processor.
    NotOwner(u32),
}

/// The lock used by SMEM allocation.
pub trait HwSpinlock {
    /// Take the lock, sleeping between attempts, within `timeout_ms`.
    fn lock(
        &self,
        timeout_ms: u32,
    ) -> impl core::future::Future<Output = Result<(), HwLockError>> + Send;
    fn unlock(&self) -> Result<(), HwLockError>;
}

/// One TCSR mutex lock.
#[derive(Debug)]
pub struct TcsrMutex<R: RegIo, D: Delay> {
    regs: R,
    delay: D,
    id: u32,
    stride: u32,
}

impl<R: RegIo, D: Delay> TcsrMutex<R, D> {
    pub fn new(regs: R, delay: D, id: u32) -> Result<Self, HwLockError> {
        if id >= NUM_LOCKS {
            return Err(HwLockError::BadId);
        }
        Ok(Self {
            regs,
            delay,
            id,
            stride: TCSR_MUTEX_STRIDE,
        })
    }

    fn reg(&self) -> u32 {
        self.id * self.stride
    }

    /// `qcom_hwspinlock_trylock`.
    pub fn try_lock(&self) -> bool {
        self.regs.write32(self.reg(), APPS_PROC_ID);
        self.regs.read32(self.reg()) == APPS_PROC_ID
    }
}

impl<R: RegIo + Sync, D: Delay + Sync> HwSpinlock for TcsrMutex<R, D> {
    async fn lock(&self, timeout_ms: u32) -> Result<(), HwLockError> {
        let deadline = self.delay.now_us() + timeout_ms as u64 * 1000;
        loop {
            if self.try_lock() {
                return Ok(());
            }
            if self.delay.now_us() >= deadline {
                return Err(HwLockError::Timeout);
            }
            self.delay.sleep_us(10).await;
        }
    }

    /// `qcom_hwspinlock_unlock`.
    fn unlock(&self) -> Result<(), HwLockError> {
        let owner = self.regs.read32(self.reg());
        if owner != APPS_PROC_ID {
            return Err(HwLockError::NotOwner(owner));
        }
        self.regs.write32(self.reg(), 0);
        Ok(())
    }
}
