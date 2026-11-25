//! Fixture seam for a published native MPDU and independently supplied
//! TXS records. It does not manufacture a bool ACK in the Session callback.
use super::*;
#[derive(Debug)]
pub(super) struct Observer {
    pub published: crate::platform::IrqSafeSpinLock<Vec<([u8; 64], Vec<u8>)>>,
    pub reports: crate::platform::IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    pub received: crate::platform::IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    pub terminal: AtomicBool,
}
impl Default for Observer {
    fn default() -> Self {
        Self {
            published: crate::platform::IrqSafeSpinLock::new(Vec::new()),
            reports: crate::platform::IrqSafeSpinLock::new(VecDeque::new()),
            received: crate::platform::IrqSafeSpinLock::new(VecDeque::new()),
            terminal: AtomicBool::new(false),
        }
    }
}
