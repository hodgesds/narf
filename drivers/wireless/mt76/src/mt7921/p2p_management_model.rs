//! Fixture seam for a published native MPDU and independently supplied
//! TXS records. It does not manufacture a bool ACK in the Session callback.
use super::*;
#[derive(Debug)]
pub(super) struct Observer {
    pub published: narf_lib::sync::IrqSafeSpinLock<Vec<([u8; 64], Vec<u8>)>>,
    pub reports: narf_lib::sync::IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    pub received: narf_lib::sync::IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    pub terminal: AtomicBool,
}
impl Default for Observer {
    fn default() -> Self {
        Self {
            published: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
            reports: narf_lib::sync::IrqSafeSpinLock::new(VecDeque::new()),
            received: narf_lib::sync::IrqSafeSpinLock::new(VecDeque::new()),
            terminal: AtomicBool::new(false),
        }
    }
}
