//! Errors shared by built-in and C-ABI device protocols.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IgcError {
    BarMapFailed,
    ResetTimeout,
    QueueTooSmall,
    /// The transmit queue is stopped or has no room for a frame that fits an
    /// empty ring (`NETDEV_TX_BUSY`). Nothing was posted or counted as
    /// rejected; the queue's wake says when to offer the frame again.
    TxBusy,
    RegisterTimeout {
        register: u64,
        mask: u32,
        expected: u32,
        observed: u32,
    },
    Other(&'static str),
}
