//! Errors shared by built-in and C-ABI device protocols.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IgcError {
    BarMapFailed,
    ResetTimeout,
    QueueTooSmall,
    RegisterTimeout {
        register: u64,
        mask: u32,
        expected: u32,
        observed: u32,
    },
    Other(&'static str),
}
