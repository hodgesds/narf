//! aarch64 exception-vector ABI shared by `frame` and the executor core.
//!
//! `frame/src/aarch64/vec.S` materialises this exact layout.  Architecture
//! ownership prevents the frame and scheduler crates from maintaining
//! independent copies of a security-critical continuation format.

/// Register image built by `SAVE_ALL_GPRS` in the aarch64 vector table.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TrapFrame {
    /// Live MTE control state captured before vector Rust runs.
    pub domain_sctlr: u64,
    pub domain_gcr: u64,
    pub x30: u64,
    /// Forced by the 16-byte stack allocation used to save `x30`.
    pub _pad: u64,
    pub elr: u64,
    pub spsr: u64,
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
}

const _: () = {
    assert!(core::mem::size_of::<TrapFrame>() == 36 * 8);
    assert!(core::mem::offset_of!(TrapFrame, x30) == 16);
    assert!(core::mem::offset_of!(TrapFrame, elr) == 32);
    assert!(core::mem::offset_of!(TrapFrame, x0) == 48);
    assert!(core::mem::offset_of!(TrapFrame, x29) == 35 * 8);
};
