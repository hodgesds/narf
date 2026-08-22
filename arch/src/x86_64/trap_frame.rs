//! x86_64 trap-entry ABI shared by `frame` and the executor core.
//!
//! The assembly in `frame/src/x86_64/trap_entry.S` materialises this exact
//! layout.  Keeping the Rust representation in the architecture crate gives
//! trap dispatch and preemption one source of truth without making the
//! scheduler depend on `frame` (or duplicating a security-critical ABI).

/// Register image built by the common x86_64 trap prologue.
///
/// Order follows the prologue's reverse pushes followed by the vector/error
/// pair and the CPU-pushed return frame.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TrapFrame {
    /// Live protection state captured by the assembly prologue. `domain_kind`
    /// identifies `domain_state` as PKRS (1), CR3/PCID (2), or inactive (0).
    pub domain_state: u64,
    pub domain_kind: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = {
    assert!(core::mem::size_of::<TrapFrame>() == 24 * 8);
    assert!(core::mem::offset_of!(TrapFrame, r15) == 16);
    assert!(core::mem::offset_of!(TrapFrame, vector) == 17 * 8);
    assert!(core::mem::offset_of!(TrapFrame, rip) == 19 * 8);
};

impl core::fmt::Debug for TrapFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TrapFrame {{ vec={}, err={:#x}, rip={:#018x}, cs={:#x}, rflags={:#x} }}",
            self.vector, self.error_code, self.rip, self.cs, self.rflags
        )
    }
}
