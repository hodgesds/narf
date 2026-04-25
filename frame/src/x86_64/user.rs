//! User-mode entry — the `iretq` transfer into CPL=3.
//!
//! After the scheduler has `activate()`-d the target task's
//! `AddressSpace` (MOV CR3 done) and populated `TSS.rsp0` with the
//! task's kernel stack, the kernel reaches user mode by pushing a
//! synthetic iretq frame and executing `iretq`. The CPU pops
//! `ss:rsp` + `rflags` + `cs:rip` from the stack and atomically
//! transitions to CPL=3.
//!
//! An `iretq` from kernel to user requires:
//! - `cs` = user-code selector (DPL=3): `UCODE_SEL` (0x33)
//! - `ss` = user-data selector (DPL=3): `UDATA_SEL` (0x2B)
//! - `rflags` with IF=1 so interrupts are enabled in user mode
//!   (bit 9 = 0x200), plus the reserved bit 1 (0x002) that's
//!   always 1.
//! - `cs.dpl >= cpl (= 0)` — DPL=3 is always >= 0, so this is
//!   structurally fine.
//!
//! `enter_user_mode` does not return. The only way back into the
//! kernel is a trap — `int 0x80` for syscalls (vector 128, now DPL=3
//! so user mode can trigger it), CPU exceptions (page fault etc.),
//! or an external IRQ.
//!
//! All of the actual primitives — `UserState`, `JmpBuf`, `setjmp`,
//! `longjmp`, `enter_user_mode`, `enter_user_mode_resume`,
//! `USER_RFLAGS` — live in `narf-arch::x86_64::user_mode` so any
//! crate downstream of `narf-arch` (notably `narf-userspace`, where
//! the Stage-4 polling future lives) can name them without taking
//! a fresh dep on `narf-frame` (which is the kernel binary, not a
//! library). This module is a re-export shim kept for any
//! pre-existing intra-crate callers that name `super::user::*`.

#![allow(unused)]

pub use narf_arch::x86_64::{
    enter_user_mode, enter_user_mode_resume, longjmp, setjmp, JmpBuf,
    UserState, USER_RFLAGS,
};
