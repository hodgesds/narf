//! aarch64-specific bring-up. `boot.S` holds the EL1 entry and stack
//! setup; it then calls `_start_rust(magic, payload)` with magic set to
//! the DTB magic (0xd00dfeed) and payload set to X0 (the DTB phys addr).

core::arch::global_asm!(include_str!("boot.S"));
