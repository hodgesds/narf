//! x86_64-specific bring-up. `boot.S` holds the multiboot2 header, the
//! 32-bit `_start` stub, and the long-mode transition. After the transition
//! it calls `_start_rust` with the multiboot2 magic and info-pointer in
//! RDI and RSI (System V AMD64 ABI for two u64 args).

core::arch::global_asm!(include_str!("boot.S"));
