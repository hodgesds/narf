//! userspace init -- the first user process.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // argv is kernel-provided; entry signature is fixed
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // SAFETY: Valid memory or trusted environment
    unsafe {
        libc::puts(b"NARF Userspace Init started!\n\0".as_ptr());
        libc::puts(b"Mounting /dev (if not already mounted)...\n\0".as_ptr());

        // No real work yet — block effectively forever rather
        // than busy-waking on a fixed cadence. saturating_mul
        // in libc::sleep caps at u64::MAX ns (~580 years), so
        // u32::MAX seconds parks for the kernel's entire
        // foreseeable uptime. Replace with a real `pause()` /
        // signal-wait primitive when signals + reaping land.
        loop {
            libc::sleep(u32::MAX);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
