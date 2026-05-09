//! userspace init -- the first user process.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    unsafe {
        libc::puts(b"NARF Userspace Init started!\n\0".as_ptr());
        libc::puts(b"Mounting /dev (if not already mounted)...\n\0".as_ptr());

        loop {
            libc::puts(b"init: idle...\n\0".as_ptr());
            libc::sleep(5);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
