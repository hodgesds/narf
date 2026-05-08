//! userspace shell — interactive command interpreter.

#![no_std]
#![no_main]

use narf_libc as libc;
use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    unsafe {
        libc::puts(b"NARF Shell started!\n\0".as_ptr());
        
        loop {
            libc::puts(b"narf> \0".as_ptr());
            // In a real system, we'd read input here.
            // For now, just idle.
            libc::sleep(10);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
