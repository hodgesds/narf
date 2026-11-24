//! Module-runtime smoke.
//!
//! `narf_module_init` proves, in order, that a module can:
//!
//! 1. allocate through its `#[global_allocator]` (a `Vec` sum),
//! 2. format with `alloc::format!` and write a whole console line,
//! 3. read its load parameters (`greeting`, `expect`; init fails unless
//!    they are equal),
//! 4. run futures on its own executor — a task that sleeps while holding an
//!    async mutex, and a second task that must wait for it.
//!
//! No device is bound, so there is no kernel poller to drive the executor;
//! init drives it inline until it is idle (bounded by a deadline). Each step
//! prints a token that `cargo xtask module-rt-smoke` requires.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_module_rt::exec::{Executor, Run};
use narf_module_rt::param;
use narf_module_rt::printkln;
use narf_module_rt::sync::Mutex;
use narf_module_rt::time::{self, Deadline};

#[used]
#[link_section = ".modinfo"]
static MODINFO_NAME: [u8; 21] = *b"name=module_rt_smoke\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_VERSION: [u8; 14] = *b"version=0.1.0\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_LICENSE: [u8; 25] = *b"license=GPL-2.0-or-later\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_AUTHOR: [u8; 12] = *b"author=narf\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_DESCRIPTION: [u8; 43] = *b"description=NARF module runtime smoke test\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_TARGET_DOMAIN: [u8; 22] = *b"target_domain=scratch\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_KERNEL_ABI: [u8; 22] = *b"kernel_abi=0x00000000\0";

// Declared parameters with defaults. `#[used]` keeps the section through the
// module link's section GC (it is emitted SHF_GNU_RETAIN). Init requires
// `greeting == expect`, so a load that overrides only one of them fails —
// which is how the e2e test proves the override reached the module.
#[used]
#[link_section = ".narf_kparams"]
static KPARAMS: [u8; 32] = *b"greeting=default\nexpect=default\n";

static EXEC: Executor = Executor::new();
static ORDER: Mutex<Vec<u32>> = Mutex::new(Vec::new());
static STEPS: AtomicU32 = AtomicU32::new(0);

/// Module entry point.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_init() -> i32 {
    // 1 + 2: heap and formatting.
    let values: Vec<u64> = (1..=1000).collect();
    let sum: u64 = values.iter().sum();
    let line = format!(
        "narf-module-rt-smoke: alloc ok sum={sum} len={}",
        values.len()
    );
    printkln!("{line}");
    if sum != 500_500 {
        return -22;
    }

    // Load parameters: both declared, and equal unless the loader set only
    // one of them.
    match (param::get("greeting"), param::get("expect")) {
        (Ok(greeting), Ok(expect)) if greeting == expect => {
            printkln!("narf-module-rt-smoke: params ok greeting={greeting}");
        }
        (greeting, expect) => {
            printkln!("narf-module-rt-smoke: params mismatch {greeting:?} vs {expect:?}");
            return -22;
        }
    }

    // 3: executor, sleep and async mutex.
    let started = time::now_ns();
    let spawned = EXEC
        .spawn(async {
            let mut order = ORDER.lock().await;
            order.push(1);
            time::sleep_ms(3).await;
            order.push(2);
            STEPS.fetch_add(1, Ordering::AcqRel);
        })
        .and_then(|()| {
            EXEC.spawn(async {
                ORDER.lock().await.push(3);
                STEPS.fetch_add(1, Ordering::AcqRel);
            })
        });
    if spawned.is_err() {
        return -12;
    }
    let deadline = Deadline::after_ms(2_000);
    while EXEC.run() != Run::Idle {
        if deadline.expired() {
            printkln!("narf-module-rt-smoke: executor timed out");
            return -110;
        }
        core::hint::spin_loop();
    }
    let elapsed_us = (time::now_ns() - started) / 1_000;
    let in_order = ORDER.try_lock().is_some_and(|o| o.as_slice() == [1, 2, 3]);
    if STEPS.load(Ordering::Acquire) != 2 || !in_order || elapsed_us < 3_000 {
        printkln!("narf-module-rt-smoke: executor wrong (elapsed {elapsed_us} us)");
        return -5;
    }
    printkln!("narf-module-rt-smoke: executor ok after {elapsed_us} us");
    0
}

/// Module teardown.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    EXEC.stop();
    let _ = EXEC.run();
    printkln!("narf-module-rt-smoke: exit");
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
