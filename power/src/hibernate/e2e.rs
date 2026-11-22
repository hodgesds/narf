//! `narf.hibernate_e2e=`: the guest half of `cargo xtask hibernate-e2e`
//! (S4 lane 9).
//!
//! - `hibernate` (first boot): once the image file's directory sits on a
//!   writable ext filesystem (the host's disk, mounted at `/mnt`), fill
//!   16 MiB with a pattern seeded by a random token, then hibernate to the
//!   image file there. In the restored image, recompute the pattern's
//!   digest and report both through QEMU's debug-exit port.
//! - `resume` (second boot): reached only when `software_resume` did not
//!   restore, so it reports that and exits.
//!
//! Every line the host parses starts with [`MARKER`]. Inert without the
//! parameter.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{Cap, Invoke};
use narf_crypto::sha256::Sha256;

pub const MARKER: &str = "HIBERNATE-E2E:";
/// Debug-exit codes: QEMU exits with `code << 1 | 1`.
pub const EXIT_RESUMED: u32 = 0x10;
pub const EXIT_FAILED: u32 = 0x11;
pub const EXIT_NO_RESUME: u32 = 0x12;
const PATTERN_BYTES: usize = 16 << 20;

static TOKEN: AtomicU64 = AtomicU64::new(0);

fn say(text: &str) {
    let _ = narf_console::write_str(&alloc::format!("{MARKER} {text}\n"));
}

fn exit(code: u32) -> ! {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: port 0xF4 is QEMU's debug-exit device; elsewhere it halts.
    unsafe {
        narf_arch::x86_64::exit_qemu(code)
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: semihosting SYS_EXIT_EXTENDED; elsewhere it halts.
    unsafe {
        narf_arch::aarch64::exit_qemu(code)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = code;
        narf_arch::halt_forever()
    }
}

/// A token-seeded pattern and its digest.
fn pattern(token: u64) -> (Vec<u8>, [u8; 32]) {
    let mut buf = Vec::with_capacity(PATTERN_BYTES);
    let mut x = token | 1;
    while buf.len() < PATTERN_BYTES {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buf.extend_from_slice(&x.to_le_bytes());
    }
    let digest = digest(&buf);
    (buf, digest)
}

fn digest(buf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(buf);
    h.finalize()
}

fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
}

async fn run_hibernate() {
    // The image file's filesystem mounts after this initcall. Until then its
    // directory resolves to the RAM root, so wait for an ext filesystem.
    let path = super::image_path();
    let dir = match path.rfind('/') {
        Some(0) | None => alloc::string::String::from("/"),
        Some(at) => alloc::string::String::from(&path[..at]),
    };
    let mut waited = 0;
    loop {
        let ready = narf_filesystem::registry()
            .fs_arc_at(&dir)
            .is_some_and(|fs| fs.name().starts_with("ext") && !fs.always_read_only());
        if ready {
            break;
        }
        if waited >= 30_000 {
            say(&alloc::format!("FAIL no writable ext filesystem at {dir}"));
            exit(EXIT_FAILED);
        }
        narf_time::sleep_ms(50).await;
        waited += 50;
    }
    let (token, _) = narf_memory::kaslr::random_u64();
    TOKEN.store(token, Ordering::Release);
    let (buf, before) = pattern(token);
    say(&alloc::format!(
        "hibernating token={token:016x} digest={}",
        hex(&before)
    ));
    let cap: Cap<crate::Power, Invoke> = Cap::bootstrap();
    match super::hibernate(&cap).await {
        Ok(()) => {
            let after = digest(&buf);
            say(&alloc::format!(
                "resumed token={:016x} digest={}",
                TOKEN.load(Ordering::Acquire),
                hex(&after)
            ));
            exit(EXIT_RESUMED);
        }
        Err(e) => {
            say(&alloc::format!("FAIL {e:?}"));
            exit(EXIT_FAILED);
        }
    }
}

/// The Stage::Late initcall: spawn the phase `narf.hibernate_e2e=` names.
pub fn initcall() -> narf_init::InitResult {
    match narf_boot::args().value("narf.hibernate_e2e") {
        Some("hibernate") => {
            // On the boot CPU, as `hibernate` requires.
            let mut spec = narf_scheduler::TaskSpec::unthrottled();
            spec.affinity = narf_scheduler::Affinity::pinned(narf_scheduler::CpuId(0));
            narf_scheduler::spawn_with_spec(run_hibernate(), spec);
            narf_init::InitResult::Ok
        }
        Some("resume") => {
            say("NO-RESUME");
            exit(EXIT_NO_RESUME);
        }
        _ => narf_init::InitResult::NotPresent,
    }
}
