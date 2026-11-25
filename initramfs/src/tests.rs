//! Per-crate smoke tests for `narf-initramfs`.

use narf_kernel_test::{kernel_test_in, TestResult};

// Hand-built CPIO newc archive — single file "hello" / "world".
// Identical to the fixture in `narf-filesystem`'s tests; kept
// inline so the smoke has zero dependency on a host cpio tool.
static SMOKE_INITRAMFS: &[u8] = b"\
070701\
00000001\
000081A4\
00000000\
00000000\
00000001\
00000064\
00000005\
00000000\
00000000\
00000000\
00000000\
00000006\
00000000\
hello\0\
world\0\0\0\
070701\
00000000\
00000000\
00000000\
00000000\
00000001\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
0000000B\
00000000\
TRAILER!!!\0\0\0\0";

fn smoke_initramfs_staging_round_trip() -> TestResult {
    use crate::{__reset_staged, install, is_staged, staged, Initramfs};
    __reset_staged();
    if is_staged() {
        return TestResult::Fail("reset didn't clear staged FS");
    }
    let fs = match Initramfs::from_cpio("smoke-stage", SMOKE_INITRAMFS) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse rejected smoke archive"),
    };
    let leaked: &'static Initramfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
    install(leaked);
    if !is_staged() {
        return TestResult::Fail("install didn't take effect");
    }
    if staged().is_none() {
        return TestResult::Fail("staged() returned None after install");
    }
    // First-install-wins idempotency: re-installing a different
    // FS doesn't replace the staged one.
    let fs2 = match Initramfs::from_cpio("alt", SMOKE_INITRAMFS) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse #2"),
    };
    let leaked2: &'static Initramfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs2));
    install(leaked2);
    // Both `Initramfs` values were parsed from the same archive,
    // so we can't distinguish them by entry data — just confirm
    // a single install left a valid staged entry.
    if !is_staged() {
        return TestResult::Fail("re-install cleared the staged FS");
    }
    TestResult::Pass
}
kernel_test_in!("initramfs", smoke_initramfs_staging_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_initramfs_pvh_module_parser() -> TestResult {
    // Synthesize a PVH `hvm_start_info` + one `hvm_modlist_entry`
    // whose cmdline is "initramfs", then verify the parser returns
    // the module's phys range. The phys-address fields we put in
    // are USERSPACE virt addresses pointing at heap-leaked boxes;
    // reading them via `read_volatile` works under the kernel
    // identity map (or here, since we never dereference them —
    // the parser only walks the modlist + cmdline string).
    use narf_boot::x86_64::pvh::initramfs_module;

    // Layout the modlist-cmdline as one byte slice; the parser
    // reads cmdline_paddr as a pointer to NUL-terminated bytes.
    let cmdline: &'static [u8] =
        alloc::boxed::Box::leak(b"initramfs\0".to_vec().into_boxed_slice());

    // PVH hvm_modlist_entry: paddr / size / cmdline_paddr / reserved.
    let modlist_bytes = {
        let mut v = alloc::vec::Vec::with_capacity(32);
        v.extend_from_slice(&0xCAFE_F00D_u64.to_le_bytes()); // paddr
        v.extend_from_slice(&0x1234_u64.to_le_bytes()); // size
        v.extend_from_slice(&(cmdline.as_ptr() as u64).to_le_bytes()); // cmdline_paddr
        v.extend_from_slice(&0u64.to_le_bytes()); // reserved
        v.into_boxed_slice()
    };
    let modlist: &'static [u8] = alloc::boxed::Box::leak(modlist_bytes);

    // Synthesize hvm_start_info — magic + version + flags +
    // nr_modules + modlist + cmdline + rsdp + memmap_paddr +
    // memmap_entries + reserved.
    let mut hdr_bytes = alloc::vec::Vec::with_capacity(56);
    hdr_bytes.extend_from_slice(&0x336e_c578u32.to_le_bytes()); // magic
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // version
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    hdr_bytes.extend_from_slice(&1u32.to_le_bytes()); // nr_modules
    hdr_bytes.extend_from_slice(&(modlist.as_ptr() as u64).to_le_bytes()); // modlist
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // cmdline
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // rsdp
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // memmap_paddr
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // memmap_entries
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    let hdr: &'static [u8] = alloc::boxed::Box::leak(hdr_bytes.into_boxed_slice());

    // SAFETY: hdr points at a fully-initialized PVH struct;
    // modlist + cmdline addresses inside it are leaked-into-static
    // pointers within the same address space.
    // SAFETY: Valid memory or trusted environment
    let result = unsafe { initramfs_module(hdr.as_ptr() as usize) };
    match result {
        Some((start, size)) => {
            if start != 0xCAFE_F00D || size != 0x1234 {
                TestResult::Fail("parser returned wrong (start, size)")
            } else {
                TestResult::Pass
            }
        }
        None => TestResult::Fail("parser missed the synthetic initramfs module"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("initramfs", smoke_initramfs_pvh_module_parser);

#[cfg(target_arch = "x86_64")]
fn smoke_initramfs_pvh_module_parser_no_match() -> TestResult {
    // Same shape as the prior smoke but with ZERO modules
    // (`nr_modules = 0`) — the parser must return `None` when there is
    // nothing to hand back. (The parser returns the FIRST module present
    // regardless of its cmdline — the bootloader only ever passes the
    // initramfs — so the meaningful no-match case is "no module at all",
    // not "a module with a non-`initramfs` cmdline".)
    use narf_boot::x86_64::pvh::initramfs_module;
    let mut hdr_bytes = alloc::vec::Vec::with_capacity(56);
    hdr_bytes.extend_from_slice(&0x336e_c578u32.to_le_bytes()); // magic
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // version
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // nr_modules = 0
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // modlist (none)
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // cmdline
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // rsdp
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // memmap_paddr
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // memmap_entries
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    let hdr: &'static [u8] = alloc::boxed::Box::leak(hdr_bytes.into_boxed_slice());
    // SAFETY: hdr points at a fully-initialized PVH start_info with no
    // modules; the parser walks an empty modlist and returns None.
    let result = unsafe { initramfs_module(hdr.as_ptr() as usize) };
    if result.is_some() {
        TestResult::Fail("parser returned a module when nr_modules == 0")
    } else {
        TestResult::Pass
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("initramfs", smoke_initramfs_pvh_module_parser_no_match);

/// `mount_at_path("/")` round-trip: stage the smoke CPIO, mount it
/// at "/", verify the staged FS shows up in `narf_filesystem`'s
/// registry. Locks down the boot-path's "fall back to initramfs as
/// root when no FAT volume mounted" contract so a future refactor
/// of the mount surface can't quietly break the no-disk laptop
/// boot scenario.
fn smoke_initramfs_mount_at_root() -> TestResult {
    use crate::{__reset_staged, install, mount_at_path, Initramfs};
    __reset_staged();
    let fs = match Initramfs::from_cpio("smoke-mount-root", SMOKE_INITRAMFS) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse rejected smoke archive"),
    };
    let leaked: &'static Initramfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
    install(leaked);
    let auth = narf_filesystem::bootstrap_mount_authority();
    // Mount at a non-"/" path because the kernel-test harness has
    // a real root mount we mustn't disturb. The mount logic is
    // identical (mount_at_path is path-generic); a successful
    // mount here proves the API contract independent of the
    // specific path.
    if mount_at_path(&auth, "/initramfs-smoke").is_err() {
        return TestResult::Fail("mount_at_path rejected /initramfs-smoke");
    }
    // Resolve through the registry to confirm the proxy actually
    // serves the staged entries.
    let pair: Option<(
        alloc::sync::Arc<dyn narf_filesystem::DirOps>,
        alloc::string::String,
    )> = narf_filesystem::registry().resolve_absolute("/initramfs-smoke/hello", |fs, rel| {
        (fs.root(), alloc::string::String::from(rel))
    });
    if pair.is_none() {
        return TestResult::Fail(
            "registry didn't return the mounted FS for /initramfs-smoke/hello",
        );
    }
    TestResult::Pass
}
kernel_test_in!("initramfs", smoke_initramfs_mount_at_root);

// ── Boot passphrase prompts (`rd.luks.prompt=`) ──────────────────────

mod prompt {
    use super::{kernel_test_in, TestResult};
    use crate::credentials::{key_byte, read_passphrase, LineEditor, Source, Step};
    use alloc::vec::Vec;
    use narf_block::encrypted::{LuksCredentialError, LuksVersion, LuksVolumeInfo};
    use narf_input::{KeyCode as K, KeyEvent, Modifiers as M};
    use narf_lib::sync::IrqSafeSpinLock;

    const UUID: &str = "4152464e-4c55-4b53-9000-000000000001";

    fn volume() -> LuksVolumeInfo {
        LuksVolumeInfo {
            version: LuksVersion::Luks1,
            uuid: alloc::string::String::from(UUID),
        }
    }

    fn feed(editor: &mut LineEditor, bytes: &[u8]) -> Step {
        let mut last = Step::More;
        for &b in bytes {
            last = editor.feed(b);
            if last != Step::More {
                break;
            }
        }
        last
    }

    fn smoke_luks_prompt_line_editor() -> TestResult {
        let mut e = LineEditor::new();
        // Enter on an empty line does nothing; Backspace deletes a byte;
        // Ctrl-U clears the line; non-printable bytes are ignored.
        if feed(&mut e, b"\rxy\x7fz\x15ab\x01c\n") != Step::Done {
            return TestResult::Fail("Enter must submit a non-empty line");
        }
        if e.into_secret().as_slice() != b"abc" {
            return TestResult::Fail("line editing differs from the serial prompt's rules");
        }
        for cancel in [3u8, 27] {
            let mut e = LineEditor::new();
            if feed(&mut e, &[b'a', cancel]) != Step::Cancelled {
                return TestResult::Fail("Ctrl-C and Escape must cancel the prompt");
            }
        }
        let mut e = LineEditor::new();
        let long = [b'x'; 513];
        if feed(&mut e, &long[..512]) != Step::More || feed(&mut e, &long[512..]) != Step::TooLarge
        {
            return TestResult::Fail("a passphrase over 512 bytes must be TooLarge");
        }
        TestResult::Pass
    }
    kernel_test_in!("initramfs/luks-prompt", smoke_luks_prompt_line_editor);

    fn key(code: K, pressed: bool, mods: M) -> KeyEvent {
        KeyEvent {
            code,
            pressed,
            modifiers: mods,
        }
    }

    fn smoke_luks_prompt_key_bytes() -> TestResult {
        let none = M::from_bits_truncate(0);
        let cases = [
            (key(K::A, true, none), Some(b'a')),
            (key(K::A, true, M::SHIFT), Some(b'A')),
            (key(K::A, false, none), None),
            (key(K::LeftShift, true, M::SHIFT), None),
            (key(K::Enter, true, none), Some(b'\n')),
            (key(K::Backspace, true, none), Some(0x7f)),
            (key(K::Escape, true, none), Some(0x1b)),
            (key(K::C, true, M::CTRL), Some(3)),
            (key(K::U, true, M::CTRL), Some(0x15)),
            // Other chords never insert their letter.
            (key(K::A, true, M::CTRL), None),
            (key(K::X, true, M::ALT), None),
            (key(K::X, true, M::META), None),
        ];
        if cases.iter().any(|&(k, want)| key_byte(k) != want) {
            return TestResult::Fail("key_byte differs from the prompt's key rules");
        }
        TestResult::Pass
    }
    kernel_test_in!("initramfs/luks-prompt", smoke_luks_prompt_key_bytes);

    // A scripted keyboard: each poll delivers the next key through the
    // same `push_key` every keyboard driver ends in.
    static SCRIPT: IrqSafeSpinLock<(Vec<(K, bool)>, usize)> = IrqSafeSpinLock::new((Vec::new(), 0));

    fn script_poll() {
        let next = {
            let mut g = SCRIPT.lock();
            let at = g.1;
            let next = g.0.get(at).copied();
            if next.is_some() {
                g.1 += 1;
            }
            next
        };
        if let Some((code, pressed)) = next {
            let _ = narf_input::push_key(code, pressed);
        }
    }

    static OUTPUT: IrqSafeSpinLock<Vec<u8>> = IrqSafeSpinLock::new(Vec::new());

    fn capture(bytes: &[u8]) {
        OUTPUT.lock().extend_from_slice(bytes);
    }

    fn type_keys(text: &[(K, bool)]) {
        *SCRIPT.lock() = (text.to_vec(), 0);
    }

    fn console_prompt(
        script: &[(K, bool)],
        timeout_ms: u64,
    ) -> Result<Vec<u8>, LuksCredentialError> {
        narf_input::init_global_ring(64);
        narf_input::__reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();
        let saved = narf_input::secret::__take_keyboard_pollers_for_test();
        let _ = narf_input::register_keyboard_poller(script_poll);
        type_keys(script);
        OUTPUT.lock().clear();
        let prev_tap = narf_console::__test_set_uart_tap(Some(capture));
        let got = read_passphrase(&volume(), Source::Console, UUID, timeout_ms);
        narf_console::__test_set_uart_tap(prev_tap);
        narf_input::secret::__restore_keyboard_pollers_for_test(saved);
        narf_input::__reset_modifiers_for_test();
        got.map(|secret| secret.to_vec())
    }

    fn presses(text: &[K]) -> Vec<(K, bool)> {
        text.iter().flat_map(|&k| [(k, true), (k, false)]).collect()
    }

    fn smoke_luks_console_prompt_reads_the_keyboard() -> TestResult {
        // Shift+N, a, r, f, Backspace, f, Enter: "Narf".
        let mut script = alloc::vec![(K::LeftShift, true)];
        script.extend(presses(&[K::N]));
        script.push((K::LeftShift, false));
        script.extend(presses(&[K::A, K::R, K::F, K::Backspace, K::F, K::Enter]));
        let got = console_prompt(&script, 5_000);
        let leaked = narf_input::pop_key();
        let still_secret = narf_input::secret_entry_active();
        let out = OUTPUT.lock().clone();
        if got.as_deref() != Ok(b"Narf".as_slice()) {
            return TestResult::Fail("the console prompt must return the typed passphrase");
        }
        if leaked.is_some() || still_secret {
            return TestResult::Fail("keys typed at the prompt must not outlive it");
        }
        let shown = core::str::from_utf8(&out).unwrap_or("");
        if !shown.contains("passphrase (no echo): ") || !shown.contains(UUID) {
            return TestResult::Fail("the prompt must name the container and say it does not echo");
        }
        if out.windows(4).any(|w| w == b"Narf" || w == b"narf") {
            return TestResult::Fail("the passphrase was echoed to the console");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "initramfs/luks-prompt",
        smoke_luks_console_prompt_reads_the_keyboard
    );

    fn smoke_luks_console_prompt_cancel_timeout_declined() -> TestResult {
        if console_prompt(&presses(&[K::A, K::Escape]), 5_000)
            != Err(LuksCredentialError::Cancelled)
        {
            return TestResult::Fail("Escape must cancel the console prompt");
        }
        if console_prompt(&[], 50) != Err(LuksCredentialError::TimedOut) {
            return TestResult::Fail("an unanswered prompt must time out");
        }
        if narf_input::secret_entry_active() {
            return TestResult::Fail("a cancelled or timed-out prompt must release the keyboard");
        }
        let other = "4152464e-4c55-4b53-9000-0000000000ff";
        if !matches!(
            read_passphrase(&volume(), Source::Console, other, 50),
            Err(LuksCredentialError::Declined)
        ) {
            return TestResult::Fail("a container rd.luks.uuid does not name must be declined");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "initramfs/luks-prompt",
        smoke_luks_console_prompt_cancel_timeout_declined
    );

    fn smoke_luks_serial_prompt_reads_serial_bytes() -> TestResult {
        narf_input::init_global_ring(64);
        while narf_input::pop_ascii_byte().is_some() {}
        for &b in b"ab\x7fc\r" {
            let _ = narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
        }
        let got = read_passphrase(&volume(), Source::Serial, UUID, 5_000);
        if got.map(|s| s.to_vec()).as_deref() != Ok(b"ac".as_slice()) {
            return TestResult::Fail("the serial prompt must keep reading serial bytes");
        }
        if narf_input::secret_entry_active() {
            return TestResult::Fail("the serial prompt must not take the keyboard");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "initramfs/luks-prompt",
        smoke_luks_serial_prompt_reads_serial_bytes
    );
}
