//! In-kernel smoke for the `narf_led_submit` kfunc.
//!
//! Registers under `bpf/leds` (so `xtask test --subsystem bpf` prefix-matches).
//! Loads a real BPF program that calls the kfunc and proves the whole path:
//! the kfunc is resolvable cross-crate (its `narf.kfuncs` entry survived the
//! link), the program's call enqueues a command, and the LED engine worker's
//! drain applies it to the device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_bpf::prog::{BpfProg, BpfProgLoad, LoadRequest};
use narf_bpf::reexport::{Cap, Grant};
use narf_bpf::Outcome;
use narf_bpf_isa::encode::encode;
use narf_bpf_isa::{CallTarget, Decoded, Insn, Reg, Source};
use narf_bpf_verifier::kfunc::Context;
use narf_kernel_test::{kernel_test_in, TestResult};

use narf_drivers_leds::{led_devices, register_led, worker, SimpleLed};

fn load_cap() -> &'static Cap<BpfProgLoad, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<BpfProgLoad, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ = alloc::boxed::Box::leak(alloc::boxed::Box::new(Cap::<
            BpfProgLoad,
            Grant,
        >::bootstrap()));
        *g = Some(c);
    }
    g.expect("just installed")
}

fn r(n: u8) -> Reg {
    Reg::new(n).expect("register in range")
}

fn mov_imm(dst: u8, v: i32) -> Decoded {
    Decoded::Mov {
        wide: true,
        dst: r(dst),
        src: Source::Imm(v),
        sign_extend: None,
    }
}

fn call_kfunc(name: &str) -> Decoded {
    Decoded::Call(CallTarget::Kfunc(narf_bpf::kfunc::id_for(name)))
}

const EXIT: Decoded = Decoded::Exit;

fn asm(items: &[Decoded]) -> Vec<Insn> {
    let mut out = Vec::new();
    for d in items {
        out.extend_from_slice(encode(*d).slots());
    }
    out
}

fn load(name: &str, insns: Vec<Insn>) -> Result<Arc<BpfProg>, &'static str> {
    BpfProg::load(
        load_cap(),
        LoadRequest {
            name: String::from(name),
            insns,
            context: Context::Atomic,
            maps: Vec::new(),
            map_indices: Vec::new(),
            load_references: Vec::new(),
        },
    )
    .map_err(|_| "load rejected")
}

fn smoke_bpf_led_submit_sets_brightness_via_kfunc() -> TestResult {
    narf_drivers_leds::__reset_all_for_test();
    // Clear any commands a prior test left in the mailbox.
    worker::drain();
    register_led(Arc::new(SimpleLed::brightness_led("bpf-kfunc-led")));
    let idx = led_devices()
        .iter()
        .position(|d| d.name() == "bpf-kfunc-led")
        .expect("registered") as i32;

    // r1 = idx; r2 = ACTION_SET_BRIGHTNESS (0); r3 = 180; call narf_led_submit;
    // r0 = its return; exit. The BPF kfunc ABI passes args in r1..r5, result in
    // r0 — so this is the C call `narf_led_submit(idx, 0, 180)`.
    let insns = asm(&[
        mov_imm(1, idx),
        mov_imm(2, 0),
        mov_imm(3, 180),
        call_kfunc("narf_led_submit"),
        EXIT,
    ]);
    let Ok(prog) = load("led-blink", insns) else {
        return TestResult::Fail("load rejected the LED program");
    };

    match prog.run_atomic([0u64; narf_bpf::interp::MAX_CTX_WORDS], 0) {
        Some(Outcome::Returned(0)) => {}
        Some(Outcome::Returned(_)) => {
            return TestResult::Fail("narf_led_submit reported failure (mailbox full?)")
        }
        _ => return TestResult::Fail("program did not return cleanly from the kfunc"),
    }

    // The engine worker applies the queued command.
    worker::drain();
    if led_devices()[idx as usize].brightness() != 180 {
        return TestResult::Fail("the kfunc-enqueued command did not reach the LED after drain");
    }
    TestResult::Pass
}
kernel_test_in!("bpf/leds", smoke_bpf_led_submit_sets_brightness_via_kfunc);

fn smoke_bpf_led_submit_rejects_unknown_action() -> TestResult {
    narf_drivers_leds::__reset_all_for_test();
    if crate::narf_led_submit(0, u32::MAX, 0) != -22 {
        return TestResult::Fail("narf_led_submit did not return EINVAL");
    }
    // Rejection happens before enqueue, so the mailbox remains immediately
    // usable by a valid command.
    if crate::narf_led_submit(0, narf_drivers_leds::ACTION_OFF, 0) != 0 {
        return TestResult::Fail("invalid action polluted the LED mailbox");
    }
    worker::drain();
    TestResult::Pass
}
kernel_test_in!("bpf/leds", smoke_bpf_led_submit_rejects_unknown_action);
