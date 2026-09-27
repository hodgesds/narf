//! Linux arm64 rt_sigframe for restorer-based userspace handlers.
//! Offsets follow arch/arm64/include/uapi/asm/{ucontext,sigcontext}.h.
use narf_arch::aarch64::user_mode::{UserFpState, UserState};
use narf_userspace::{SigDeliveryParams, SyscallArgs, SA_ONSTACK, SA_RESTART, SA_SIGINFO};

const USER_LIMIT: u64 = 1 << 47;
const UC: usize = 128;
const MC: usize = UC + 176;
const REGS: usize = MC + 8;
const SP: usize = MC + 256;
const PC: usize = MC + 264;
const PSTATE: usize = MC + 272;
const EXTRA: usize = MC + 288;
const FRAME_SIZE: usize = EXTRA + 4096;
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: usize = 528;

fn user_range(address: u64, len: usize) -> bool {
    address != 0 && address < USER_LIMIT && len as u64 <= USER_LIMIT - address
}
fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Build completely before publishing a handler context. Failed user writes
/// can leave partial user bytes, but never partially alter the kernel frame.
pub(super) fn deliver(
    state: &mut UserState,
    args: &SyscallArgs,
    params: &SigDeliveryParams,
    fp: &UserFpState,
) -> bool {
    let mut bytes = [0u8; FRAME_SIZE];
    let alternate = params.flags & SA_ONSTACK != 0 && params.altstack_sp != 0;
    let top = if alternate {
        let Some(top) = params.altstack_sp.checked_add(params.altstack_size) else {
            return false;
        };
        top
    } else {
        state.sp
    };
    let Some(bottom) = top.checked_sub(FRAME_SIZE as u64) else {
        return false;
    };
    let base = bottom & !15;
    if !user_range(base, FRAME_SIZE)
        || !user_range(params.handler, 4)
        || !user_range(params.restorer, 4)
        || (alternate && base < params.altstack_sp)
    {
        return false;
    }
    let mut saved = *state;
    let restart = params.flags & SA_RESTART != 0 && params.restartable_syscall;
    if params.prerewound_syscall {
        if !restart {
            saved.pc = saved.pc.wrapping_add(4);
            saved.x[0] = (-4i64) as u64;
        }
    } else if restart && saved.x[0] == (-4i64) as u64 {
        saved.pc = saved.pc.wrapping_sub(4);
        saved.x[..6].copy_from_slice(&[
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
        ]);
    }
    put32(&mut bytes, 0, params.signum);
    put32(&mut bytes, 8, params.si_code as u32);
    if params.si_code <= 0 {
        put32(&mut bytes, 16, params.si_pid);
    } else {
        put64(&mut bytes, 16, params.si_addr);
    }
    put64(&mut bytes, 24, params.si_value);
    put64(&mut bytes, UC + 16, params.altstack_sp);
    put32(&mut bytes, UC + 24, if alternate { 1 } else { 0 });
    put64(&mut bytes, UC + 32, params.altstack_size);
    put64(
        &mut bytes,
        UC + 40,
        narf_userspace::signal_mask_of(narf_scheduler::current_task_id().raw()),
    );
    put64(&mut bytes, MC, params.si_addr);
    for (i, value) in saved.x.iter().enumerate() {
        put64(&mut bytes, REGS + i * 8, *value);
    }
    put64(&mut bytes, SP, saved.sp);
    put64(&mut bytes, PC, saved.pc);
    put64(&mut bytes, PSTATE, saved.spsr);
    put32(&mut bytes, EXTRA, FPSIMD_MAGIC);
    put32(&mut bytes, EXTRA + 4, FPSIMD_SIZE as u32);
    // SAFETY: UserFpState is initialized, exactly 528 bytes, with no padding
    // read; its documented layout is Q0..Q31, FPCR u64, FPSR u64.
    let fp_bytes = unsafe { core::slice::from_raw_parts(fp.as_ptr(), 528) };
    put32(&mut bytes, EXTRA + 8, get64(fp_bytes, 520) as u32);
    put32(&mut bytes, EXTRA + 12, get64(fp_bytes, 512) as u32);
    bytes[EXTRA + 16..EXTRA + FPSIMD_SIZE].copy_from_slice(&fp_bytes[..512]);
    // Zero initialization supplies the terminating _aarch64_ctx and all ABI
    // padding, so the frame exposes no uninitialized kernel bytes.
    // SAFETY: bounded user range, live initialized kernel source, SVC context.
    if unsafe {
        narf_arch::aarch64::uaccess::copy_user_guarded(base as *mut u8, bytes.as_ptr(), bytes.len())
    }
    .is_err()
    {
        return false;
    }
    state.sp = base;
    state.pc = params.handler;
    state.x[0] = params.signum as u64;
    if params.flags & SA_SIGINFO != 0 {
        state.x[1] = base;
        state.x[2] = base + UC as u64;
    }
    state.x[30] = params.restorer;
    true
}

fn valid_return(state: &UserState) -> bool {
    // Only NZCV is mutable user PSTATE on NARF's current arm64 ABI. In
    // particular reject EL1/EL2, AArch32, DAIF, PAN and tag-check overrides.
    state.spsr & !0xf000_0000 == 0
        && user_range(state.pc, 4)
        && state.pc & 3 == 0
        && user_range(state.sp, 1)
        && state.sp & 15 == 0
}

/// Snapshot hostile memory once, validate every record and register, and only
/// then restore FP state and return a complete GPR image to the trap adapter.
pub(super) fn restore(base: u64) -> Option<(UserState, UserFpState)> {
    if base & 15 != 0 || !user_range(base, FRAME_SIZE) {
        return None;
    }
    let mut bytes = [0u8; FRAME_SIZE];
    // SAFETY: bounded user source and live writable kernel destination.
    unsafe {
        narf_arch::aarch64::uaccess::copy_user_guarded(
            bytes.as_mut_ptr(),
            base as *const u8,
            bytes.len(),
        )
    }
    .ok()?;
    let mut state = UserState {
        sp: get64(&bytes, SP),
        pc: get64(&bytes, PC),
        spsr: get64(&bytes, PSTATE),
        valid: 1,
        ..UserState::default()
    };
    for (i, value) in state.x.iter_mut().enumerate() {
        *value = get64(&bytes, REGS + i * 8);
    }
    if !valid_return(&state) {
        return None;
    }
    let mut fp = UserFpState::zeroed();
    let mut found = false;
    let mut cursor = EXTRA;
    loop {
        if cursor + 8 > bytes.len() {
            return None;
        }
        let magic = get32(&bytes, cursor);
        let size = get32(&bytes, cursor + 4) as usize;
        if magic == 0 && size == 0 {
            break;
        }
        if magic != FPSIMD_MAGIC || size != FPSIMD_SIZE || found || size > bytes.len() - cursor {
            return None;
        }
        // SAFETY: uniquely borrowed initialized UserFpState of 528 bytes.
        let fp_bytes = unsafe { core::slice::from_raw_parts_mut(fp.as_mut_ptr(), 528) };
        fp_bytes[..512].copy_from_slice(&bytes[cursor + 16..cursor + size]);
        put64(fp_bytes, 512, get32(&bytes, cursor + 12) as u64);
        put64(fp_bytes, 520, get32(&bytes, cursor + 8) as u64);
        found = true;
        cursor += size;
    }
    if !found {
        return None;
    }
    // The trap adapter publishes this image; only assembly restores hardware
    // after all Rust completes, so compiler-held SIMD temporaries stay intact.
    Some((state, fp))
}

fn smoke_arm64_sigreturn_validation() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let mut state = UserState {
        pc: 0x10000,
        sp: 0x20000,
        ..UserState::default()
    };
    if !valid_return(&state) {
        return TestResult::Fail("valid EL0 return rejected");
    }
    for forbidden in [1, 4, 5, 0x10, 0x40, 0x80, 1 << 22, 1 << 25] {
        state.spsr = forbidden;
        if valid_return(&state) {
            return TestResult::Fail("privileged return accepted");
        }
    }
    state.spsr = 0;
    state.pc = USER_LIMIT;
    if valid_return(&state) || user_range(u64::MAX - 8, 32) {
        return TestResult::Fail("kernel/overflow return accepted");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("frame", smoke_arm64_sigreturn_validation);
