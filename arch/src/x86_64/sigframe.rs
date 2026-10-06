//! Linux x86_64 `rt_sigframe` layout and the FPU/xstate part of a signal
//! frame, shared by every NARF signal-delivery path (the live-trap-frame path
//! in `frame/` and the own-stack `UserState` path in `userspace/`).
//!
//! Layout, low → high address (`arch/x86/include/asm/sigframe.h`,
//! `arch/x86/kernel/signal.c::get_sigframe`):
//!
//! ```text
//! rsp →  pretcode                      8 B   (sa_restorer)
//!        struct ucontext uc          304 B   (uc_mcontext at +40)
//!        struct siginfo info         128 B
//!        … padding to 64 B …
//!        xstate area (XSAVE standard format) + FP_XSTATE_MAGIC2
//! top
//! ```
//!
//! The ORDER is ABI: glibc's `ucontext_t` (0x3c8 B) is larger than the
//! kernel's `struct ucontext`, and handlers copy `sizeof(ucontext_t)` from the
//! `uc` they are handed. With siginfo and the xstate area above `uc`, that
//! read stays inside the frame. One shared definition keeps the two delivery
//! paths (and their `rt_sigreturn` counterparts) from drifting apart again.

use core::sync::atomic::{AtomicU64, Ordering};

/// `sizeof(struct ucontext)`: uc_flags, uc_link, uc_stack, uc_mcontext,
/// uc_sigmask.
pub const UCONTEXT_BYTES: u64 = 304;
/// `sizeof(struct siginfo)`.
pub const SIGINFO_BYTES: u64 = 128;
/// Offset of `uc_mcontext` inside `struct ucontext`.
pub const MCONTEXT_OFFSET: u64 = 40;
/// `pretcode` + `uc` + `info`.
pub const FRAME_BYTES: u64 = 8 + UCONTEXT_BYTES + SIGINFO_BYTES;

/// `uc_flags` bits (`arch/x86/include/uapi/asm/ucontext.h`).
pub const UC_FP_XSTATE: u64 = 0x1;
pub const UC_SIGCONTEXT_SS: u64 = 0x2;
pub const UC_STRICT_RESTORE_SS: u64 = 0x4;

/// `struct _fpx_sw_bytes` markers (`arch/x86/include/uapi/asm/sigcontext.h`).
pub const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
pub const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
pub const FP_XSTATE_MAGIC2_SIZE: usize = 4;

const FXSAVE_BYTES: usize = 512;
/// `fxregs_state.sw_reserved` — where `struct _fpx_sw_bytes` lives.
const SW_BYTES_OFF: usize = 464;
const XSAVE_HDR_OFF: usize = 512;
const XSAVE_HDR_BYTES: usize = 64;
/// Kernel staging capacity. Equal to the per-task FPU area
/// (`xsave::FPU_AREA_SIZE`); an enabled feature set larger than this is
/// never XSAVEd for a task in the first place.
pub const IMAGE_CAP: usize = super::xsave::FPU_AREA_SIZE;

/// Where each part of an `rt_sigframe` goes for a given stack top.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Handler entry RSP (points at `pretcode`; ≡ 8 mod 16 like a call).
    pub rsp: u64,
    pub uc: u64,
    pub info: u64,
    /// 64-byte-aligned xstate/FXSAVE area above the frame.
    pub fpstate: u64,
}

/// `get_sigframe`: carve the FPU area (`fpu__alloc_mathframe`, 64-byte
/// aligned) off the top, then `sp = round_down(sp - frame_size, 16) - 8`.
pub const fn layout(stack_top: u64, fp_bytes: u64) -> Layout {
    let fpstate = stack_top.wrapping_sub(fp_bytes) & !63;
    let rsp = (fpstate.wrapping_sub(FRAME_BYTES) & !0xF).wrapping_sub(8);
    Layout {
        rsp,
        uc: rsp + 8,
        info: rsp + 8 + UCONTEXT_BYTES,
        fpstate,
    }
}

/// `rt_sigreturn` receives the siginfo address (what delivery put in RSI,
/// or `rsp + UCONTEXT_BYTES` after the handler's `ret` popped `pretcode`);
/// the ucontext sits directly below it.
pub const fn uc_from_info(info: u64) -> u64 {
    info.wrapping_sub(UCONTEXT_BYTES)
}

/// The XCR0 user features saved in signal frames and the standard-format
/// XSAVE size for them, computed once. `0` = not yet computed; bit 63 marks
/// "no XSAVE, use FXSAVE" (never a real XCR0 bit).
static SIG_XSTATE: AtomicU64 = AtomicU64::new(0);
const NO_XSAVE: u64 = 1 << 63;

fn sig_xstate() -> Option<(u64, usize)> {
    let cached = SIG_XSTATE.load(Ordering::Relaxed);
    if cached == NO_XSAVE {
        return None;
    }
    if cached != 0 {
        // Packed as (size << 32) | low-32 mask bits; every user feature
        // NARF enables (x87..PKRU, bit 9) fits in the low half.
        return Some((cached & 0xFFFF_FFFF, (cached >> 32) as usize));
    }
    let caps = super::xsave::caps();
    let computed = if caps.xcr0_supported == 0 {
        NO_XSAVE
    } else {
        // SAFETY: XSAVE is supported (CPUID.0Dh present) and NARF boot
        // validation enables CR4.OSXSAVE before user code can run.
        let mask = unsafe { super::xsave::read_xcr0() };
        let size = super::xsave::area_size_for_mask(mask);
        if mask >> 32 != 0 || size + FP_XSTATE_MAGIC2_SIZE > IMAGE_CAP || size < 576 {
            NO_XSAVE
        } else {
            ((size as u64) << 32) | mask
        }
    };
    SIG_XSTATE.store(computed, Ordering::Relaxed);
    sig_xstate()
}

/// Bytes the FPU area of an rt frame occupies (`fpu__get_fpstate_size`):
/// the standard-format xstate plus `FP_XSTATE_MAGIC2`, or a bare FXSAVE.
pub fn fp_bytes() -> u64 {
    sig_xstate()
        .map(|(_, size)| (size + FP_XSTATE_MAGIC2_SIZE) as u64)
        .unwrap_or(FXSAVE_BYTES as u64)
}

/// 64-byte-aligned staging image of the FPU area of a signal frame.
#[repr(C, align(64))]
pub struct FpImage {
    bytes: [u8; IMAGE_CAP],
    len: usize,
    xsave: bool,
}

impl core::fmt::Debug for FpImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpImage")
            .field("len", &self.len)
            .field("xsave", &self.xsave)
            .finish_non_exhaustive()
    }
}

impl FpImage {
    const fn zeroed() -> Self {
        Self {
            bytes: [0; IMAGE_CAP],
            len: 0,
            xsave: false,
        }
    }
    /// The bytes to write at `Layout::fpstate`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    /// Whether the image is an XSAVE frame (`uc_flags` gets `UC_FP_XSTATE`).
    pub fn is_xstate(&self) -> bool {
        self.xsave
    }
}

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

/// `copy_fpstate_to_sigframe` for the CURRENT CPU's live user FPU state:
/// standard-format `XSAVE` of the enabled user features with the
/// `_fpx_sw_bytes` descriptor and `FP_XSTATE_MAGIC2`, or `FXSAVE` without
/// XSAVE support.
///
/// # Safety
/// The interrupted task's user FPU registers must be live in hardware (the
/// caller materializes a deferred image first), at CPL 0 with
/// CR4.OSFXSR (and OSXSAVE when XSAVE is used) set.
pub unsafe fn capture() -> FpImage {
    let mut img = FpImage::zeroed();
    match sig_xstate() {
        Some((mask, size)) => {
            // SAFETY: caller contract; `img.bytes` is 64-byte aligned and
            // `size <= IMAGE_CAP`; RFBM = enabled user features only.
            unsafe {
                core::arch::asm!(
                    "xsave64 [{0}]",
                    in(reg) img.bytes.as_mut_ptr(),
                    in("eax") mask as u32,
                    in("edx") (mask >> 32) as u32,
                    options(nostack, preserves_flags)
                );
            }
            let b = &mut img.bytes;
            b[SW_BYTES_OFF..FXSAVE_BYTES].fill(0);
            put_u32(b, SW_BYTES_OFF, FP_XSTATE_MAGIC1);
            put_u32(b, SW_BYTES_OFF + 4, (size + FP_XSTATE_MAGIC2_SIZE) as u32);
            put_u64(b, SW_BYTES_OFF + 8, mask);
            put_u32(b, SW_BYTES_OFF + 16, size as u32);
            put_u32(b, size, FP_XSTATE_MAGIC2);
            img.len = size + FP_XSTATE_MAGIC2_SIZE;
            img.xsave = true;
        }
        None => {
            // SAFETY: caller contract; FXSAVE needs 16-byte alignment.
            unsafe {
                core::arch::asm!(
                    "fxsave64 [{0}]",
                    in(reg) img.bytes.as_mut_ptr(),
                    options(nostack, preserves_flags)
                );
            }
            img.len = FXSAVE_BYTES;
        }
    }
    img
}

/// Why a frame's FPU area could not be restored — `badframe` in Linux.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RestoreError {
    /// The user memory could not be read.
    Fault,
    /// A self-described xstate image with an invalid header
    /// (`validate_user_xstate_header`): XRSTOR of it would #GP at CPL 0.
    BadHeader,
}

/// `fpu__restore_sig` for an rt frame whose FPU area is at `fpstate`:
/// validate exactly what Linux validates, then load it into the CPU.
/// `read_user(addr, dst)` must copy user memory without trusting `addr`.
///
/// - `_fpx_sw_bytes` absent/inconsistent, or `FP_XSTATE_MAGIC2` missing →
///   legacy FXSAVE restore (`check_xstate_in_sigframe` → `fx_only`).
/// - Valid descriptor: header must have `xcomp_bv == 0`, zero reserved
///   bytes and `xfeatures ⊆` enabled features, else `BadHeader`. Features
///   the frame does not carry are reset to their init state.
/// - MXCSR reserved bits are cleared (they would #GP the restore).
///
/// # Safety
/// CPL 0 with CR4.OSFXSR/OSXSAVE set; the caller has materialized the
/// current task's FPU ownership so the restored state becomes the task's.
pub unsafe fn restore(
    fpstate: u64,
    mut read_user: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<(), RestoreError> {
    let mut img = FpImage::zeroed();
    if !read_user(fpstate, &mut img.bytes[..FXSAVE_BYTES]) {
        return Err(RestoreError::Fault);
    }
    // MXCSR (bytes 24..28): Linux masks with mxcsr_feature_mask.
    let mxcsr = get_u32(&img.bytes, 24) & 0xffff;
    put_u32(&mut img.bytes, 24, mxcsr);

    let xstate = sig_xstate().and_then(|(mask, size)| {
        let b = &img.bytes;
        let magic1 = get_u32(b, SW_BYTES_OFF);
        let extended = get_u32(b, SW_BYTES_OFF + 4) as usize;
        let xfeatures = get_u64(b, SW_BYTES_OFF + 8);
        let xsize = get_u32(b, SW_BYTES_OFF + 16) as usize;
        let ok = magic1 == FP_XSTATE_MAGIC1
            && xsize >= FXSAVE_BYTES + XSAVE_HDR_BYTES
            && xsize <= size
            && extended == xsize + FP_XSTATE_MAGIC2_SIZE;
        ok.then_some((mask, xsize, xfeatures & mask))
    });
    let xstate = match xstate {
        Some((mask, xsize, xfeatures)) => {
            if !read_user(
                fpstate + FXSAVE_BYTES as u64,
                &mut img.bytes[FXSAVE_BYTES..xsize + FP_XSTATE_MAGIC2_SIZE],
            ) {
                return Err(RestoreError::Fault);
            }
            if get_u32(&img.bytes, xsize) == FP_XSTATE_MAGIC2 {
                Some((mask, xfeatures))
            } else {
                None
            }
        }
        None => None,
    };

    match xstate {
        Some((mask, xfeatures)) => {
            let hdr = &img.bytes[XSAVE_HDR_OFF..XSAVE_HDR_OFF + XSAVE_HDR_BYTES];
            let xstate_bv = get_u64(hdr, 0);
            let xcomp_bv = get_u64(hdr, 8);
            if xstate_bv & !mask != 0 || xcomp_bv != 0 || hdr[16..].iter().any(|&b| b != 0) {
                return Err(RestoreError::BadHeader);
            }
            // Components outside the frame's xfeatures restore as init
            // (Linux restores init_fpstate for ~ufeatures).
            put_u64(&mut img.bytes, XSAVE_HDR_OFF, xstate_bv & xfeatures);
            // SAFETY: caller contract; header validated (standard format,
            // only enabled features), MXCSR sanitized, buffer aligned.
            unsafe {
                core::arch::asm!(
                    "xrstor64 [{0}]",
                    in(reg) img.bytes.as_ptr(),
                    in("eax") mask as u32,
                    in("edx") (mask >> 32) as u32,
                    options(nostack, preserves_flags)
                );
            }
        }
        None => {
            // SAFETY: caller contract; sanitized 64-byte-aligned FXSAVE image.
            unsafe {
                core::arch::asm!(
                    "fxrstor64 [{0}]",
                    in(reg) img.bytes.as_ptr(),
                    options(nostack, preserves_flags)
                );
            }
        }
    }
    Ok(())
}
