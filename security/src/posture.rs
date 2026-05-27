//! Boot-time hardening posture report.
//!
//! A single struct the security-init initcall fills in so observability
//! can surface "which knobs are live" without each subsystem
//! re-discovering its own state at runtime.
//!
//! The "more secure than Linux" framing this enables: Linux ships ~40
//! hardening flags in `kernel-parameters.txt` and even kernel devs
//! struggle to enumerate which are live on a given boot. NARF exposes
//! one [`PostureReport`] that names every floor + every optional
//! enable in one place.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// KPTI posture on this CPU.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Posture {
    /// Single page table — Renoir/Phoenix, anything Meltdown-immune.
    #[default]
    Native,
    /// Dual page tables (page-table-isolation), required on
    /// Meltdown-vulnerable Intel.
    Isolate,
}

impl Posture {
    /// Encoded as a small integer for storage in an `AtomicU8`.
    #[inline]
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => Posture::Isolate,
            _ => Posture::Native,
        }
    }
    #[inline]
    pub fn as_byte(self) -> u8 {
        match self {
            Posture::Native => 0,
            Posture::Isolate => 1,
        }
    }
}

/// Reportable hardening state. Filled in by the security-init
/// initcall; readable by any subsystem.
#[derive(Debug, Default)]
pub struct PostureReport {
    pub smep: AtomicBool,
    pub smap: AtomicBool,
    pub cet_shstk: AtomicBool,
    pub cet_ibt: AtomicBool,
    pub pac_addr: AtomicBool,
    pub pac_generic: AtomicBool,
    pub mte: AtomicBool,
    pub kpti: AtomicU8,
    pub kaslr: AtomicBool,
    pub canary: AtomicBool,
    pub w_xor_x: AtomicBool,
    pub ro_after_init: AtomicBool,
}

impl PostureReport {
    pub const fn new() -> Self {
        Self {
            smep: AtomicBool::new(false),
            smap: AtomicBool::new(false),
            cet_shstk: AtomicBool::new(false),
            cet_ibt: AtomicBool::new(false),
            pac_addr: AtomicBool::new(false),
            pac_generic: AtomicBool::new(false),
            mte: AtomicBool::new(false),
            kpti: AtomicU8::new(0),
            kaslr: AtomicBool::new(false),
            canary: AtomicBool::new(false),
            w_xor_x: AtomicBool::new(false),
            ro_after_init: AtomicBool::new(false),
        }
    }

    /// Quick check: are the always-on floors live? SMEP + SMAP + W^X
    /// + canary + KASLR. KPTI is *not* in the floor because on
    /// Meltdown-immune parts the right answer is Native (don't pay).
    pub fn floors_live(&self) -> bool {
        self.smep.load(Ordering::Acquire)
            && self.smap.load(Ordering::Acquire)
            && self.w_xor_x.load(Ordering::Acquire)
            && self.canary.load(Ordering::Acquire)
            && self.kaslr.load(Ordering::Acquire)
    }

    /// Number of "extra" HW features turned on — CET, PAC, MTE.
    /// Diagnostic only; used by boot log to print "extras: 3/5 live."
    pub fn extras_count(&self) -> u32 {
        [
            &self.cet_shstk,
            &self.cet_ibt,
            &self.pac_addr,
            &self.pac_generic,
            &self.mte,
        ]
        .iter()
        .filter(|b| b.load(Ordering::Acquire))
        .count() as u32
    }
}

/// Global posture report. Populated once at boot; read at any time.
pub static REPORT: PostureReport = PostureReport::new();
