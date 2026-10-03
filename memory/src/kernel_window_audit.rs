//! Audit: the higher-half kernel image window must not alias any frame the
//! frame allocator owns.
//!
//! The window maps the kernel image at `kernel_virt_base() + phys`, present
//! and writable (and executable over kernel text), on every CPU and in every
//! address space's kernel half. A frame the buddy owns inside it therefore has
//! a second, writable kernel mapping that nothing tracks: page tables, slab
//! pages and user memory could all be reached — and on aarch64's text block,
//! executed — through the window. The window is built from whole 2 MiB leaves,
//! so the property is about the leaves' slack, not the image bytes: the x86_64
//! window once ran from physical 0 (not the image start) and aliased the
//! 15 MiB of buddy RAM below `KERNEL_LOAD_BASE`.
//!
//! [`check`] examines the whole window rather than one sample frame. The
//! previous test allocated a single frame and looked up its alias; late in a
//! full run the buddy handed out a frame above 1 GiB, which the window can
//! never cover, and the test passed without examining anything. That is why a
//! full run was green while a memory-only run failed. The audit's answer does
//! not depend on which frames earlier tests happened to take, and two
//! registrations exercise that: `frame/src/kernel_window_audit.rs` runs among
//! the first cases of a full run and prints the report, and the one in
//! `tests.rs` runs thousands of cases later, where the old probe was vacuous.
//!
//! Independence: the window is discovered by walking the live page tables over
//! the whole image-window VA span, `[KERNEL_LINK_BASE, MODULE_VA_BASE)` — not
//! by asking `kernel_window_covers` or `image_window_phys_bounds`, the
//! predicates the mapping and reservation code use, which would agree with
//! that code even if both were wrong. Each covered frame is then compared with
//! the allocator's own state: the ranges it was given (ownership, which
//! catches a frame that happens to be allocated right now) and its free lists
//! and per-CPU caches (availability).

use narf_kernel_test::TestResult;

use crate::{FrameAllocError, PhysAddr};

const SZ_4K: u64 = 1 << 12;
const SZ_2M: u64 = 1 << 21;
const SZ_1G: u64 = 1 << 30;

/// Physically contiguous stretches of the window tracked, merged in VA order.
pub const MAX_RUNS: usize = 16;

/// What one pass over the window found. Every count is printed by the frame
/// crate's registration.
#[derive(Debug, Default)]
pub struct KernelWindowAudit {
    /// VA span walked, `[lo, hi)`.
    pub lo: u64,
    pub hi: u64,
    runs: [(u64, u64); MAX_RUNS],
    pub nruns: usize,
    /// More discontiguous runs than [`MAX_RUNS`]; the tail was not checked.
    pub overflow: bool,
    pub leaves_4k: u64,
    pub leaves_2m: u64,
    /// 2 MiB slots of the span that fell inside a 1 GiB leaf.
    pub slots_in_1g: u64,
    /// Frames the window maps.
    pub covered: u64,
    /// Frames of `image_phys_bounds()`, and how many of them the walk found.
    pub image_frames: u64,
    pub image_covered: u64,
    /// Covered frames the allocator owns / could hand out right now.
    pub owned: u64,
    pub free: u64,
    /// First run with a nonzero answer: `(start, end, owned, free)`.
    pub first_bad: Option<(u64, u64, u64, u64)>,
    /// The single frame the original test examined, and its two answers.
    pub probe_phys: u64,
    pub probe_covered: bool,
    pub probe_mapped: bool,
}

impl KernelWindowAudit {
    /// Record `[pa, pa + len)` as mapped, merging with the previous run.
    fn visit(&mut self, pa: u64, len: u64) {
        if self.nruns > 0 && self.runs[self.nruns - 1].1 == pa {
            self.runs[self.nruns - 1].1 = pa + len;
        } else if self.nruns < MAX_RUNS {
            self.runs[self.nruns] = (pa, pa + len);
            self.nruns += 1;
        } else {
            self.overflow = true;
        }
    }

    /// The physical runs found, `[start, end)` bytes.
    pub fn runs(&self) -> &[(u64, u64)] {
        &self.runs[..self.nruns]
    }

    fn overlap_frames(&self, lo: u64, hi: u64) -> u64 {
        self.runs()
            .iter()
            .map(|&(a, b)| {
                let s = a.max(lo);
                let e = b.min(hi);
                if s < e {
                    (e - s) / SZ_4K
                } else {
                    0
                }
            })
            .sum()
    }

    /// The verdict. Never `Pass` on an empty walk: finding nothing means the
    /// walk looked in the wrong place, not that the property holds.
    pub fn verdict(&self) -> TestResult {
        if self.covered == 0 {
            return TestResult::Fail(
                "kernel-window walk found no present leaf; nothing was checked",
            );
        }
        if self.overflow {
            return TestResult::Fail(
                "kernel window has more discontiguous runs than the audit tracks",
            );
        }
        // The walk must have found the image itself, or it is not looking at
        // the image window.
        if self.image_covered != self.image_frames {
            return TestResult::Fail("kernel-window walk does not cover the whole kernel image");
        }
        if self.owned != 0 {
            return TestResult::Fail("kernel window maps frames the frame allocator owns");
        }
        if self.free != 0 {
            return TestResult::Fail(
                "kernel window maps frames that are free in the frame allocator",
            );
        }
        if self.probe_covered || self.probe_mapped {
            return TestResult::Fail("buddy frame still has a higher-half kernel-window alias");
        }
        TestResult::Pass
    }
}

/// One raw descriptor of the table at physical `table`.
///
/// # Safety
/// `table` must be a live page-table page reachable through the kernel's
/// physical accessor, and `idx < 512`.
unsafe fn entry(table: u64, idx: u64) -> u64 {
    // SAFETY: per the contract; a table page is 512 naturally aligned u64s.
    unsafe {
        PhysAddr::new(table)
            .kernel_ptr::<u64>()
            .add(idx as usize)
            .read_volatile()
    }
}

#[cfg(target_arch = "x86_64")]
mod arch {
    pub const ADDR: u64 = 0x000f_ffff_ffff_f000;
    pub fn root() -> crate::PhysAddr {
        // SAFETY: CR3 is readable at CPL=0; the kernel half of every PML4 is
        // copied from the kernel's, so PML4[511] is the kernel window's.
        unsafe { crate::paging::read_cr3() }
    }
    pub fn valid(e: u64) -> bool {
        e & 1 != 0
    }
    /// A present PDPT/PD entry with PS set maps a leaf.
    pub fn upper_leaf(e: u64) -> bool {
        e & (1 << 7) != 0
    }
    pub fn upper_table(e: u64) -> bool {
        !upper_leaf(e)
    }
    pub fn l3_page(e: u64) -> bool {
        valid(e)
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    pub const ADDR: u64 = 0x0000_ffff_ffff_f000;
    pub fn root() -> crate::PhysAddr {
        // SAFETY: `MRS TTBR1_EL1` at EL1 is always defined.
        unsafe { crate::paging::read_ttbr1_el1() }
    }
    pub fn valid(e: u64) -> bool {
        e & 1 != 0
    }
    /// Bits [1:0] = 0b01 is a block at L1/L2.
    pub fn upper_leaf(e: u64) -> bool {
        e & 0b11 == 0b01
    }
    pub fn upper_table(e: u64) -> bool {
        e & 0b11 == 0b11
    }
    /// At L3 only 0b11 is a page; 0b01 is reserved (invalid).
    pub fn l3_page(e: u64) -> bool {
        e & 0b11 == 0b11
    }
}

/// Walk every 2 MiB slot of `[lo, hi)` from the live root and record each
/// present leaf's physical span.
fn scan_window(a: &mut KernelWindowAudit) {
    let root = arch::root().raw();
    let mut va = a.lo;
    while va < a.hi {
        let (i0, i1, i2) = ((va >> 39) & 511, (va >> 30) & 511, (va >> 21) & 511);
        // Every table address below comes from a valid table descriptor read
        // from the live root, and the kernel keeps its page-table pages
        // reachable through the physical accessor for the life of the boot.
        // SAFETY: `root` is the live kernel root; `i0 < 512`.
        let e0 = unsafe { entry(root, i0) };
        if arch::valid(e0) && arch::upper_table(e0) {
            // SAFETY: `e0` is a valid table descriptor; `i1 < 512`.
            let e1 = unsafe { entry(e0 & arch::ADDR, i1) };
            if arch::valid(e1) && arch::upper_leaf(e1) {
                let base = e1 & arch::ADDR & !(SZ_1G - 1);
                a.slots_in_1g += 1;
                a.visit(base + (va & (SZ_1G - 1)), SZ_2M);
            } else if arch::valid(e1) {
                // SAFETY: `e1` is valid and not a leaf, so a table; `i2 < 512`.
                let e2 = unsafe { entry(e1 & arch::ADDR, i2) };
                if arch::valid(e2) && arch::upper_leaf(e2) {
                    a.leaves_2m += 1;
                    a.visit(e2 & arch::ADDR & !(SZ_2M - 1), SZ_2M);
                } else if arch::valid(e2) && arch::upper_table(e2) {
                    let pt = e2 & arch::ADDR;
                    for i3 in 0..512 {
                        // SAFETY: `pt` came from a valid table descriptor.
                        let e3 = unsafe { entry(pt, i3) };
                        if arch::l3_page(e3) {
                            a.leaves_4k += 1;
                            a.visit(e3 & arch::ADDR, SZ_4K);
                        }
                    }
                }
            }
        }
        va += SZ_2M;
    }
}

/// Walk the window, compare it with the allocator, and run the original
/// single-frame probe. `Err` carries the `TestResult` for an allocator that
/// cannot answer at all.
pub fn check() -> Result<KernelWindowAudit, TestResult> {
    // Preserved from the single-frame version: an allocator that is not up
    // has nothing to alias, and every other answer would be a guess.
    let probe = match crate::alloc_frame() {
        Ok(f) => f,
        Err(FrameAllocError::Uninitialised) => {
            return Err(TestResult::Skip("frame allocator not initialised"))
        }
        Err(_) => return Err(TestResult::Fail("alloc_frame failed")),
    };

    let mut a = KernelWindowAudit {
        lo: crate::kaslr::KERNEL_LINK_BASE,
        hi: crate::module_text::MODULE_VA_BASE,
        probe_phys: probe.start_address().raw(),
        ..KernelWindowAudit::default()
    };
    scan_window(&mut a);

    a.covered = a.runs().iter().map(|&(s, e)| (e - s) / SZ_4K).sum();
    let (kstart, kend) = crate::kaslr::image_phys_bounds();
    let (istart, iend) = (kstart & !(SZ_4K - 1), kend.next_multiple_of(SZ_4K));
    a.image_frames = (iend - istart) / SZ_4K;
    a.image_covered = a.overlap_frames(istart, iend);

    for i in 0..a.nruns {
        let (s, e) = a.runs[i];
        let o = crate::frame::allocator_owned_frames_in(s, e);
        let f = crate::frame::free_frames_in(s, e);
        a.owned += o;
        a.free += f;
        if (o | f) != 0 && a.first_bad.is_none() {
            a.first_bad = Some((s, e, o, f));
        }
    }

    // The sample frame the old test examined, asked the old question: is its
    // `kernel_virt_base() + phys` address mapped? Kept so the original
    // assertion still runs, now alongside the whole-window check instead of
    // standing in for it.
    let probe_va = crate::kaslr::kernel_virt_base().wrapping_add(a.probe_phys);
    a.probe_mapped = (a.lo..a.hi).contains(&probe_va)
        // SAFETY: the live root's tables are reachable through the kernel's
        // physical accessor; `leaf_flags_at` only reads them.
        && unsafe { crate::paging::leaf_flags_at(arch::root(), crate::VirtAddr::new(probe_va)) }
            .is_some();
    a.probe_covered = a.overlap_frames(a.probe_phys, a.probe_phys + SZ_4K) != 0;
    crate::free_frame(probe);
    Ok(a)
}
