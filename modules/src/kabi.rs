//! The kernel ABI a loadable module may call.
//!
//! Until this file existed, KSYMTAB was empty — there was not one
//! `narf_export!` call site in the tree — so a module could be parsed,
//! relocated and started, but could not call a single kernel function.
//!
//! ## Why this is a hand-written surface
//!
//! Rust has no stable ABI. `narf_block::register_block_device(&dyn BlockDev)`
//! cannot be exported to a separately-compiled module: the layout of `&dyn`,
//! of every `repr(Rust)` struct, and of the calling convention itself are all
//! free to change between compilations, and nothing in the toolchain will tell
//! you when they do. The only things that can safely cross the boundary are
//! `extern "C"` functions over primitives and `repr(C)` types.
//!
//! So the module ABI is not a projection of the kernel's internal APIs — it is
//! a deliberate, curated set of C shims, and every addition is a promise. It
//! starts small on purpose. `bpf/src/kfuncs.rs` made the same call for the same
//! reason ("deliberately tiny"), and is the closest in-tree precedent.
//!
//! Conventions, so the surface stays predictable as it grows:
//!
//!   * Errors are a negative errno in an `i32`, matching the syscall layer.
//!   * Sizes and counts are `usize`; addresses are raw pointers.
//!   * Anything with kernel-side lifetime is an opaque `u64` handle, never a
//!     borrowed reference.
//!   * No function may unwind. Every one is `extern "C"` and the kernel is
//!     built `panic=abort`, so this holds by construction.
//!   * **Every export is `unsafe`**, including ones taking no pointers. The
//!     caller is separately-compiled kernel-mode code whose arguments nothing
//!     has verified, so the boundary is unsafe as a whole; marking only the
//!     pointer-taking ones would imply the rest had been checked, and would
//!     mean adding a pointer argument later silently changes a function's
//!     contract without changing its declaration.
//!
//! ## Versioning
//!
//! Each export carries a CRC derived from its signature *as written* —
//! `crc_for_signature` hashes the stringified argument and return types at
//! compile time. Change a parameter and the CRC changes, so a module built
//! against the old signature is refused by `symbols::resolve` with
//! `CrcMismatch` instead of being called with the wrong stack layout. This is
//! Linux's MODVERSIONS idea (`kernel/module/version.c`) without needing
//! genksyms: the macro sees the tokens, so it can hash them.
//!
//! `DESIGN.md` deferred CRC generation to "build-system integration". It turns
//! out none is needed.

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;

macro_rules! register_kernel_abi_export {
    ($name:ident, $crc:expr) => {
        crate::symbols::export(stringify!($name), $name as usize, $crc)
    };
    ($name:ident, $crc:expr, $required_cap:expr) => {
        crate::symbols::export_with_cap(stringify!($name), $name as usize, $crc, $required_cap)
    };
}

/// FNV-1a over a signature string, evaluated at compile time.
///
/// Not a real CRC despite the field name it feeds; the property that matters
/// is that any change to the signature changes the value, and FNV-1a gives
/// that in a `const fn` with no table.
pub const fn crc_for_signature(sig: &str) -> u32 {
    let b = sig.as_bytes();
    let mut h: u32 = 0x811C_9DC5;
    let mut i = 0;
    while i < b.len() {
        h ^= b[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

/// Define the kernel ABI surface.
///
/// One invocation defines every export *and* the function that registers
/// them, so the two cannot drift — adding a function to the list is the only
/// step. Each export's CRC is computed from its own stringified signature.
macro_rules! kernel_abi {
    ($(
        $(#[$meta:meta])*
        $(requires $required_cap:expr;)?
        fn $name:ident ( $($arg:ident : $aty:ty),* $(,)? ) $(-> $ret:ty)? $body:block
    )*) => {
        $(
            $(#[$meta])*
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name ( $($arg : $aty),* ) $(-> $ret)? $body
        )*

        /// Every export's name, for diagnostics and the `/proc` surface.
        pub const NAMES: &[&str] = &[$(stringify!($name)),*];

        /// An empty ABI surface would mean no module can call anything —
        /// a build-time mistake, so it fails at build time.
        const _: () = assert!(!NAMES.is_empty(), "kernel ABI surface is empty");

        /// Register the whole surface with KSYMTAB.
        ///
        /// Called from the `modules-abi` initcall before any module can be
        /// loaded, and again by `symbols::__reset_for_test` to restore the
        /// boot state. Idempotent for that reason: re-registering a name
        /// would otherwise duplicate the entry and skew the ABI hash, which
        /// sums over the table.
        pub fn register_all() {
            $(
                if !crate::symbols::is_exported(stringify!($name)) {
                register_kernel_abi_export!(
                    $name,
                    crc_for_signature(concat!(
                        stringify!($name),
                        "(",
                        $(stringify!($aty), ",",)*
                        ")",
                        $("->", stringify!($ret),)?
                    ))
                    $(, $required_cap)?
                );
                }
            )*
        }
    };
}

kernel_abi! {
    /// Write `len` bytes of UTF-8 at `ptr` to the kernel console.
    ///
    /// Returns 0, or `-EINVAL` if the pointer is null or the bytes are not
    /// valid UTF-8. Modules that want formatting do it on their own side and
    /// hand over the finished bytes — exporting a varargs printf across an
    /// ABI boundary is a supply of foot-guns for no gain.
    ///
    /// # Safety
    /// `ptr` must name `len` readable bytes that stay valid for the duration
    /// of the call. A null pointer or a zero length is rejected rather than
    /// dereferenced; nothing else is checked.
    fn narf_printk(ptr: *const u8, len: usize) -> i32 {
        if ptr.is_null() || len == 0 {
            return -22;
        }
        // SAFETY: the module promises `ptr` names `len` readable bytes. This
        // is the ABI's trust boundary — a module is kernel-mode code and can
        // corrupt its own domain regardless; the check above only catches the
        // common mistake.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        match core::str::from_utf8(bytes) {
            Ok(s) => {
                narf_console::write_str(s);
                0
            }
            Err(_) => -22,
        }
    }

    /// Allocate `size` bytes with `align` from the kernel heap. Returns null
    /// on failure or on an invalid layout.
    ///
    /// Paired strictly with [`narf_kfree`], which must be given the same size
    /// and alignment — the kernel heap is not `malloc` and does not record
    /// the layout for you.
    ///
    /// # Safety
    /// No preconditions beyond the ABI's blanket one: an invalid or
    /// zero-sized layout returns null rather than allocating. The returned
    /// pointer must be released with [`narf_kfree`] and the same
    /// `size`/`align`, or it leaks.
    fn narf_kmalloc(size: usize, align: usize) -> *mut u8 {
        let Ok(layout) = Layout::from_size_align(size, align) else {
            return core::ptr::null_mut();
        };
        if layout.size() == 0 {
            return core::ptr::null_mut();
        }
        // Module allocations come from the calling domain's tagged heap when
        // one can serve them, so a buffer a module allocates is reachable only
        // through a pointer carrying that domain's tag — the same property its
        // image already has. Falls through to the ordinary kernel heap
        // whenever the tagged path declines (no MTE, FRAME, oversized, or the
        // window full), which is a capacity answer and not an error.
        {
            let domain = narf_lib::assert::current_domain();
            if let Some(p) = narf_memory::domain_heap::alloc(layout, domain) {
                return p;
            }
        }
        // SAFETY: the layout is non-zero-sized and valid, as `alloc` requires.
        unsafe { alloc(layout) }
    }

    /// Release an allocation from [`narf_kmalloc`].
    ///
    /// # Safety
    /// `ptr` must have come from [`narf_kmalloc`], must not have been freed
    /// already, and `size`/`align` must be exactly the values it was
    /// allocated with — the kernel heap does not record the layout, so a
    /// mismatch corrupts the allocator rather than failing. A null `ptr` is a
    /// no-op.
    fn narf_kfree(ptr: *mut u8, size: usize, align: usize) {
        if ptr.is_null() {
            return;
        }
        let Ok(layout) = Layout::from_size_align(size, align) else {
            return;
        };
        if layout.size() == 0 {
            return;
        }
        // Route by ADDRESS, not by current domain: a buffer may be freed
        // outside the scope that allocated it, or by a different domain, and
        // sending it to the wrong allocator corrupts one of them.
        if narf_memory::domain_heap::owns(ptr) {
            // SAFETY: forwarded from the module's contract — matched pair.
            unsafe { narf_memory::domain_heap::free(ptr, layout) };
            return;
        }
        // SAFETY: forwarded from the module's contract — `ptr` came from
        // `narf_kmalloc` with this exact layout.
        unsafe { dealloc(ptr, layout) }
    }

    /// Nanoseconds on the monotonic clock. The one every driver needs first,
    /// for timeouts and rate limiting.
    ///
    /// # Safety
    /// None in practice — it takes no arguments and reads a clock. `unsafe`
    /// only because the whole ABI surface is; see the module docs.
    fn narf_monotonic_ns() -> u64 {
        narf_time::monotonic_ns()
    }

    /// Register a PCI driver match from a loadable module.
    ///
    /// The first export that lets a `.ko` *be a driver*. `name`/`name_len`
    /// name the driver; the bytes are copied into a kernel-owned intern table,
    /// so the module may later unmap its `.rodata`. `vendor`/`device` are the
    /// PCI IDs to claim. `probe` is a `ModuleProbeFn` — an
    /// `extern "C" fn(dev_token: u64, reserved: u64) -> i32` — passed as a raw
    /// address, because `PciProbeFn`'s `BusDevice`/`Cap` arguments are
    /// `repr(Rust)` and cannot cross this boundary. The kernel installs a
    /// trampoline that dispatches matching devices to the thunk. Returns 0, or
    /// `-EINVAL` for a null/empty name, a non-UTF-8 name, or a null probe.
    ///
    /// # Safety
    /// `name` must name `name_len` readable bytes valid for the call. `probe`
    /// must be a valid `ModuleProbeFn` pointer that stays mapped for as long
    /// as the driver is registered. Module unload removes the callback and
    /// its device contexts before unmapping the owner's text.
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32 {
        if name.is_null() || name_len == 0 || probe == 0 {
            return -22; // -EINVAL
        }
        // SAFETY: the module promises `name` names `name_len` readable bytes.
        let bytes = unsafe { core::slice::from_raw_parts(name, name_len) };
        let Ok(name) = core::str::from_utf8(bytes) else {
            return -22;
        };
        // SAFETY: `probe` is non-null (checked) and the module promises it is a
        // valid `ModuleProbeFn` for as long as the match is registered.
        let owner = crate::symbols::current_init_id().0;
        // SAFETY: the validated callback remains owned by `owner`; the module
        // unload path removes it before that owner's text is unmapped.
        unsafe { narf_bus::register_module_pci_driver(owner, name, vendor, device, probe) }
    }

    // ── Device datapath: PCI/MMIO (Stage 1) + coherent DMA (Stage 2) ───────
    //
    // These let a module's probe actually drive the device it was handed. The
    // kernel keeps the device cap + mapped BARs in a per-device context keyed
    // by `dev` (the token the probe received); the module holds only the `dev`
    // token and 1-based BAR handles. Every op is cap-gated through the stored
    // device authority. `dev` is the `dev_token` the `ModuleProbeFn` was called
    // with.

    /// Enable PCI command bits (e.g. `MEM_SPACE | BUS_MASTER`) on the module's
    /// device so its BARs respond. Returns 0, or `-ENODEV`/`-EIO`.
    ///
    /// # Safety
    /// `dev` must be the token the module's probe was invoked with.
    fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_pci_enable(owner, dev, cmd_bits)
    }

    /// Map BAR `bar_idx` of the module's device; returns a 1-based BAR handle,
    /// or 0 on failure.
    ///
    /// # Safety
    /// `dev` must be the token the module's probe was invoked with.
    fn narf_bar_map(dev: u64, bar_idx: u8) -> u64 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_bar_map(owner, dev, bar_idx)
    }

    /// Read a 32-bit device register at `off` in BAR handle `bar`, storing it
    /// through `out`. Returns 0, or `-EINVAL` for a bad handle/offset/pointer.
    ///
    /// # Safety
    /// `out` must point to a writable `u32`. `dev`/`bar` identify a mapped BAR.
    fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32 {
        if out.is_null() {
            return -22; // -EINVAL
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_mmio_read32(owner, dev, bar, off) {
            Some(v) => {
                // SAFETY: `out` is non-null; the module promises it is writable.
                unsafe { out.write(v) };
                0
            }
            None => -22,
        }
    }

    /// Write `val` to the 32-bit device register at `off` in BAR handle `bar`.
    /// Returns 0, or `-EINVAL` for a bad handle/offset.
    ///
    /// # Safety
    /// `dev`/`bar` identify a mapped BAR of the module's device.
    fn narf_mmio_write32(dev: u64, bar: u64, off: u64, val: u32) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_mmio_write32(owner, dev, bar, off, val)
    }

    /// Responsively wait until `(read32(off) & mask) == expected`, bounded by
    /// `timeout_ns` (1 ns through 1 s). Returns `-ETIMEDOUT` on expiry.
    ///
    /// # Safety
    /// `dev`/`bar` identify a mapped BAR and `off` names a register safe to
    /// poll repeatedly.
    fn narf_mmio_wait32(
        dev: u64,
        bar: u64,
        off: u64,
        mask: u32,
        expected: u32,
        timeout_ns: u64,
    ) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_mmio_wait32(owner, dev, bar, off, mask, expected, timeout_ns)
    }

    /// Allocate a coherent DMA buffer in the module's effective isolation
    /// domain. Returns a 1-based opaque handle, or 0 on failure.
    ///
    /// # Safety
    /// `dev` must be the token the module's probe was invoked with. The caller
    /// must not use the returned handle after `narf_dma_free` or unload.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_alloc(dev: u64, len: usize) -> u64 {
        let owner = crate::symbols::current_execution_id().0;
        let domain = narf_lib::assert::current_domain();
        if owner == crate::symbols::KERNEL_MODULE_ID.0 || domain == narf_lib::id::DomainId::FRAME {
            return 0;
        }
        narf_bus::module_dma_alloc(owner, dev, len, domain)
    }

    /// Return the device-visible address of byte `off` in a DMA buffer.
    /// Returns 0 on success or `-EINVAL` for a stale handle, bad offset, or
    /// null output pointer.
    ///
    /// # Safety
    /// `out` must point to writable `u64` storage for the call's duration.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_addr(dev: u64, dma: u64, off: u64, out: *mut u64) -> i32 {
        if out.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_dma_addr(owner, dev, dma, off) {
            Some(addr) => {
                // SAFETY: `out` is non-null and the caller promises writable
                // storage for one `u64`.
                unsafe { out.write(addr) };
                0
            }
            None => -22,
        }
    }

    /// Copy module bytes into a coherent DMA buffer. The kernel checks the
    /// complete range before copying and never exposes the CPU mapping.
    ///
    /// # Safety
    /// `src` must name `len` readable bytes. `dev`/`dma` must identify a live
    /// buffer owned by the current module callback.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_write(dev: u64, dma: u64, off: u64, src: *const u8, len: usize) -> i32 {
        if src.is_null() {
            return -22;
        }
        // SAFETY: the module promises `src` names `len` readable bytes. The
        // bus bridge validates the destination range before copying.
        let src = unsafe { core::slice::from_raw_parts(src, len) };
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_dma_write(owner, dev, dma, off, src)
    }

    /// Copy coherent DMA bytes into module memory. The kernel checks the
    /// complete range before copying and never exposes the CPU mapping.
    ///
    /// # Safety
    /// `dst` must name `len` writable bytes. `dev`/`dma` must identify a live
    /// buffer owned by the current module callback.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_read(dev: u64, dma: u64, off: u64, dst: *mut u8, len: usize) -> i32 {
        if dst.is_null() {
            return -22;
        }
        // SAFETY: the module promises `dst` names `len` writable bytes. The
        // bus bridge validates the source range before copying.
        let dst = unsafe { core::slice::from_raw_parts_mut(dst, len) };
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_dma_read(owner, dev, dma, off, dst)
    }

    /// Responsively wait until one DMA status byte matches. This is the
    /// synchronous completion primitive for copy-mode module TX paths.
    ///
    /// # Safety
    /// `dev`/`dma` identify a live DMA handle and `off` names a device-owned
    /// status byte safe to sample repeatedly.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_wait8(
        dev: u64,
        dma: u64,
        off: u64,
        mask: u8,
        expected: u8,
        timeout_ns: u64,
    ) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_dma_wait8(owner, dev, dma, off, mask, expected, timeout_ns)
    }

    /// Revoke and release a coherent DMA buffer. Returns 0, `-ENODEV`, or
    /// `-EINVAL`; a second free of the same handle is rejected.
    ///
    /// # Safety
    /// `dev`/`dma` must be opaque handles returned to this module.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_free(dev: u64, dma: u64) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_dma_free(owner, dev, dma)
    }

    // ── Device datapath: MSI-X + task-context callbacks (Stage 3) ────

    /// Discover and retain the device's MSI-X table. Returns 0,
    /// `-EOPNOTSUPP` when the function has no MSI-X capability, or another
    /// negative errno for a stale device/configuration failure.
    ///
    /// # Safety
    /// `dev` must be the live token supplied to the current module callback.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_msix_enable(dev: u64) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_msix_enable(owner, dev)
    }

    /// Allocate and program one MSI-X vector, writing its kernel vector number
    /// through `out_vector`.
    ///
    /// # Safety
    /// `out_vector` must point to writable `u16` storage for the call.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_msix_claim(dev: u64, out_vector: *mut u16) -> i32 {
        if out_vector.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_msix_claim(owner, dev) {
            Ok(vector) => {
                // SAFETY: non-null above; the module promises writable storage.
                unsafe { out_vector.write(vector) };
                0
            }
            Err(errno) => errno,
        }
    }

    /// Attach a synchronous module callback to a claimed vector. The callback
    /// runs from an executor task in the module's effective domain, never from
    /// the hard-IRQ handler. Returning non-zero stops the callback pump.
    ///
    /// # Safety
    /// `callback` must be a valid `extern "C" fn(u64) -> i32` address that
    /// remains mapped until device teardown.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_irq_set_handler(dev: u64, vector: u16, callback: usize, cookie: u64) -> i32 {
        if callback == 0 {
            return -22;
        }
        // SAFETY: the module supplies the documented C callback address and
        // unload removes the binding before its text is unmapped.
        let callback: narf_bus::ModuleCallbackFn = unsafe { core::mem::transmute(callback) };
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_irq_set_handler(owner, dev, vector, callback, cookie)
    }

    /// Spawn one 1-ms periodic task-context callback for this device. The
    /// first poll is immediate; returning non-zero retires the poller.
    ///
    /// # Safety
    /// `callback` has the same lifetime/signature contract as
    /// [`narf_irq_set_handler`].
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32 {
        if callback == 0 {
            return -22;
        }
        // SAFETY: same callback contract as `narf_irq_set_handler`.
        let callback: narf_bus::ModuleCallbackFn = unsafe { core::mem::transmute(callback) };
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_spawn_poller(owner, dev, callback, cookie)
    }


    // ── Device datapath: copy-mode network interface (Stage 4) ──────

    /// Register one Ethernet interface for the device and return its ifindex.
    /// `tx_callback` is an `extern "C" fn(*const u8, usize) -> i32`; it runs in
    /// the module's effective domain and must consume the borrowed frame before
    /// returning.
    ///
    /// # Safety
    /// `mac` names six readable bytes, `out_ifindex` names writable `u32`
    /// storage, and `tx_callback` remains valid until device teardown.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_netif_register(
        dev: u64,
        mac: *const u8,
        tx_callback: usize,
        out_ifindex: *mut u32,
    ) -> i32 {
        if mac.is_null() || tx_callback == 0 || out_ifindex.is_null() {
            return -22;
        }
        // SAFETY: the module promises six readable bytes.
        let mut mac_bytes = [0u8; 6];
        // SAFETY: the module promises six readable bytes.
        mac_bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(mac, 6) });
        // SAFETY: the callback address has the documented C signature and the
        // bus context removes it before module text is unmapped.
        let tx_callback: narf_bus::ModuleTxFn = unsafe { core::mem::transmute(tx_callback) };
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_netif_register(owner, dev, mac_bytes, tx_callback) {
            Ok(ifindex) => {
                // SAFETY: non-null above; caller promises writable storage.
                unsafe { out_ifindex.write(ifindex) };
                0
            }
            Err(errno) => errno,
        }
    }

    /// Deliver one copied Ethernet frame from a module RX ring into the kernel
    /// stack. The stack may rewrite bytes in place for XDP before the call
    /// returns; the module retains ownership of the backing storage.
    ///
    /// # Safety
    /// `frame` names `len` writable bytes for the duration of the call.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_netif_rx(dev: u64, ifindex: u32, frame: *mut u8, len: usize) -> i32 {
        if frame.is_null() || len == 0 || len > u16::MAX as usize {
            return -22;
        }
        // SAFETY: the module promises this writable range; the stack borrows
        // it only synchronously and never retains the pointer.
        let frame = unsafe { core::slice::from_raw_parts_mut(frame, len) };
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_netif_rx(owner, dev, ifindex, frame)
    }
}

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// The surface must actually be in KSYMTAB. Before `kabi` existed this table
/// was empty tree-wide, so a module could be relocated and started but could
/// not call one kernel function; this is the test that keeps that from
/// silently coming back if the `modules-abi` initcall is ever dropped.
fn smoke_kabi_surface_is_registered() -> TestResult {
    for name in NAMES {
        if !crate::symbols::is_exported(name) {
            return TestResult::Fail("a kernel ABI export is missing from KSYMTAB");
        }
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_surface_is_registered);

/// DMA access is privileged at link time as well as at handle invocation.
/// A module that omits `required_caps=DmaBuffer:*` must never receive the
/// function address to call in the first place.
fn smoke_kabi_dma_exports_require_cap() -> TestResult {
    register_all();
    let denied = crate::manifest::Manifest::default();
    match crate::symbols::resolve("narf_dma_alloc", None, &denied) {
        Err(crate::symbols::ResolveError::CapMissing(narf_capabilities::CapKind::DmaBuffer)) => {}
        _ => return TestResult::Fail("DMA export resolved without DmaBuffer cap declaration"),
    }

    let mut allowed = crate::manifest::Manifest::default();
    allowed.required_caps.push(crate::manifest::RequiredCap {
        kind: narf_capabilities::CapKind::DmaBuffer,
        right: <narf_capabilities::Write as narf_capabilities::Rights>::BITS,
    });
    if crate::symbols::resolve("narf_dma_alloc", None, &allowed).is_err() {
        return TestResult::Fail("DMA export stayed hidden with DmaBuffer cap declaration");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_dma_exports_require_cap);

fn smoke_kabi_irq_exports_require_cap() -> TestResult {
    register_all();
    let denied = crate::manifest::Manifest::default();
    match crate::symbols::resolve("narf_spawn_poller", None, &denied) {
        Err(crate::symbols::ResolveError::CapMissing(narf_capabilities::CapKind::BusDevice)) => {}
        _ => return TestResult::Fail("IRQ export resolved without BusDevice cap declaration"),
    }

    let mut allowed = crate::manifest::Manifest::default();
    allowed.required_caps.push(crate::manifest::RequiredCap {
        kind: narf_capabilities::CapKind::BusDevice,
        right: <narf_capabilities::Write as narf_capabilities::Rights>::BITS,
    });
    if crate::symbols::resolve("narf_spawn_poller", None, &allowed).is_err() {
        return TestResult::Fail("IRQ export stayed hidden with BusDevice cap declaration");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_irq_exports_require_cap);

fn smoke_kabi_netif_exports_require_cap() -> TestResult {
    register_all();
    let denied = crate::manifest::Manifest::default();
    match crate::symbols::resolve("narf_netif_register", None, &denied) {
        Err(crate::symbols::ResolveError::CapMissing(narf_capabilities::CapKind::NetIface)) => {}
        _ => return TestResult::Fail("netif export resolved without NetIface cap declaration"),
    }

    let mut allowed = crate::manifest::Manifest::default();
    allowed.required_caps.push(crate::manifest::RequiredCap {
        kind: narf_capabilities::CapKind::NetIface,
        right: <narf_capabilities::Write as narf_capabilities::Rights>::BITS,
    });
    if crate::symbols::resolve("narf_netif_register", None, &allowed).is_err() {
        return TestResult::Fail("netif export stayed hidden with NetIface cap declaration");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_netif_exports_require_cap);

/// Registration is idempotent: a second call must not duplicate entries,
/// because the ABI hash sums over the table and would change.
fn smoke_kabi_register_all_is_idempotent() -> TestResult {
    let before = crate::symbols::export_count();
    let hash_before = crate::symbols::compute_abi_hash();
    register_all();
    if crate::symbols::export_count() != before {
        return TestResult::Fail("register_all duplicated entries on a second call");
    }
    if crate::symbols::compute_abi_hash() != hash_before {
        return TestResult::Fail("ABI hash moved across an idempotent re-registration");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_register_all_is_idempotent);

/// The CRC must track the signature. If it did not, a module built against
/// an old signature would be called with the wrong stack layout instead of
/// being refused — the exact failure MODVERSIONS exists to prevent.
fn smoke_kabi_crc_tracks_signature() -> TestResult {
    let a = crc_for_signature("narf_printk(*const u8,usize,)->i32");
    let same = crc_for_signature("narf_printk(*const u8,usize,)->i32");
    let arg_changed = crc_for_signature("narf_printk(*const u8,u32,)->i32");
    let ret_changed = crc_for_signature("narf_printk(*const u8,usize,)->i64");
    let name_changed = crc_for_signature("narf_printq(*const u8,usize,)->i32");

    if a != same {
        return TestResult::Fail("crc_for_signature is not deterministic");
    }
    if a == arg_changed || a == ret_changed || a == name_changed {
        return TestResult::Fail("crc_for_signature collided on a changed signature");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_crc_tracks_signature);

/// The ABI hash must be derived from the table, not a constant — otherwise
/// it cannot catch the "wrong kernel" case it exists for.
fn smoke_kabi_abi_hash_follows_the_table() -> TestResult {
    // Start from the boot state. Several unrelated smokes call
    // `set_kernel_abi(0)` after resetting, so whether the published hash
    // matches the table depends on what ran before this — asserting on
    // ambient global state made this smoke order-dependent, and it failed in
    // CI for that reason rather than for anything about the hash.
    crate::symbols::__reset_for_test();

    let before = crate::symbols::compute_abi_hash();
    if before == 0 {
        return TestResult::Fail("ABI hash is zero over a non-empty export table");
    }
    if crate::symbols::kernel_abi() != before {
        return TestResult::Fail("published kernel_abi does not match the current table");
    }

    // Adding a symbol must move it.
    crate::symbols::export("narf_kabi_smoke_probe", 0xDEAD_BEEF, 0x1234_5678);
    let after = crate::symbols::compute_abi_hash();

    // Restores the boot surface, dropping the probe.
    crate::symbols::__reset_for_test();
    crate::symbols::set_kernel_abi(crate::symbols::compute_abi_hash());

    if after == before {
        return TestResult::Fail("ABI hash did not change when an export was added");
    }
    if crate::symbols::compute_abi_hash() != before {
        return TestResult::Fail("reset did not restore the boot export surface");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_abi_hash_follows_the_table);

/// `narf_printk` must reject rather than dereference bad input — a module
/// passing a null pointer is a bug to report, not a kernel fault.
fn smoke_kabi_printk_rejects_bad_input() -> TestResult {
    // SAFETY: deliberately passing the arguments the function documents as
    // rejected; neither is dereferenced.
    let null = unsafe { narf_printk(core::ptr::null(), 8) };
    // SAFETY: the pointer is valid; the zero length is what is under test.
    let zero = unsafe { narf_printk(b"x".as_ptr(), 0) };
    // 0x80 is a continuation byte with no lead byte — not valid UTF-8.
    let bad: [u8; 2] = [0x80, 0x80];
    // SAFETY: `bad` names 2 readable bytes for the duration of the call.
    let invalid = unsafe { narf_printk(bad.as_ptr(), bad.len()) };

    if null == -22 && zero == -22 && invalid == -22 {
        TestResult::Pass
    } else {
        TestResult::Fail("narf_printk accepted input it documents as invalid")
    }
}
kernel_test_in!("modules/kabi", smoke_kabi_printk_rejects_bad_input);

/// The heap pair must round-trip, including the layouts it documents as
/// rejected.
fn smoke_kabi_kmalloc_round_trip() -> TestResult {
    // SAFETY: valid layout.
    let p = unsafe { narf_kmalloc(64, 8) };
    if p.is_null() {
        return TestResult::Fail("narf_kmalloc(64, 8) returned null");
    }
    // SAFETY: `p` names 64 writable bytes just allocated.
    unsafe { core::ptr::write_bytes(p, 0xA5, 64) };
    // SAFETY: `p` came from `narf_kmalloc` with exactly this layout.
    let readback = unsafe { *p };
    // SAFETY: as above; freed exactly once.
    unsafe { narf_kfree(p, 64, 8) };

    // Zero size and a non-power-of-two alignment are both invalid layouts.
    // SAFETY: no allocation is performed for either.
    let zero = unsafe { narf_kmalloc(0, 8) };
    // SAFETY: as above.
    let bad_align = unsafe { narf_kmalloc(64, 3) };
    // SAFETY: null is documented as a no-op.
    unsafe { narf_kfree(core::ptr::null_mut(), 64, 8) };

    if readback != 0xA5 {
        return TestResult::Fail("kmalloc'd memory did not hold what was written");
    }
    if !zero.is_null() || !bad_align.is_null() {
        return TestResult::Fail("narf_kmalloc accepted an invalid layout");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_kmalloc_round_trip);

/// `narf_register_pci_driver` must register a module driver's match in the
/// bus registry and wire its probe thunk through the trampoline. This is the
/// unit-level half of the e1000-as-a-`.ko` proof: the full `.ko` load path is
/// exercised by the loader e2e smoke, but the registration mechanism the
/// export funnels into is proven here without any hardware.
///
/// A unique, device-free `(vendor, device)` is used so the entry is harmless
/// if left registered (no such device exists, so the trampoline never fires
/// against a real probe walk).
extern "C" fn kabi_smoke_probe_thunk(_dev_token: u64, _reserved: u64) -> i32 {
    -38 // -ENOSYS: this synthetic match deliberately declines probing.
}

fn smoke_kabi_register_pci_driver_round_trips() -> TestResult {
    const VENDOR: u16 = 0xFEED;
    const DEVICE: u16 = 0xFACE;
    let name = b"narf-kabi-smoke-drv";

    // SAFETY: `name` names its bytes for the call; the thunk pointer is a
    // valid `extern "C"` fn for the program's lifetime.
    let rc = unsafe {
        narf_register_pci_driver(
            name.as_ptr(),
            name.len(),
            VENDOR,
            DEVICE,
            kabi_smoke_probe_thunk as usize,
        )
    };
    if rc != 0 {
        return TestResult::Fail("narf_register_pci_driver rejected a valid registration");
    }

    // A null probe is -EINVAL and must NOT register anything.
    // SAFETY: documented invalid input; nothing is dereferenced.
    let bad = unsafe { narf_register_pci_driver(name.as_ptr(), name.len(), VENDOR, DEVICE, 0) };
    if bad != -22 {
        return TestResult::Fail("narf_register_pci_driver accepted a null probe");
    }

    // The match is now in the bus registry under the interned name.
    let present = narf_bus::registered_pci_drivers().into_iter().any(|m| {
        m.name == "narf-kabi-smoke-drv"
            && m.kind
                == narf_bus::MatchKind::VendorDevice {
                    vendor: VENDOR,
                    device: DEVICE,
                }
    });
    if !present {
        return TestResult::Fail("module match did not appear in the bus registry");
    }

    // The trampoline records the exact module thunk supplied above.
    match narf_bus::driver_match::__module_thunk_for_test(VENDOR, DEVICE) {
        Some(f) => {
            if f(0, 0) != -38 {
                return TestResult::Fail("registered thunk did not reach the module probe");
            }
        }
        None => return TestResult::Fail("module thunk was not recorded for dispatch"),
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_register_pci_driver_round_trips);
