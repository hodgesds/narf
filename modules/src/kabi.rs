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

// USB datapath export helpers. Kept above the `kernel_abi!` block: xtask
// compiles that block alone (to compute the ABI hash), without kernel crates.

/// Build a completion notification from an export's raw callback argument.
///
/// # Safety
/// `callback` is 0 or the address of an `extern "C" fn(u64) -> i32` in the
/// calling module's text, which stays mapped until the module's USB
/// contexts are retired at unload.
unsafe fn usb_completion(callback: usize, cookie: u64) -> narf_bus::module_usb::Completion {
    narf_bus::module_usb::Completion {
        callback: (callback != 0).then(|| {
            // SAFETY: the caller promises the documented C callback address.
            unsafe { core::mem::transmute::<usize, narf_bus::ModuleCallbackFn>(callback) }
        }),
        cookie,
    }
}

/// Store a submitted request id, or return the submit error.
///
/// # Safety
/// `out_urb` is non-null and names writable, aligned `u64` storage.
unsafe fn usb_submitted(result: Result<u64, i32>, out_urb: *mut u64) -> i32 {
    match result {
        Ok(urb) => {
            // SAFETY: the caller checked `out_urb` is non-null, and the
            // export contract promises writable, aligned storage.
            unsafe { out_urb.write(urb) };
            0
        }
        Err(e) => e,
    }
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

    /// Register a USB class-driver match for this module. `match_flags`
    /// selects which fields are compared, as Linux `usb_device_id`:
    /// bit 0 `(idVendor, idProduct)`, bit 1 interface class, bit 2 interface
    /// subclass, bit 3 interface protocol; unselected fields are ignored.
    /// `probe` is a `ModuleProbeFn` called through the module call gate, in
    /// task context, for a device no built-in driver claimed; its `dev_token`
    /// is an opaque USB device token, accepted by the `narf_usb_*` exports,
    /// and a 0 return claims the device. Returns 0, `-EINVAL` for a bad
    /// name, null probe, no/unknown flags or a vendor match on VID 0,
    /// `-ENODEV` when the kernel has no USB stack, `-EBUSY` when another
    /// module holds the same match, or `-ENOSPC` when the module match table
    /// is full.
    ///
    /// # Safety
    /// `name` must name `name_len` readable bytes valid for the call. `probe`
    /// must stay mapped for as long as the match is registered; module unload
    /// removes the match before unmapping the owner's text.
    // Flat C arguments, one per `usb_device_id` field, so no `repr(C)` struct
    // has to be shared with separately compiled modules.
    #[allow(clippy::too_many_arguments)]
    fn narf_register_usb_driver(
        name: *const u8,
        name_len: usize,
        match_flags: u16,
        vendor: u16,
        product: u16,
        class: u8,
        subclass: u8,
        protocol: u8,
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
        let m = match narf_bus::module_usb::ModuleUsbMatch::from_flags(
            match_flags, vendor, product, class, subclass, protocol,
        ) {
            Ok(m) => m,
            Err(errno) => return errno,
        };
        let owner = crate::symbols::current_init_id().0;
        // SAFETY: `probe` is non-null (checked); the unload path removes the
        // match before the owner's text is unmapped.
        unsafe { narf_bus::module_usb::register_module_usb_driver(owner, name, m, probe) }
    }

    /// Register an SDIO function-driver match for this module. `vendor`/`device`
    /// are the card's SDIO ids and `function` the function number (F1..=F7) to
    /// claim. `probe` is a `ModuleProbeFn` called through the module call gate,
    /// in task context, for a card no built-in driver claimed; its `dev_token`
    /// is an opaque SDIO device token (no SDIO datapath export accepts it yet)
    /// and a 0 return claims the card. Returns 0, `-EINVAL` for a bad name,
    /// null probe or an out-of-range function, `-ENODEV` when the kernel has no
    /// SDIO stack, `-EBUSY` when another module owns the match.
    ///
    /// # Safety
    /// `name` must name `name_len` readable bytes valid for the call. `probe`
    /// must be a valid `ModuleProbeFn` pointer that stays mapped for as long as
    /// the driver is registered; module unload removes the callback and its
    /// device contexts before unmapping the owner's text.
    fn narf_register_sdio_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        function: u8,
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
        let m = match narf_bus::module_sdio::ModuleSdioMatch::new(vendor, device, function) {
            Ok(m) => m,
            Err(errno) => return errno,
        };
        let owner = crate::symbols::current_init_id().0;
        // SAFETY: `probe` is non-null (checked); the unload path removes the
        // match before the owner's text is unmapped.
        unsafe { narf_bus::module_sdio::register_module_sdio_driver(owner, name, m, probe) }
    }

    /// Register a Devicetree driver match for this module. `name`/`name_len`
    /// name the driver; `compatible`/`compatible_len` are the single
    /// `of_device_id.compatible` string it claims. `probe` is a `ModuleProbeFn`
    /// called through the module call gate, in task context, for a DT node no
    /// built-in driver claimed; its `dev_token` is an opaque DT token (no DT
    /// datapath export accepts it yet) and a 0 return binds the node. Returns
    /// 0, `-EINVAL` for a bad/non-UTF-8 name or compatible or a null probe,
    /// `-EBUSY` when another module already claims the compatible.
    ///
    /// # Safety
    /// `name`/`compatible` must name their readable byte lengths for the call.
    /// `probe` must be a valid `ModuleProbeFn` pointer that stays mapped for as
    /// long as the driver is registered; module unload removes the callback and
    /// its device contexts before unmapping the owner's text.
    fn narf_register_dt_driver(
        name: *const u8,
        name_len: usize,
        compatible: *const u8,
        compatible_len: usize,
        probe: usize,
    ) -> i32 {
        if name.is_null() || name_len == 0 || compatible.is_null() || compatible_len == 0 || probe == 0
        {
            return -22; // -EINVAL
        }
        // SAFETY: the module promises each pointer names its byte length.
        let name_bytes = unsafe { core::slice::from_raw_parts(name, name_len) };
        let Ok(name) = core::str::from_utf8(name_bytes) else {
            return -22;
        };
        // SAFETY: as above.
        let compat_bytes = unsafe { core::slice::from_raw_parts(compatible, compatible_len) };
        let Ok(compatible) = core::str::from_utf8(compat_bytes) else {
            return -22;
        };
        let owner = crate::symbols::current_init_id().0;
        // SAFETY: `probe` is non-null (checked); the unload path removes the
        // match before the owner's text is unmapped.
        unsafe { narf_bus::module_dt::register_module_dt_driver(owner, name, compatible, probe) }
    }

    // ── Device datapath: PCI/MMIO (Stage 1) + coherent DMA (Stage 2) ───────
    //
    // These let a module's probe actually drive the device it was handed. The
    // kernel keeps the device cap + mapped BARs in a per-device context keyed
    // by `dev` (the token the probe received); the module holds only the `dev`
    // token and 1-based BAR handles. Every op is cap-gated through the stored
    // device authority. `dev` is the `dev_token` the `ModuleProbeFn` was called
    // with.

    /// Park inherited PCI decoding/mastering and enter D0 before initial
    /// BAR/DMA setup. Refused once this module context has live resources.
    ///
    /// # Safety
    /// `dev` is the caller's fresh probe token; no concurrent setup may run.
    fn narf_pci_prepare_probe(dev: u64) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::module_pci_prepare_probe(owner, dev)
    }

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

    /// Write the length in bytes of BAR handle `bar` through `out_len`.
    /// Returns 0, or `-EINVAL` for a bad handle or null pointer.
    ///
    /// # Safety
    /// `out_len` must point to writable `u64` storage.
    fn narf_bar_len(dev: u64, bar: u64, out_len: *mut u64) -> i32 {
        if out_len.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_bar_len(owner, dev, bar) {
            Some(len) => {
                // SAFETY: non-null; the module promises writable storage.
                unsafe { out_len.write(len) };
                0
            }
            None => -22,
        }
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

    /// Keep DMA allocations pinned after teardown if drain cannot be proven.
    /// Set retain=1 before exposing ring addresses; clear only after a terminal
    /// hardware drain/reset. Invalid owner/token or retain>1 fails closed.
    ///
    /// # Safety
    /// Clearing retention promises that no device can still access any buffer.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_retain_on_teardown(dev:u64,retain:u32)->i32{
        if retain>1{return -22;}
        let owner=crate::symbols::current_execution_id().0;
        narf_bus::driver_match::module_dma_retain_on_teardown(owner,dev,retain!=0)
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


    // ── Device datapath: identity, plain MSI, ASPM, mapped DMA ──────────
    //
    // What a PCIe driver with its own interrupt and ring programming needs
    // beyond Stages 1–4 (ath11k is the first consumer). See
    // `modules/DATAPATH_ABI_DESIGN.md`, "PCI identity, plain MSI and mapped
    // DMA".

    /// Fill `out` with the function's 16-byte identity record (vendor,
    /// device, subsystem ids, revision, class, segment/bus/devfn; layout in
    /// `narf_bus::driver_match::module_pci_identity`). `len` must be at least
    /// 16. Returns 0, `-EINVAL`, or `-ENODEV`.
    ///
    /// # Safety
    /// `out` must name `len` writable bytes for the call.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_pci_identity(dev: u64, out: *mut u8, len: usize) -> i32 {
        if out.is_null() || len < narf_bus::driver_match::MODULE_PCI_IDENTITY_LEN {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_pci_identity(owner, dev) {
            Ok(record) => {
                // SAFETY: non-null and at least `record.len()` writable bytes.
                unsafe { core::ptr::copy_nonoverlapping(record.as_ptr(), out, record.len()) };
                0
            }
            Err(errno) => errno,
        }
    }

    /// Program multi-message MSI: exactly `want` vectors (power of two,
    /// 1..=32) in an aligned block, delivery left disabled. Writes the vector
    /// count, the first kernel vector, the Message Address and vector 0's
    /// Message Data. Vector `i` is `base_vector + i` for
    /// `narf_irq_set_handler`. `-ENOSPC` when the block cannot be had (ask
    /// again with fewer), `-EOPNOTSUPP` without an MSI capability, `-EBUSY`
    /// when MSI or MSI-X is already set up on the device.
    ///
    /// # Safety
    /// Every output pointer must name writable storage of its type.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_msi_enable(
        dev: u64,
        want: u16,
        out_count: *mut u16,
        out_base_vector: *mut u16,
        out_addr: *mut u64,
        out_data: *mut u32,
    ) -> i32 {
        if out_count.is_null() || out_base_vector.is_null() || out_addr.is_null() || out_data.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_msi_enable(owner, dev, want) {
            Ok(grant) => {
                // SAFETY: all four are non-null; the module promises writable
                // storage of each type.
                unsafe {
                    out_count.write(grant.count);
                    out_base_vector.write(grant.base_vector);
                    out_addr.write(grant.addr);
                    out_data.write(grant.data);
                }
                0
            }
            Err(errno) => errno,
        }
    }

    /// Enable (`enabled = 1`) or disable (`0`) delivery for the MSI block
    /// `narf_msi_enable` programmed.
    ///
    /// # Safety
    /// `dev` must be the live token supplied to the current module callback.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_msi_set_enabled(dev: u64, enabled: u32) -> i32 {
        if enabled > 1 {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::driver_match::module_msi_set_enabled(owner, dev, enabled != 0)
    }

    /// Set the PCIe Link Control ASPM field (bits 1:0: L0s, L1) to `aspmc`
    /// and write the previous field through `out_prev`. `-EOPNOTSUPP` on a
    /// function without a PCI Express capability.
    ///
    /// # Safety
    /// `out_prev` must point to writable `u16` storage.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_pcie_aspm(dev: u64, aspmc: u16, out_prev: *mut u16) -> i32 {
        if out_prev.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_pcie_aspm(owner, dev, aspmc) {
            Ok(previous) => {
                // SAFETY: non-null; the module promises writable storage.
                unsafe { out_prev.write(previous) };
                0
            }
            Err(errno) => errno,
        }
    }

    /// Allocate a coherent DMA buffer the module's CPU code may dereference:
    /// at least `len` bytes, wholly below `2^addr_bits` (32..=64), zeroed.
    /// Writes the CPU address, the device address and the reserved length,
    /// and returns a 1-based handle shared with `narf_dma_free`/`narf_dma_addr`
    /// (0 on failure). The CPU mapping is valid until `narf_dma_free` of the
    /// handle or device teardown.
    ///
    /// # Safety
    /// Each output pointer must name writable storage of its type. The module
    /// must not touch the mapping after freeing the handle.
    requires narf_capabilities::CapKind::DmaBuffer;
    fn narf_dma_alloc_mapped(
        dev: u64,
        len: usize,
        addr_bits: u32,
        out_cpu: *mut usize,
        out_bus: *mut u64,
        out_len: *mut usize,
    ) -> u64 {
        if out_cpu.is_null() || out_bus.is_null() || out_len.is_null() {
            return 0;
        }
        let owner = crate::symbols::current_execution_id().0;
        let domain = narf_lib::assert::current_domain();
        if owner == crate::symbols::KERNEL_MODULE_ID.0 || domain == narf_lib::id::DomainId::FRAME {
            return 0;
        }
        match narf_bus::driver_match::module_dma_alloc_mapped(owner, dev, len, addr_bits, domain) {
            Ok(dma) => {
                // SAFETY: all three non-null; the module promises storage.
                unsafe {
                    out_cpu.write(dma.cpu);
                    out_bus.write(dma.bus);
                    out_len.write(dma.len);
                }
                dma.handle
            }
            Err(_) => 0,
        }
    }

    // ── Runtime services: delay, entropy, platform tables, parameters ───

    /// Busy-wait `ns` nanoseconds (1 ns ..= 1 s) on the monotonic clock while
    /// keeping the kernel's sleep pumps (framebuffer, cursor, console) ticking
    /// — for hardware sequences with a mandated synchronous delay.
    ///
    /// # Safety
    /// None beyond the ABI's blanket contract; it holds the calling upcall.
    fn narf_udelay(ns: u64) -> i32 {
        if ns == 0 || ns > 1_000_000_000 {
            return -22;
        }
        let deadline = narf_time::Deadline::after_ns(ns);
        narf_scheduler::responsive_spin_until(|| deadline.expired(), narf_time::Deadline::after_ns(ns + 1_000));
        0
    }

    /// Fill `len` bytes (at most 4096 per call) with output of the kernel's
    /// health-tested entropy source. `-EAGAIN` when no healthy source is
    /// available — never a deterministic fallback.
    ///
    /// # Safety
    /// `buf` must name `len` writable bytes.
    fn narf_random_bytes(buf: *mut u8, len: usize) -> i32 {
        if buf.is_null() || len == 0 || len > 4096 {
            return -22;
        }
        // SAFETY: non-null; the module promises `len` writable bytes.
        let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
        match narf_crypto::try_fill_random_bytes(out) {
            Ok(()) => 0,
            Err(_) => {
                out.fill(0);
                -11
            }
        }
    }

    /// Copy the firmware's SMBIOS structure table, starting `off` bytes in,
    /// into `buf` (up to `len` bytes; `len` may be 0 to only size it). The
    /// table's total length is written through `out_total`. `-ENODATA` when
    /// the firmware published no table, `-EINVAL` for `off` past its end.
    ///
    /// # Safety
    /// `buf` must name `len` writable bytes (or be null with `len == 0`);
    /// `out_total` must point to writable `usize` storage.
    fn narf_smbios_read(off: usize, buf: *mut u8, len: usize, out_total: *mut usize) -> i32 {
        if out_total.is_null() || (buf.is_null() && len != 0) {
            return -22;
        }
        let Some(table) = narf_firmware_smbios::boot_table() else {
            return -61;
        };
        let bytes = table.bytes();
        if off > bytes.len() {
            return -22;
        }
        let n = len.min(bytes.len() - off);
        // SAFETY: `out_total` non-null; `buf` names `len >= n` writable bytes.
        unsafe {
            out_total.write(bytes.len());
            if n != 0 {
                core::ptr::copy_nonoverlapping(bytes[off..].as_ptr(), buf, n);
            }
        }
        0
    }

    /// Report whether open firmware `handle` carries a verified signer: 1
    /// signed, 0 unsigned, or a negative errno (`-EBADF`). Drivers that refuse
    /// unsigned board or regulatory data (ath11k, as built in) check this
    /// before using the bytes.
    ///
    /// # Safety
    /// None beyond the ABI's blanket contract.
    requires narf_capabilities::CapKind::Firmware;
    fn narf_firmware_signed(handle: u64) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        match narf_firmware::module_fetch::signed(owner, handle) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(errno) => errno,
        }
    }

    /// Copy the calling module's parameter `name` (its current value, after
    /// any `<module>.<name>=` from the kernel command line) into `out`, and
    /// write its length through `out_len`. `-ENOENT` if the module declares
    /// no such parameter; `-ENOBUFS` (with the needed length written) when
    /// `cap` is too small.
    ///
    /// # Safety
    /// `name` names `name_len` readable bytes; `out` names `cap` writable
    /// bytes (or is null with `cap == 0`); `out_len` names writable `usize`.
    fn narf_module_param(
        name: *const u8,
        name_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> i32 {
        if name.is_null() || name_len == 0 || out_len.is_null() || (out.is_null() && cap != 0) {
            return -22;
        }
        // SAFETY: the module promises `name_len` readable bytes at `name`.
        let name = unsafe { core::slice::from_raw_parts(name, name_len) };
        let Ok(name) = core::str::from_utf8(name) else {
            return -22;
        };
        // Init runs under the init-attribution context; probe, poller and
        // IRQ callbacks under the execution context. Either names the caller.
        let mut owner = crate::symbols::current_execution_id();
        if owner == crate::symbols::KERNEL_MODULE_ID {
            owner = crate::symbols::current_init_id();
        }
        let Some(module) = crate::registry::lookup_by_id(owner) else {
            return -19;
        };
        let Some(slot) = crate::params::find(&module.params, name) else {
            return -2;
        };
        let value = slot.read();
        // SAFETY: `out_len` is non-null and names writable `usize` storage.
        unsafe { out_len.write(value.len()) };
        if value.len() > cap {
            return -105; // -ENOBUFS, with the needed length reported
        }
        if !value.is_empty() {
            // SAFETY: `out` is non-null here (cap >= len > 0) and names
            // `cap >= value.len()` writable bytes.
            unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len()) };
        }
        0
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

    /// Register a device-aware Ethernet TX callback and return its ifindex.
    /// `tx_callback` is an `extern "C" fn(u64, *const u8, usize) -> i32`; it runs in
    /// the module's effective domain, receives `dev`, and consumes the frame before
    /// returning.
    ///
    /// # Safety
    /// `mac` names six readable bytes, `out_ifindex` names writable `u32`
    /// storage, and `tx_callback` remains valid until device teardown.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_netif_register_with_context(
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
        let tx_callback: narf_bus::ModuleTxCtxFn = unsafe { core::mem::transmute(tx_callback) };
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_netif_register_with_context(owner, dev, mac_bytes, tx_callback) {
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

    /// Open a versioned permanent wireless host on this module's existing
    /// probe device. No Rust object, MMIO mapping or firmware pointer crosses
    /// the boundary. `out_session` receives a never-reused, owner-scoped id.
    ///
    /// # Safety
    /// `dev` is this module's probe token; `out_session` is writable/aligned.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_wireless_open(dev: u64, family: u32, version: u32, out_session: *mut u64) -> i32 {
        if out_session.is_null() { return -22; }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_wireless::open(owner, dev, family, version) {
            Ok(session) => {
                // SAFETY: the module promises writable, aligned output storage.
                unsafe { out_session.write(session) };
                0
            }
            Err(error) => error,
        }
    }

    /// Open a versioned permanent wireless host with a per-session event
    /// callback for native→module control-plane events (family `WIFI`:
    /// cfg80211 scan/connect/key requests reach the module through this
    /// callback instead of tunnelling through the netif `tx_callback`).
    /// `event_callback` is an `extern "C" fn(u64, u32, *const u8, usize)
    /// -> i32` in the calling module's text: it receives the probe device
    /// token, the event id, and kernel-owned read-only payload bytes
    /// borrowed only for the call, and runs in the module's effective
    /// domain through the bus call gate. The callback address is stored in
    /// the session and forgotten when the session closes or the device is
    /// retired; the gate refuses a retired module. A null callback is
    /// `-EINVAL` — use plain `narf_wireless_open` for no event channel.
    /// No Rust object, MMIO mapping or firmware pointer crosses the
    /// boundary. `out_session` receives a never-reused, owner-scoped id.
    ///
    /// # Safety
    /// `dev` is this module's probe token; `event_callback` is 0 or the
    /// address of an `extern "C" fn(u64, u32, *const u8, usize) -> i32` in
    /// the calling module's text, which stays mapped until the module's
    /// wireless session is closed or its device context is retired;
    /// `out_session` is writable/aligned.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_wireless_open_with_event(
        dev: u64, family: u32, version: u32, event_callback: usize, out_session: *mut u64,
    ) -> i32 {
        if event_callback == 0 || out_session.is_null() { return -22; }
        // SAFETY: the caller promises the documented C callback address.
        let event_callback: narf_bus::ModuleWirelessEventFn =
            unsafe { core::mem::transmute(event_callback) };
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_wireless::open_with_event(owner, dev, family, version, event_callback) {
            Ok(session) => {
                // SAFETY: the module promises writable, aligned output storage.
                unsafe { out_session.write(session) };
                0
            }
            Err(error) => error,
        }
    }

    /// Copy one bounded family-protocol request into retained host work.
    /// Success means accepted; only poll's terminal result completes it.
    ///
    /// # Safety
    /// Request storage is readable for `request_len` and `out_operation` is
    /// writable/aligned. Ids must come from this module's exact probe service.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_wireless_submit(
        dev: u64, session: u64, opcode: u32,
        request: *const u8, request_len: usize, out_operation: *mut u64,
    ) -> i32 {
        if out_operation.is_null() || request_len > narf_bus::module_wireless::MAX_REQUEST
            || (request_len != 0 && request.is_null()) { return -22; }
        let request = if request_len == 0 { &[] } else {
            // SAFETY: the module promises readable bytes for this bounded call;
            // the host copies them before returning. The pointer is non-null.
            unsafe { core::slice::from_raw_parts(request, request_len) }
        };
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_wireless::submit(owner, dev, session, opcode, request) {
            Ok(operation) => {
                // SAFETY: writable aligned output, per the export contract.
                unsafe { out_operation.write(operation) };
                0
            }
            Err(error) => error,
        }
    }

    /// Poll once. `-EAGAIN` is pending; `-ENOBUFS` reports required bytes
    /// without consuming the terminal reply. Zero consumes a copied result.
    /// Other negative statuses are terminal errors, except invalid handles.
    ///
    /// # Safety
    /// Reply storage is writable for `reply_len` and `out_len` is writable/
    /// aligned. The two output ranges must not overlap.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_wireless_poll(
        dev: u64, session: u64, operation: u64,
        reply: *mut u8, reply_len: usize, out_len: *mut usize,
    ) -> i32 {
        if out_len.is_null() || reply_len > narf_bus::module_wireless::MAX_REPLY
            || (reply_len != 0 && reply.is_null()) { return -22; }
        let reply = if reply_len == 0 { &mut [] } else {
            // SAFETY: bounded writable module storage, borrowed for this call;
            // the nonempty buffer has a non-null pointer.
            unsafe { core::slice::from_raw_parts_mut(reply, reply_len) }
        };
        let owner = crate::symbols::current_execution_id().0;
        let (status, required) = narf_bus::module_wireless::poll(owner, dev, session, operation, reply);
        // SAFETY: writable aligned scalar output, per the export contract.
        unsafe { out_len.write(required) };
        status
    }

    /// Request cancellation; native resources remain retained until terminal
    /// completion. Continue polling the same operation id.
    ///
    /// # Safety
    /// Ids identify an operation submitted by this module's exact service.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_wireless_cancel(dev: u64, session: u64, operation: u64) -> i32 {
        narf_bus::module_wireless::cancel(crate::symbols::current_execution_id().0,
            dev, session, operation)
    }

    /// Withdraw the service and request native teardown. Uncertain DMA and
    /// in-flight work outlive module text; close never invents a DMA receipt.
    ///
    /// # Safety
    /// Ids identify this module's service; no later use of them is permitted.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_wireless_close(dev: u64, session: u64) -> i32 {
        narf_bus::module_wireless::close(crate::symbols::current_execution_id().0, dev, session)
    }

    /// Resolve a vendor firmware blob by `name` and retain it for this module.
    /// `out_handle` receives an owner-scoped, never-reused handle and
    /// `out_size` the total blob size; read it in bounded chunks with
    /// `narf_firmware_read`, then release it with `narf_firmware_close`. No
    /// kernel memory or `Cap<FirmwareBlob>` crosses the boundary.
    ///
    /// # Safety
    /// `name` names `name_len` readable bytes; `out_handle`/`out_size` are
    /// writable/aligned and must not overlap.
    requires narf_capabilities::CapKind::Firmware;
    fn narf_firmware_open(
        name: *const u8, name_len: usize, out_handle: *mut u64, out_size: *mut usize,
    ) -> i32 {
        if name.is_null() || name_len == 0 || name_len > narf_firmware::module_fetch::MAX_NAME
            || out_handle.is_null() || out_size.is_null()
        {
            return -22;
        }
        // SAFETY: the module promises `name_len` readable bytes for this call.
        let bytes = unsafe { core::slice::from_raw_parts(name, name_len) };
        let Ok(name) = core::str::from_utf8(bytes) else {
            return -22;
        };
        let owner = crate::symbols::current_execution_id().0;
        match narf_firmware::module_fetch::open(owner, name) {
            Ok((handle, size)) => {
                // SAFETY: writable aligned outputs, per the export contract.
                unsafe {
                    out_handle.write(handle);
                    out_size.write(size);
                }
                0
            }
            Err(error) => error,
        }
    }

    /// Copy up to `len` bytes of firmware `handle` starting at `offset` into
    /// the module's `buf`; `out_len` receives the count copied (`0` past end).
    ///
    /// # Safety
    /// `buf` names `len` writable bytes; `out_len` is writable/aligned. The
    /// handle must come from this module's `narf_firmware_open`.
    requires narf_capabilities::CapKind::Firmware;
    fn narf_firmware_read(
        handle: u64, offset: u64, buf: *mut u8, len: usize, out_len: *mut usize,
    ) -> i32 {
        if buf.is_null() || len == 0 || len > narf_firmware::module_fetch::MAX_CHUNK
            || out_len.is_null()
        {
            return -22;
        }
        // SAFETY: the module promises `len` writable bytes; the broker copies
        // into them synchronously and never retains the pointer.
        let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
        let owner = crate::symbols::current_execution_id().0;
        match narf_firmware::module_fetch::read(owner, handle, offset, out) {
            Ok(copied) => {
                // SAFETY: writable aligned scalar output, per the contract.
                unsafe { out_len.write(copied) };
                0
            }
            Err(error) => error,
        }
    }

    /// Release a firmware handle. Module unload releases any still-open handle.
    ///
    /// # Safety
    /// The handle must come from this module's `narf_firmware_open`; no later
    /// use of it is permitted.
    requires narf_capabilities::CapKind::Firmware;
    fn narf_firmware_close(handle: u64) -> i32 {
        narf_firmware::module_fetch::close(crate::symbols::current_execution_id().0, handle)
    }

    // ── Device datapath: USB transfers (URB-style) ──────────────────
    //
    // `dev` is the token a USB probe (`narf_register_usb_driver`) received.
    // Every request is kernel-owned: submit returns an opaque, never-reused
    // id; the kernel optionally calls `callback(cookie)` (an `extern "C"
    // fn(u64) -> i32`, task context, module domain) once the request is
    // terminal; `narf_usb_poll` collects it. Payloads are copied: module
    // memory is never a DMA target. See `narf_bus::module_usb`.

    /// Copy the configuration descriptor the device was probed with into
    /// `buf`, storing its length through `out_len`. `-ENOBUFS` (nothing
    /// copied, required length stored) when `len` is too small, so a call
    /// with `len = 0` sizes the buffer.
    ///
    /// # Safety
    /// `buf` names `len` writable bytes (it may be null when `len` is 0) and
    /// `out_len` names writable, aligned `usize` storage.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_config_descriptor(dev: u64, buf: *mut u8, len: usize, out_len: *mut usize) -> i32 {
        if out_len.is_null() || len > narf_bus::module_usb::MAX_CONFIG_DESCRIPTOR
            || (len != 0 && buf.is_null()) { return -22; }
        let out = if len == 0 { &mut [] } else {
            // SAFETY: non-null, bounded writable module storage for this call.
            unsafe { core::slice::from_raw_parts_mut(buf, len) }
        };
        let owner = crate::symbols::current_execution_id().0;
        let (status, required) = narf_bus::module_usb::config_descriptor(owner, dev, out);
        // SAFETY: writable aligned output, per the export contract.
        unsafe { out_len.write(required) };
        status
    }

    /// Request xHCI configuration of `count` endpoints, named by address
    /// (bit 7 = IN) as they appear in the configuration descriptor; the
    /// kernel takes type, packet size and interval from that descriptor.
    /// The request id is stored through `out_urb`; poll it for the result.
    ///
    /// # Safety
    /// `endpoints` names `count` readable bytes; `out_urb` names writable
    /// `u64` storage; `callback` is 0 or stays mapped until unload.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_configure(
        dev: u64, endpoints: *const u8, count: usize,
        callback: usize, cookie: u64, out_urb: *mut u64,
    ) -> i32 {
        if endpoints.is_null() || out_urb.is_null()
            || count == 0 || count > narf_bus::module_usb::MAX_CONFIGURE_ENDPOINTS { return -22; }
        // SAFETY: the module promises `count` readable bytes; bounded above.
        let endpoints = unsafe { core::slice::from_raw_parts(endpoints, count) };
        // SAFETY: `callback` is 0 or a valid `extern "C" fn(u64) -> i32`
        // address; unload retires the context before unmapping it.
        let done = unsafe { usb_completion(callback, cookie) };
        let owner = crate::symbols::current_execution_id().0;
        // SAFETY: `out_urb` was checked non-null above.
        unsafe { usb_submitted(narf_bus::module_usb::configure(owner, dev, endpoints, done), out_urb) }
    }

    /// Submit one control transfer on EP0. `setup` names the 8-byte SETUP
    /// packet. For an OUT request `data`/`len` is the data stage and `len`
    /// must equal `wLength`; for an IN request pass `len = 0` and poll with
    /// a buffer of at least `wLength` bytes. `SET_ADDRESS` is refused.
    ///
    /// # Safety
    /// `setup` names 8 readable bytes, `data` names `len` readable bytes
    /// (null when `len` is 0), `out_urb` names writable `u64` storage, and
    /// `callback` is 0 or stays mapped until unload.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_control(
        dev: u64, setup: *const u8, data: *const u8, len: usize,
        callback: usize, cookie: u64, out_urb: *mut u64,
    ) -> i32 {
        if setup.is_null() || out_urb.is_null() || len > narf_bus::module_usb::MAX_TRANSFER
            || (len != 0 && data.is_null()) { return -22; }
        let mut packet = [0u8; 8];
        // SAFETY: the module promises eight readable bytes.
        packet.copy_from_slice(unsafe { core::slice::from_raw_parts(setup, 8) });
        let data = if len == 0 { &[] } else {
            // SAFETY: non-null, bounded readable module storage; copied
            // before this call returns.
            unsafe { core::slice::from_raw_parts(data, len) }
        };
        // SAFETY: same callback contract as `narf_usb_configure`.
        let done = unsafe { usb_completion(callback, cookie) };
        let owner = crate::symbols::current_execution_id().0;
        // SAFETY: `out_urb` was checked non-null above.
        unsafe { usb_submitted(narf_bus::module_usb::control(owner, dev, packet, data, done), out_urb) }
    }

    /// Submit one bulk or interrupt transfer on a configured endpoint. For
    /// an IN endpoint pass `data = null` and `len` = receive capacity; for an
    /// OUT endpoint `data`/`len` is the payload, copied before return. An
    /// endpoint carries one transfer at a time (`-EBUSY` otherwise).
    ///
    /// # Safety
    /// For OUT, `data` names `len` readable bytes; `out_urb` names writable
    /// `u64` storage; `callback` is 0 or stays mapped until unload.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_submit(
        dev: u64, endpoint: u8, data: *const u8, len: usize,
        callback: usize, cookie: u64, out_urb: *mut u64,
    ) -> i32 {
        if out_urb.is_null() || len == 0 || len > narf_bus::module_usb::MAX_TRANSFER { return -22; }
        let is_in = endpoint & 0x80 != 0;
        if is_in != data.is_null() { return -22; }
        let data = if is_in { &[] } else {
            // SAFETY: non-null, bounded readable module storage; copied
            // before this call returns.
            unsafe { core::slice::from_raw_parts(data, len) }
        };
        // SAFETY: same callback contract as `narf_usb_configure`.
        let done = unsafe { usb_completion(callback, cookie) };
        let owner = crate::symbols::current_execution_id().0;
        // SAFETY: `out_urb` was checked non-null above.
        unsafe { usb_submitted(narf_bus::module_usb::transfer(owner, dev, endpoint, data, len, done), out_urb) }
    }

    /// Poll one request. `-EAGAIN` while pending. `-ENOBUFS` stores the
    /// required length and retains the result. Otherwise the request is
    /// consumed: IN data is copied to `buf`, the transferred length is stored
    /// through `out_len`, and the terminal status is returned (0, or a
    /// Linux URB errno such as `-EPIPE` for a stall or `-ECANCELED`).
    ///
    /// # Safety
    /// `buf` names `len` writable bytes (null when `len` is 0); `out_len`
    /// names writable, aligned `usize` storage not overlapping `buf`.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_poll(dev: u64, urb: u64, buf: *mut u8, len: usize, out_len: *mut usize) -> i32 {
        if out_len.is_null() || len > narf_bus::module_usb::MAX_TRANSFER
            || (len != 0 && buf.is_null()) { return -22; }
        let out = if len == 0 { &mut [] } else {
            // SAFETY: non-null, bounded writable module storage for this call.
            unsafe { core::slice::from_raw_parts_mut(buf, len) }
        };
        let owner = crate::symbols::current_execution_id().0;
        let (status, n) = narf_bus::module_usb::poll(owner, dev, urb, out);
        // SAFETY: writable aligned output, per the export contract.
        unsafe { out_len.write(n) };
        status
    }

    /// Request cancellation of a pending bulk or interrupt-IN request; keep
    /// polling it for the terminal status. Control, configure and
    /// interrupt-OUT requests run to completion (`-EBUSY`).
    ///
    /// # Safety
    /// `dev`/`urb` are this module's own token and request id.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_cancel(dev: u64, urb: u64) -> i32 {
        narf_bus::module_usb::cancel(crate::symbols::current_execution_id().0, dev, urb)
    }

    /// Wait up to `timeout_ns` (at most 1 s) for a bulk or interrupt request
    /// submitted without a completion callback, polling it inline: the wait
    /// never depends on another task running, so synchronous paths (a block
    /// request callback) can use it. 0 once terminal (collect it with
    /// `narf_usb_poll`), `-ETIMEDOUT`, `-EINVAL` for an unknown request or
    /// one with a callback, `-EOPNOTSUPP` for control/configure requests.
    ///
    /// # Safety
    /// `dev`/`urb` are this module's own token and request id.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_wait(dev: u64, urb: u64, timeout_ns: u64) -> i32 {
        narf_bus::module_usb::wait(crate::symbols::current_execution_id().0, dev, urb, timeout_ns)
    }

    /// Publish a `/dev/ttyUSB<N>` node backed by this device and store its
    /// port number through `out_port`. `family` names the chip for sysfs
    /// (0 ch341, 1 ftdi_sio, 2 pl2303, 3 cp210x). `kick` (0 or an `extern
    /// "C" fn(u64) -> i32`) runs with `cookie` whenever a writer queues bytes.
    ///
    /// # Safety
    /// `out_port` names writable `u32` storage; `kick` is 0 or stays mapped
    /// until unload.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_serial_register(
        dev: u64, family: u32, kick: usize, cookie: u64, out_port: *mut u32,
    ) -> i32 {
        if out_port.is_null() { return -22; }
        // SAFETY: same callback contract as `narf_usb_configure`.
        let kick = unsafe { usb_completion(kick, cookie) };
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_usb::serial_register(owner, dev, family, kick) {
            Ok(port) => {
                // SAFETY: non-null above; the module promises writable storage.
                unsafe { out_port.write(port) };
                0
            }
            Err(e) => e,
        }
    }

    /// Take up to `len` bytes writers queued on this device's serial node,
    /// storing the count through `out_len` (0 when none, or while output is
    /// stopped by `TCXONC`).
    ///
    /// # Safety
    /// `buf` names `len` writable bytes; `out_len` names writable `usize`.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_serial_tx(dev: u64, port: u32, buf: *mut u8, len: usize, out_len: *mut usize) -> i32 {
        if buf.is_null() || out_len.is_null() || len == 0
            || len > narf_bus::module_usb::MAX_TRANSFER { return -22; }
        // SAFETY: non-null, bounded writable module storage for this call.
        let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_usb::serial_tx(owner, dev, port, out) {
            Ok(n) => {
                // SAFETY: writable aligned output, per the export contract.
                unsafe { out_len.write(n) };
                0
            }
            Err(e) => e,
        }
    }

    /// Deliver `len` received bytes to readers of this device's serial node.
    /// Returns the number of bytes accepted (the ring may be full), or a
    /// negative errno.
    ///
    /// # Safety
    /// `data` names `len` readable bytes.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_serial_rx(dev: u64, port: u32, data: *const u8, len: usize) -> i32 {
        if data.is_null() || len == 0 || len > narf_bus::module_usb::MAX_TRANSFER { return -22; }
        // SAFETY: non-null, bounded readable module storage; copied here.
        let data = unsafe { core::slice::from_raw_parts(data, len) };
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::module_usb::serial_rx(owner, dev, port, data) {
            Ok(n) => n as i32,
            Err(e) => e,
        }
    }

    /// Register a module-backed disk `name` (lowercase ASCII, digits, `_`,
    /// `-`; at most 31 bytes) for the device behind `dev`. `geometry` names
    /// four `u64`s: bytes per block (512..=4096, a power of two), capacity
    /// in blocks, the largest request in blocks (at most 1 MiB of data), and
    /// flags (bit 0 volatile write cache, bit 1 read-only). `request` is an
    /// `extern "C" fn(cookie: u64, request: u64, op: u32, lba: u64,
    /// count: u32) -> i32`: op 0 read, 1 write, 2 flush. It runs in the
    /// module's domain, finishes the whole request before returning, and
    /// moves data only with `narf_blk_copy_in`/`narf_blk_copy_out`.
    /// `-EEXIST` if the name is taken.
    ///
    /// # Safety
    /// `name` names `name_len` readable bytes and `geometry` four readable,
    /// aligned `u64`s. `request` stays valid until the module is unloaded.
    requires narf_capabilities::CapKind::BlockDevice;
    fn narf_blk_register(
        dev: u64, name: *const u8, name_len: usize,
        geometry: *const u64, request: usize, cookie: u64,
    ) -> i32 {
        if name.is_null() || name_len == 0 || name_len > crate::module_block::MAX_NAME
            || geometry.is_null() || request == 0 || geometry.align_offset(8) != 0 {
            return -22;
        }
        // SAFETY: non-null, bounded readable module storage; copied here.
        let name = unsafe { core::slice::from_raw_parts(name, name_len) };
        // SAFETY: the module promises four readable, aligned `u64`s.
        let g = unsafe { core::slice::from_raw_parts(geometry, 4) };
        let (Ok(lba_size), Ok(max_blocks), Ok(flags)) =
            (u32::try_from(g[0]), u32::try_from(g[2]), u32::try_from(g[3]))
        else {
            return -22;
        };
        // SAFETY: the address has the documented C signature, and the disk is
        // retired before the module's text is unmapped.
        let request = unsafe {
            core::mem::transmute::<usize, crate::module_block::RequestFn>(request)
        };
        let spec = crate::module_block::DiskSpec {
            lba_size, capacity: g[1], max_blocks, flags, request, cookie,
        };
        let owner = crate::symbols::current_execution_id().0;
        crate::module_block::register(owner, dev, name, spec)
    }

    /// Copy `len` bytes of a running write request, starting `req_off` bytes
    /// into it, to offset `dma_off` of DMA buffer `dma`. Valid only inside
    /// that request's callback.
    ///
    /// # Safety
    /// `dev`/`dma` are this module's handles; nothing is dereferenced in
    /// module memory.
    requires narf_capabilities::CapKind::BlockDevice;
    fn narf_blk_copy_in(
        dev: u64, request: u64, dma: u64, dma_off: u64, req_off: usize, len: usize,
    ) -> i32 {
        let Some(end) = req_off.checked_add(len) else { return -22; };
        let owner = crate::symbols::current_execution_id().0;
        let side = crate::module_block::Endpoint::Dma { handle: dma, offset: dma_off };
        crate::module_block::copy(owner, dev, request, side, req_off..end, false)
    }

    /// Copy `len` bytes from offset `dma_off` of DMA buffer `dma` into a
    /// running read request, starting `req_off` bytes into it. Valid only
    /// inside that request's callback.
    ///
    /// # Safety
    /// `dev`/`dma` are this module's handles; nothing is dereferenced in
    /// module memory.
    requires narf_capabilities::CapKind::BlockDevice;
    fn narf_blk_copy_out(
        dev: u64, request: u64, dma: u64, dma_off: u64, req_off: usize, len: usize,
    ) -> i32 {
        let Some(end) = req_off.checked_add(len) else { return -22; };
        let owner = crate::symbols::current_execution_id().0;
        let side = crate::module_block::Endpoint::Dma { handle: dma, offset: dma_off };
        crate::module_block::copy(owner, dev, request, side, req_off..end, true)
    }

    /// Copy `len` bytes of module memory at `src` into a running read
    /// request, starting `req_off` bytes into it: for drivers without bus
    /// DMA buffers (USB). Valid only inside that request's callback.
    ///
    /// # Safety
    /// `src` names `len` readable bytes of module memory.
    requires narf_capabilities::CapKind::BlockDevice;
    fn narf_blk_fill(dev: u64, request: u64, req_off: usize, src: *const u8, len: usize) -> i32 {
        if src.is_null() { return -22; }
        let Some(end) = req_off.checked_add(len) else { return -22; };
        let owner = crate::symbols::current_execution_id().0;
        let side = crate::module_block::Endpoint::Module(src as usize);
        crate::module_block::copy(owner, dev, request, side, req_off..end, true)
    }

    /// Copy `len` bytes of a running write request, starting `req_off` bytes
    /// into it, to module memory at `dst`. Valid only inside that request's
    /// callback.
    ///
    /// # Safety
    /// `dst` names `len` writable bytes of module memory.
    requires narf_capabilities::CapKind::BlockDevice;
    fn narf_blk_fetch(dev: u64, request: u64, req_off: usize, dst: *mut u8, len: usize) -> i32 {
        if dst.is_null() { return -22; }
        let Some(end) = req_off.checked_add(len) else { return -22; };
        let owner = crate::symbols::current_execution_id().0;
        let side = crate::module_block::Endpoint::Module(dst as usize);
        crate::module_block::copy(owner, dev, request, side, req_off..end, false)
    }

    // ── PCI command register read/clear (mt76.ko) ──────────────────────────

    /// Clear, then set, PCI command bits on the module's device and write the
    /// register read back through `out_cmd` (`clear = set = 0` only reads
    /// it). Only memory decode, bus mastering and INTx disable may change
    /// (`-EINVAL` otherwise). For stop/reset sequences that must prove bus
    /// mastering off (Linux `pci_clear_master`). Returns 0, `-ENODEV` or
    /// `-EIO`.
    ///
    /// # Safety
    /// `out_cmd` must point to writable `u16` storage.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_pci_command(dev: u64, clear: u16, set: u16, out_cmd: *mut u16) -> i32 {
        if out_cmd.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_pci_command(owner, dev, clear, set) {
            Ok(command) => {
                // SAFETY: non-null; the module promises writable storage.
                unsafe { out_cmd.write(command) };
                0
            }
            Err(errno) => errno,
        }
    }

    // ── USB Wi-Fi modules: device heartbeat and regulatory domain ────────
    //
    // Additive exports whose first consumer is rtw88.ko (RTL8821CU /
    // RTL8822BU over the USB KABI). See `modules/DATAPATH_ABI_DESIGN.md`,
    // "USB device poller and the regulatory domain".

    /// Spawn one 1 ms periodic task-context callback for the USB function
    /// behind `dev` (the token a USB probe received): the USB counterpart of
    /// [`narf_spawn_poller`], which serves PCI/MMIO device contexts only. The
    /// first run is immediate. The poller stops when `callback` returns
    /// non-zero, when the USB context goes away (detach, declined probe,
    /// unload), or when a later call for the same device replaces it.
    /// `-ENODEV` without a live USB context of this module for `dev`.
    ///
    /// # Safety
    /// `callback` has the same lifetime/signature contract as
    /// [`narf_irq_set_handler`].
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_usb_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32 {
        if callback == 0 {
            return -22;
        }
        // SAFETY: same callback contract as `narf_irq_set_handler`.
        let callback: narf_bus::ModuleCallbackFn = unsafe { core::mem::transmute(callback) };
        let owner = crate::symbols::current_execution_id().0;
        crate::usb_wifi::spawn_poller(owner, dev, callback, cookie)
    }

    /// Register one copy-mode Wi-Fi station interface (`wlan%d`) for the USB
    /// function behind `dev`: the USB counterpart of
    /// [`narf_netif_register_with_context`], which serves PCI/MMIO device
    /// contexts only. `tx_callback` is an `extern "C" fn(dev_token, frame,
    /// len) -> i32` the stack calls (module gate, task context) with one
    /// borrowed Ethernet frame. The interface is withdrawn when the USB
    /// context goes away (detach, declined probe, unload). Stores the
    /// ifindex through `out_ifindex`. `-ENODEV` without a live USB context
    /// of this module for `dev`; `-EBUSY` if it already has one.
    ///
    /// # Safety
    /// `mac` names six readable bytes; `out_ifindex` names writable `u32`
    /// storage; `tx_callback` stays mapped until unload.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_usb_netif_register_with_context(
        dev: u64,
        mac: *const u8,
        tx_callback: usize,
        out_ifindex: *mut u32,
    ) -> i32 {
        if mac.is_null() || tx_callback == 0 || out_ifindex.is_null() {
            return -22;
        }
        let mut mac_bytes = [0u8; 6];
        // SAFETY: the module promises six readable bytes.
        mac_bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(mac, 6) });
        // SAFETY: the callback address has the documented C signature and the
        // interface is withdrawn before module text is unmapped.
        let tx_callback: narf_bus::ModuleTxCtxFn = unsafe { core::mem::transmute(tx_callback) };
        let owner = crate::symbols::current_execution_id().0;
        match crate::usb_wifi::netif_register(owner, dev, mac_bytes, tx_callback) {
            Ok(ifindex) => {
                // SAFETY: non-null above; caller promises writable storage.
                unsafe { out_ifindex.write(ifindex) };
                0
            }
            Err(errno) => errno,
        }
    }

    /// Deliver one received Ethernet frame (`len` bytes at `frame`, copied
    /// before return) to the stack on the interface
    /// [`narf_usb_netif_register_with_context`] registered for `dev`.
    ///
    /// # Safety
    /// `frame` names `len` readable and writable bytes.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_usb_netif_rx(dev: u64, ifindex: u32, frame: *mut u8, len: usize) -> i32 {
        if frame.is_null() || len == 0 || len > 65_535 {
            return -22;
        }
        // SAFETY: the module promises `len` bytes for the duration of the call.
        let frame = unsafe { core::slice::from_raw_parts_mut(frame, len) };
        let owner = crate::symbols::current_execution_id().0;
        crate::usb_wifi::netif_rx(owner, dev, ifindex, frame)
    }

    /// Copy the kernel's installed regulatory domain (the one built-in
    /// drivers read from `narf_wireless::reg::db`) into `buf` as one NRGD v1
    /// record — `narf_wireless::reg::parse_policy`'s layout, with the world
    /// domain's country "00" allowed; decode it with
    /// `narf_wireless::reg::parse_domain_record` — and store its length through
    /// `out_len`. `-ENOBUFS` (nothing copied, required length stored) when
    /// `len` is too small, so `len = 0` sizes it; `-ENODATA` when no domain
    /// is installed and none can be bootstrapped; `-EOVERFLOW` for a domain
    /// the record cannot carry. Read-only: a module cannot install a domain.
    ///
    /// # Safety
    /// `buf` names `len` writable bytes (null when `len` is 0); `out_len`
    /// names writable, aligned `usize` storage.
    requires narf_capabilities::CapKind::NetIface;
    fn narf_wireless_regdomain(buf: *mut u8, len: usize, out_len: *mut usize) -> i32 {
        if out_len.is_null() || (len != 0 && buf.is_null()) {
            return -22;
        }
        let record = match crate::usb_wifi::regdomain_record() {
            Ok(record) => record,
            Err(errno) => return errno,
        };
        // SAFETY: writable aligned output, per the export contract.
        unsafe { out_len.write(record.len()) };
        if len < record.len() {
            return -105;
        }
        // SAFETY: `buf` names at least `record.len()` writable bytes.
        unsafe { core::ptr::copy_nonoverlapping(record.as_ptr(), buf, record.len()) };
        0
    }

    // ── ath9k.ko: softMAC PCIe state and config reads ────────────────────
    //
    // Additive exports for a softMAC PCIe driver (ath9k is the first
    // consumer; `modules/DATAPATH_ABI_DESIGN.md`, "softMAC PCI state and
    // config reads"). A softMAC chip has no firmware between the
    // driver and the radio: the driver picks SerDes workarounds from the
    // upstream link's ASPM policy and enforces the host regulatory domain
    // itself. (Its bus-master gating uses the shared `narf_pci_command`.)

    /// Fill `out` with the function's 20-byte PCI Express state record
    /// (Device Capabilities/Control/Status, Link Capabilities/Status and the
    /// upstream bridge's Link Control; layout in
    /// `narf_bus::driver_match::module_pcie_state`). `len` must be at least
    /// 20. Returns 0, `-EINVAL`, `-EOPNOTSUPP` (not PCI Express) or
    /// `-ENODEV`.
    ///
    /// # Safety
    /// `out` must name `len` writable bytes for the call.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_pcie_state(dev: u64, out: *mut u8, len: usize) -> i32 {
        if out.is_null() || len < narf_bus::driver_match::MODULE_PCIE_STATE_LEN {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_pcie_state(owner, dev) {
            Ok(record) => {
                // SAFETY: non-null and at least `record.len()` writable bytes.
                unsafe { core::ptr::copy_nonoverlapping(record.as_ptr(), out, record.len()) };
                0
            }
            Err(errno) => errno,
        }
    }

    /// Read one aligned config dword at `offset` (`0x40 ..= 0xffc`: the
    /// device-dependent region and extended space, never the standard
    /// header) of the module's device into `out`. Read only. Returns 0,
    /// `-EINVAL`, `-EIO` (beyond the function's config window) or
    /// `-ENODEV`.
    ///
    /// # Safety
    /// `out` must point to writable `u32` storage.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_pci_config_read32(dev: u64, offset: u16, out: *mut u32) -> i32 {
        if out.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_pci_config_read32(owner, dev, offset) {
            Ok(value) => {
                // SAFETY: non-null; the module promises writable storage.
                unsafe { out.write(value) };
                0
            }
            Err(errno) => errno,
        }
    }
    // ── end ath9k.ko block ───────────────────────────────────────────────

    // ── Device-specific PCI configuration window (brcmfmac.ko) ──────────
    //
    // FullMAC PCIe parts select their BAR0 backplane window and ring their
    // mailbox doorbell through vendor registers in config space. Reads use
    // `narf_pci_config_read32`; decode/bus-master parking around BAR sizing
    // and firmware download uses the shared `narf_pci_command`. See
    // `modules/DATAPATH_ABI_DESIGN.md`, "Device-specific PCI configuration
    // window". Additive: no existing export changes.

    /// Write config dword `offset` of the probed PCI function: the
    /// device-specific region 0x40..0x100, dword-aligned, outside the PM,
    /// MSI, MSI-X and PCI Express capabilities and every capability header
    /// (`-EPERM` for those). Vendor-specific capability bodies are writable.
    ///
    /// # Safety
    /// `dev` must be the live token supplied to the current module callback.
    requires narf_capabilities::CapKind::BusDevice;
    fn narf_pci_config_write32(dev: u64, offset: u16, value: u32) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_pci_config_write32(owner, dev, offset, value) {
            Ok(()) => 0,
            Err(errno) => errno,
        }
    }

    // ── Control-BAR mapping and 8/16-bit MMIO (rtl.ko) ──────────────────
    //
    // Additive. The first consumer is rtlwifi (`rtl.ko`), whose SYS, EFUSE
    // and power-sequence registers are byte- and word-addressed: emulating
    // them with a read-modify-write of the enclosing dword would also write
    // back neighbouring write-1-to-clear and trigger bytes. Same handle,
    // owner and bounds rules as `narf_mmio_read32`/`_write32`; 16-bit
    // offsets must be 2-byte aligned. See `modules/DATAPATH_ABI_DESIGN.md`,
    // "Control BARs and 8/16-bit MMIO".

    /// Map BAR `bar_idx` like `narf_bar_map`, but with Device (uncached,
    /// unmerged) attributes even when the BAR is prefetchable — the mapping
    /// built-in drivers use for control registers. Returns a 1-based BAR
    /// handle shared with `narf_bar_map`'s, or 0 on failure.
    ///
    /// # Safety
    /// `dev` must be the token the module's probe was invoked with.
    fn narf_bar_map_control(dev: u64, bar_idx: u8) -> u64 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::driver_match::module_bar_map_control(owner, dev, bar_idx)
    }

    /// Read the 8-bit device register at `off` in BAR handle `bar` into
    /// `out`. Returns 0, or `-EINVAL` for a bad handle/offset/pointer.
    ///
    /// # Safety
    /// `out` must point to a writable `u8`. `dev`/`bar` identify a mapped BAR.
    fn narf_mmio_read8(dev: u64, bar: u64, off: u64, out: *mut u8) -> i32 {
        if out.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_mmio_read8(owner, dev, bar, off) {
            Some(v) => {
                // SAFETY: `out` is non-null; the module promises it is writable.
                unsafe { out.write(v) };
                0
            }
            None => -22,
        }
    }

    /// Read the 2-byte-aligned 16-bit device register at `off` in BAR handle
    /// `bar` into `out`. Returns 0, or `-EINVAL` for a bad handle, offset,
    /// alignment or pointer.
    ///
    /// # Safety
    /// `out` must point to a writable, aligned `u16`. `dev`/`bar` identify a
    /// mapped BAR.
    fn narf_mmio_read16(dev: u64, bar: u64, off: u64, out: *mut u16) -> i32 {
        if out.is_null() {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_bus::driver_match::module_mmio_read16(owner, dev, bar, off) {
            Some(v) => {
                // SAFETY: `out` is non-null; the module promises it is writable.
                unsafe { out.write(v) };
                0
            }
            None => -22,
        }
    }

    /// Write `val` to the 8-bit device register at `off` in BAR handle `bar`.
    /// Returns 0, or `-EINVAL` for a bad handle/offset.
    ///
    /// # Safety
    /// `dev`/`bar` identify a mapped BAR of the module's device.
    fn narf_mmio_write8(dev: u64, bar: u64, off: u64, val: u8) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::driver_match::module_mmio_write8(owner, dev, bar, off, val)
    }

    /// Write `val` to the 2-byte-aligned 16-bit device register at `off` in
    /// BAR handle `bar`. Returns 0, or `-EINVAL` for a bad handle, offset or
    /// alignment.
    ///
    /// # Safety
    /// `dev`/`bar` identify a mapped BAR of the module's device.
    fn narf_mmio_write16(dev: u64, bar: u64, off: u64, val: u16) -> i32 {
        let owner = crate::symbols::current_execution_id().0;
        narf_bus::driver_match::module_mmio_write16(owner, dev, bar, off, val)
    }

    // ── end rtl.ko block ───────────────────────────────────────────────

    // ── Firmware signer identity (iwlwifi.ko) ───────────────────────────
    //
    // Additive. `narf_firmware_signed` answers whether a blob is signed;
    // iwlwifi's Gen2 power programs also bind the signer key itself, as its
    // built-in `firmware_asset::Asset::signer` does.

    /// Copy the verified signer key of open firmware `handle` (32 bytes) into
    /// `out`. Returns 0, `-ENODATA` when the blob is unsigned, `-EINVAL` for a
    /// null or short output, or `-EBADF`.
    ///
    /// # Safety
    /// `out` must name `len` writable bytes for the call.
    requires narf_capabilities::CapKind::Firmware;
    fn narf_firmware_signer(handle: u64, out: *mut u8, len: usize) -> i32 {
        if out.is_null() || len < 32 {
            return -22;
        }
        let owner = crate::symbols::current_execution_id().0;
        match narf_firmware::module_fetch::signer(owner, handle) {
            Ok(Some(key)) => {
                // SAFETY: non-null and at least 32 writable bytes.
                unsafe { core::ptr::copy_nonoverlapping(key.as_ptr(), out, 32) };
                0
            }
            Ok(None) => -61,
            Err(errno) => errno,
        }
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
    let mut allowed = crate::manifest::Manifest::default();
    allowed.required_caps.push(crate::manifest::RequiredCap {
        kind: narf_capabilities::CapKind::NetIface,
        right: <narf_capabilities::Write as narf_capabilities::Rights>::BITS,
    });
    for name in [
        "narf_netif_register",
        "narf_netif_register_with_context",
        "narf_wireless_open",
        "narf_wireless_open_with_event",
        "narf_wireless_submit",
        "narf_wireless_poll",
        "narf_wireless_cancel",
        "narf_wireless_close",
    ] {
        match crate::symbols::resolve(name, None, &denied) {
            Err(crate::symbols::ResolveError::CapMissing(narf_capabilities::CapKind::NetIface)) => {
            }
            _ => {
                return TestResult::Fail(
                    "netif/wireless export resolved without NetIface cap declaration",
                )
            }
        }
        if crate::symbols::resolve(name, None, &allowed).is_err() {
            return TestResult::Fail(
                "netif/wireless export stayed hidden with NetIface cap declaration",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_netif_exports_require_cap);

/// The softMAC exports (ath9k.ko) and the regulatory record: link-time cap
/// gated like their neighbours, bounded to their fields, and the record
/// (NRGD v1) parses back to the host's active domain, world domain included.
fn smoke_kabi_softmac_exports() -> TestResult {
    use narf_wireless::reg::{db, RegFlags, RegRule, RegulatoryDomain};
    register_all();
    let denied = crate::manifest::Manifest::default();
    for (name, kind) in [
        ("narf_pcie_state", narf_capabilities::CapKind::BusDevice),
        (
            "narf_pci_config_read32",
            narf_capabilities::CapKind::BusDevice,
        ),
        (
            "narf_wireless_regdomain",
            narf_capabilities::CapKind::NetIface,
        ),
    ] {
        match crate::symbols::resolve(name, None, &denied) {
            Err(crate::symbols::ResolveError::CapMissing(missing)) if missing == kind => {}
            _ => return TestResult::Fail("softMAC export resolved without its cap declaration"),
        }
    }
    let mut state = [0u8; 20];
    // SAFETY: live locals; no device context exists for this token.
    let (short, no_state) = unsafe {
        (
            narf_pcie_state(0x5eed, state.as_mut_ptr(), 19),
            narf_pcie_state(0x5eed, state.as_mut_ptr(), state.len()),
        )
    };
    if short != -22 || no_state != -19 {
        return TestResult::Fail("narf_pcie_state accepted an out-of-bounds request");
    }
    let mut word = 0u32;
    // SAFETY: live local; no device context exists for this token.
    let (header, unaligned, beyond, no_cfg) = unsafe {
        (
            narf_pci_config_read32(0x5eed, 0x04, &mut word),
            narf_pci_config_read32(0x5eed, 0x702, &mut word),
            narf_pci_config_read32(0x5eed, 0x1000, &mut word),
            narf_pci_config_read32(0x5eed, 0x70c, &mut word),
        )
    };
    if header != -22 || unaligned != -22 || beyond != -22 || no_cfg != -19 {
        return TestResult::Fail("narf_pci_config_read32 accepted an out-of-bounds read");
    }

    let saved = db::get_domain();
    let domain = RegulatoryDomain {
        country_code: *b"DE",
        rules: alloc::vec![
            RegRule {
                freq_start_mhz: 2400,
                freq_end_mhz: 2483,
                max_bandwidth_mhz: 40,
                max_power_dbm: 20,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5250,
                freq_end_mhz: 5330,
                max_bandwidth_mhz: 80,
                max_power_dbm: 20,
                flags: RegFlags::NO_IR | RegFlags::AUTO_BW,
            },
        ],
    };
    db::set_domain(domain.clone());
    let mut len = 0usize;
    let mut record = [0u8; 64];
    // SAFETY: live locals; a sizing call, then a copy into `record`.
    let (sizing, sized, copied) = unsafe {
        let sizing = narf_wireless_regdomain(core::ptr::null_mut(), 0, &mut len);
        let sized = len;
        (
            sizing,
            sized,
            narf_wireless_regdomain(record.as_mut_ptr(), record.len(), &mut len),
        )
    };
    match saved {
        Some(saved) => db::set_domain(saved),
        None => db::clear_domain(),
    }
    if sizing != -105 || copied != 0 || sized != 12 + 2 * 16 || len != sized {
        return TestResult::Fail("narf_wireless_regdomain sizing is wrong");
    }
    if narf_wireless::reg::parse_domain_record(&record[..len]) != Ok(domain) {
        return TestResult::Fail("narf_wireless_regdomain record differs from the domain");
    }
    // The world domain the database holds before any policy is installed
    // parses as a record, never as a deployment policy.
    let mut world = record;
    world[6..8].copy_from_slice(b"00");
    if narf_wireless::reg::parse_domain_record(&world[..len]).map(|d| d.country_code) != Ok(*b"00")
        || narf_wireless::reg::parse_policy(&world[..len]).is_ok()
    {
        return TestResult::Fail("the world domain's record is not parsed as a record only");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_softmac_exports);

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

/// `narf_register_usb_driver` validates its C arguments itself and forwards a
/// well-formed match to the USB registry's `narf_bus::module_usb` host. The
/// registry side (dedup, `-EBUSY`, unload sweep, match selection) is proven
/// by `drivers/usb/class-registry`; this pins the export's own contract.
fn smoke_kabi_register_usb_driver_validates_and_forwards() -> TestResult {
    const VP: u16 = 1; // MATCH_VENDOR_PRODUCT
    let name = b"narf-kabi-usb-smoke";
    let probe = kabi_smoke_probe_thunk as usize;
    // SAFETY: `name` names its bytes for each call; nothing else is read.
    let call = |n: *const u8, len: usize, flags: u16, vendor: u16, p: usize| unsafe {
        narf_register_usb_driver(n, len, flags, vendor, 0xFACE, 0, 0, 0, p)
    };
    if call(core::ptr::null(), name.len(), VP, 0xFEED, probe) != -22
        || call(name.as_ptr(), 0, VP, 0xFEED, probe) != -22
        || call(name.as_ptr(), name.len(), VP, 0xFEED, 0) != -22
    {
        return TestResult::Fail("narf_register_usb_driver accepted a null name or probe");
    }
    if call(name.as_ptr(), name.len(), 0, 0xFEED, probe) != -22
        || call(name.as_ptr(), name.len(), 0x8000, 0xFEED, probe) != -22
        || call(name.as_ptr(), name.len(), VP, 0, probe) != -22
    {
        return TestResult::Fail("narf_register_usb_driver accepted bad match flags or VID 0");
    }
    let bad_utf8 = [0xFFu8, 0xFE];
    if call(bad_utf8.as_ptr(), bad_utf8.len(), VP, 0xFEED, probe) != -22 {
        return TestResult::Fail("narf_register_usb_driver accepted a non-UTF-8 name");
    }
    let rc = call(name.as_ptr(), name.len(), VP, 0xFEED, probe);
    let owner = crate::symbols::current_init_id().0;
    narf_bus::module_usb::unregister_module_usb_drivers(owner);
    narf_bus::module_sdio::unregister_module_sdio_drivers(owner);
    narf_bus::module_dt::unregister_module_dt_drivers(owner);
    match rc {
        0 => TestResult::Pass,
        -19 => TestResult::Skip("no USB stack registered a module host in this build"),
        _ => TestResult::Fail("narf_register_usb_driver rejected a valid registration"),
    }
}
kernel_test_in!(
    "modules/kabi",
    smoke_kabi_register_usb_driver_validates_and_forwards
);

/// The USB datapath exports reject malformed arguments before reaching the
/// USB stack, and a token no probe context was minted for is `-ENODEV`
/// (never another module's device). `0x55 << 56` is the USB token tag.
fn smoke_kabi_usb_datapath_validates_arguments() -> TestResult {
    const UNKNOWN: u64 = (0x55u64 << 56) | 0xFEFE;
    let mut urb = 0u64;
    let mut n = 0usize;
    let mut buf = [0u8; 64];
    let setup = [0x80u8, 0x06, 0, 1, 0, 0, 18, 0];
    let eps = [0x81u8];
    // SAFETY: every pointer below is either null (to prove rejection) or
    // names live, correctly sized local storage; callbacks are 0.
    let rejected = unsafe {
        narf_usb_poll(UNKNOWN, 1, buf.as_mut_ptr(), buf.len(), core::ptr::null_mut()) == -22
            && narf_usb_poll(UNKNOWN, 1, core::ptr::null_mut(), 8, &mut n) == -22
            && narf_usb_wait(UNKNOWN, 1, 0) == -22
            && narf_usb_wait(UNKNOWN, 1, 2_000_000_000) == -22
            && narf_usb_config_descriptor(UNKNOWN, buf.as_mut_ptr(), 1 << 20, &mut n) == -22
            && narf_usb_control(UNKNOWN, core::ptr::null(), core::ptr::null(), 0, 0, 0, &mut urb) == -22
            && narf_usb_control(UNKNOWN, setup.as_ptr(), core::ptr::null(), 4, 0, 0, &mut urb) == -22
            // IN endpoint with a data pointer, OUT endpoint without one.
            && narf_usb_submit(UNKNOWN, 0x81, buf.as_ptr(), 8, 0, 0, &mut urb) == -22
            && narf_usb_submit(UNKNOWN, 0x02, core::ptr::null(), 8, 0, 0, &mut urb) == -22
            && narf_usb_submit(UNKNOWN, 0x81, core::ptr::null(), 0, 0, 0, &mut urb) == -22
            && narf_usb_configure(UNKNOWN, eps.as_ptr(), 0, 0, 0, &mut urb) == -22
            && narf_usb_configure(UNKNOWN, eps.as_ptr(), 1, 0, 0, core::ptr::null_mut()) == -22
            && narf_usb_serial_register(UNKNOWN, 1, 0, 0, core::ptr::null_mut()) == -22
            && narf_usb_serial_tx(UNKNOWN, 0, buf.as_mut_ptr(), 0, &mut n) == -22
            && narf_usb_serial_rx(UNKNOWN, 0, core::ptr::null(), 4) == -22
    };
    if !rejected {
        return TestResult::Fail("a USB datapath export accepted a malformed argument");
    }
    let mut port = 0u32;
    // SAFETY: as above; all arguments are well formed.
    let unknown = unsafe {
        [
            narf_usb_config_descriptor(UNKNOWN, buf.as_mut_ptr(), buf.len(), &mut n),
            narf_usb_control(
                UNKNOWN,
                setup.as_ptr(),
                core::ptr::null(),
                0,
                0,
                0,
                &mut urb,
            ),
            narf_usb_submit(UNKNOWN, 0x81, core::ptr::null(), 8, 0, 0, &mut urb),
            narf_usb_configure(UNKNOWN, eps.as_ptr(), 1, 0, 0, &mut urb),
            narf_usb_poll(UNKNOWN, 1, buf.as_mut_ptr(), buf.len(), &mut n),
            narf_usb_cancel(UNKNOWN, 1),
            narf_usb_wait(UNKNOWN, 1, 1_000_000),
            narf_usb_serial_register(UNKNOWN, 1, 0, 0, &mut port),
        ]
    };
    if unknown.iter().any(|&rc| rc != -19) {
        return TestResult::Fail("a USB datapath export reached a device with no probe context");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_usb_datapath_validates_arguments);

/// The block exports reject malformed arguments, refuse a device the caller
/// holds no probe context for (`-ENODEV`, so no disk is published), and
/// refuse a copy outside a running request.
fn smoke_kabi_block_datapath_validates_arguments() -> TestResult {
    extern "C" fn request(_: u64, _: u64, _: u32, _: u64, _: u32) -> i32 {
        0
    }
    const UNKNOWN: u64 = 0xB10C_FEFE;
    let name = b"mblkkabi0";
    let geometry = [512u64, 64, 8, 0];
    let cb = request as usize;
    // SAFETY: every pointer is null (to prove rejection) or names live,
    // correctly sized local storage; the callback is a valid C fn.
    let rejected = unsafe {
        narf_blk_register(UNKNOWN, core::ptr::null(), 4, geometry.as_ptr(), cb, 0) == -22
            && narf_blk_register(UNKNOWN, name.as_ptr(), 0, geometry.as_ptr(), cb, 0) == -22
            && narf_blk_register(UNKNOWN, name.as_ptr(), 64, geometry.as_ptr(), cb, 0) == -22
            && narf_blk_register(UNKNOWN, name.as_ptr(), name.len(), core::ptr::null(), cb, 0)
                == -22
            && narf_blk_register(UNKNOWN, name.as_ptr(), name.len(), geometry.as_ptr(), 0, 0) == -22
            && narf_blk_copy_in(UNKNOWN, 1, 1, 0, usize::MAX, 2) == -22
            && narf_blk_copy_out(UNKNOWN, 1, 1, 0, 0, 512) == -22
            && narf_blk_copy_in(UNKNOWN, 1, 1, 0, 0, 512) == -22
            && narf_blk_fill(UNKNOWN, 1, 0, core::ptr::null(), 512) == -22
            && narf_blk_fetch(UNKNOWN, 1, 0, core::ptr::null_mut(), 512) == -22
            && narf_blk_fill(UNKNOWN, 1, usize::MAX, geometry.as_ptr().cast(), 2) == -22
            && narf_blk_fetch(UNKNOWN, 1, 0, [0u8; 8].as_mut_ptr(), 8) == -22
    };
    if !rejected {
        return TestResult::Fail("a block datapath export accepted a malformed argument");
    }
    // SAFETY: as above; all arguments are well formed.
    let unknown =
        unsafe { narf_blk_register(UNKNOWN, name.as_ptr(), name.len(), geometry.as_ptr(), cb, 0) };
    let published = narf_block::block_devices()
        .iter()
        .any(|d| d.name == "mblkkabi0");
    if unknown != -19 || published {
        return TestResult::Fail("narf_blk_register published a disk with no probe context");
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi",
    smoke_kabi_block_datapath_validates_arguments
);

/// The PCI-identity, plain-MSI, ASPM and mapped-DMA exports reject malformed
/// arguments before touching any context, and an unknown device token gets
/// `-ENODEV`, never a grant. The bus bridges' positive paths are covered
/// against a synthetic function in `bus/module-pci`.
fn smoke_kabi_pci_ext_exports_validate_arguments() -> TestResult {
    const UNKNOWN: u64 = (0x56u64 << 56) | 0xFEFE;
    let mut rec = [0u8; 16];
    let (mut count, mut base, mut prev) = (0u16, 0u16, 0u16);
    let (mut addr, mut data) = (0u64, 0u32);
    let (mut cpu, mut bus, mut len) = (0usize, 0u64, 0usize);
    // SAFETY: every pointer is null (to prove rejection) or names live,
    // correctly sized local storage.
    let ok = unsafe {
        narf_pci_identity(UNKNOWN, core::ptr::null_mut(), 16) == -22
            && narf_pci_identity(UNKNOWN, rec.as_mut_ptr(), 15) == -22
            && narf_pci_identity(UNKNOWN, rec.as_mut_ptr(), 16) == -19
            && narf_msi_enable(
                UNKNOWN,
                1,
                core::ptr::null_mut(),
                &mut base,
                &mut addr,
                &mut data,
            ) == -22
            && narf_msi_enable(UNKNOWN, 3, &mut count, &mut base, &mut addr, &mut data) == -22
            && narf_msi_enable(UNKNOWN, 1, &mut count, &mut base, &mut addr, &mut data) == -19
            && narf_msi_set_enabled(UNKNOWN, 2) == -22
            && narf_msi_set_enabled(UNKNOWN, 1) == -19
            && narf_pcie_aspm(UNKNOWN, 0, core::ptr::null_mut()) == -22
            && narf_pcie_aspm(UNKNOWN, 0, &mut prev) == -19
            && narf_dma_alloc_mapped(UNKNOWN, 4096, 32, core::ptr::null_mut(), &mut bus, &mut len)
                == 0
            && narf_dma_alloc_mapped(UNKNOWN, 4096, 32, &mut cpu, &mut bus, &mut len) == 0
    };
    if !ok || cpu != 0 || count != 0 {
        return TestResult::Fail("a PCI extension export accepted a malformed argument or token");
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi",
    smoke_kabi_pci_ext_exports_validate_arguments
);

/// `narf_bar_len` refuses a null output and a token with no device context
/// (the owned-handle cases are `bus/module-pci`'s).
fn smoke_kabi_bar_len_validates_arguments() -> TestResult {
    const UNKNOWN: u64 = (0x56u64 << 56) | 0xFEFF;
    let mut len = 0x5a5a_u64;
    // SAFETY: the pointer is null (to prove rejection) or names a live local.
    let ok = unsafe {
        narf_bar_len(UNKNOWN, 1, core::ptr::null_mut()) == -22
            && narf_bar_len(UNKNOWN, 1, &mut len) == -22
            && narf_bar_len(UNKNOWN, 0, &mut len) == -22
    };
    if !ok || len != 0x5a5a {
        return TestResult::Fail("narf_bar_len accepted a null output or an unknown token");
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_bar_len_validates_arguments);

/// Device-bound additions need their manifest cap to resolve; the
/// device-independent services need none.
fn smoke_kabi_pci_ext_and_runtime_exports_cap_gating() -> TestResult {
    use narf_capabilities::CapKind;
    register_all();
    let denied = crate::manifest::Manifest::default();
    for (name, kind) in [
        ("narf_pci_identity", CapKind::BusDevice),
        ("narf_msi_enable", CapKind::BusDevice),
        ("narf_msi_set_enabled", CapKind::BusDevice),
        ("narf_pcie_aspm", CapKind::BusDevice),
        ("narf_dma_alloc_mapped", CapKind::DmaBuffer),
        ("narf_firmware_signed", CapKind::Firmware),
    ] {
        match crate::symbols::resolve(name, None, &denied) {
            Err(crate::symbols::ResolveError::CapMissing(k)) if k == kind => {}
            _ => return TestResult::Fail("a device export resolved without its cap"),
        }
    }
    for name in [
        "narf_udelay",
        "narf_random_bytes",
        "narf_smbios_read",
        "narf_module_param",
    ] {
        if crate::symbols::resolve(name, None, &denied).is_err() {
            return TestResult::Fail("a runtime service export required a cap");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/kabi",
    smoke_kabi_pci_ext_and_runtime_exports_cap_gating
);

/// The runtime services: bounded delay, entropy that fills (or refuses and
/// zeroes), and an SMBIOS read whose pieces reassemble the table.
fn smoke_kabi_runtime_services_behave() -> TestResult {
    // SAFETY: argument-only calls.
    let delay_ok = unsafe {
        narf_udelay(0) == -22 && narf_udelay(1_000_000_001) == -22 && narf_udelay(10_000) == 0
    };
    if !delay_ok {
        return TestResult::Fail("narf_udelay bounds or short delay misbehaved");
    }

    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    // SAFETY: each buffer names its length in writable bytes; the null and
    // oversized calls are the rejected forms.
    let (rc_a, rc_b, null, big) = unsafe {
        (
            narf_random_bytes(a.as_mut_ptr(), a.len()),
            narf_random_bytes(b.as_mut_ptr(), b.len()),
            narf_random_bytes(core::ptr::null_mut(), 8),
            narf_random_bytes(a.as_mut_ptr(), 4097),
        )
    };
    if null != -22 || big != -22 {
        return TestResult::Fail("narf_random_bytes accepted a null or oversized buffer");
    }
    match (rc_a, rc_b) {
        (0, 0) if a != b && a.iter().any(|&x| x != 0) => {}
        (-11, _) | (_, -11) if a.iter().all(|&x| x == 0) || b.iter().all(|&x| x == 0) => {}
        _ => return TestResult::Fail("narf_random_bytes neither filled distinctly nor refused"),
    }

    let mut total = 0usize;
    // SAFETY: sizing call (null buffer, zero length) with live `total`.
    let rc = unsafe { narf_smbios_read(0, core::ptr::null_mut(), 0, &mut total) };
    match narf_firmware_smbios::boot_table() {
        None if rc == -61 => {}
        Some(table) if rc == 0 && total == table.bytes().len() => {
            let mut whole = alloc::vec![0u8; total];
            let split = total / 2;
            // SAFETY: `whole` names `total` writable bytes; the two reads
            // cover `[0, split)` and `[split, total)`.
            let (r1, r2, past) = unsafe {
                (
                    narf_smbios_read(0, whole.as_mut_ptr(), split, &mut total),
                    narf_smbios_read(
                        split,
                        whole[split..].as_mut_ptr(),
                        total - split,
                        &mut total,
                    ),
                    narf_smbios_read(total + 1, whole.as_mut_ptr(), 0, &mut total),
                )
            };
            if r1 != 0 || r2 != 0 || past != -22 || whole.as_slice() != table.bytes() {
                return TestResult::Fail("narf_smbios_read pieces do not reassemble the table");
            }
        }
        _ => return TestResult::Fail("narf_smbios_read disagrees with the boot SMBIOS table"),
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_runtime_services_behave);

// ── narf_pci_command (mt76.ko) ─────────────────────────────────────────

/// `narf_pci_command` refuses a null output, bits outside decode/mastering/
/// INTx, and a token with no device context, and needs `BusDevice` to link.
fn smoke_kabi_pci_command_validates_arguments() -> TestResult {
    use narf_capabilities::CapKind;
    const UNKNOWN: u64 = (0x56u64 << 56) | 0xFF00;
    let mut command = 0x5a5a_u16;
    // SAFETY: the pointer is null (to prove rejection) or names a live local.
    let ok = unsafe {
        narf_pci_command(UNKNOWN, 0, 0, core::ptr::null_mut()) == -22
            && narf_pci_command(UNKNOWN, 0x1, 0, &mut command) == -22
            && narf_pci_command(UNKNOWN, 0, 0x100, &mut command) == -22
            && narf_pci_command(UNKNOWN, 0x4, 0x2, &mut command) == -19
            && narf_pci_command(UNKNOWN, 0, 0, &mut command) == -19
    };
    if !ok || command != 0x5a5a {
        return TestResult::Fail("narf_pci_command accepted a malformed argument or token");
    }
    register_all();
    let denied = crate::manifest::Manifest::default();
    match crate::symbols::resolve("narf_pci_command", None, &denied) {
        Err(crate::symbols::ResolveError::CapMissing(CapKind::BusDevice)) => TestResult::Pass,
        _ => TestResult::Fail("narf_pci_command resolved without BusDevice"),
    }
}
kernel_test_in!("modules/kabi", smoke_kabi_pci_command_validates_arguments);

// ── Device-specific PCI configuration window (brcmfmac.ko) ─────────────

/// The config-window write and the Command export refuse a null output, an
/// out-of-window or unaligned offset, a Command bit outside
/// decode/master/INTx-disable and a token with no device context, and
/// resolve only with the BusDevice cap.
/// The owned-context write policy is `bus`'s
/// `smoke_module_pci_cfg_window_validates`.
fn smoke_kabi_pci_cfg_window_exports_validate() -> TestResult {
    use narf_capabilities::CapKind;
    const UNKNOWN: u64 = (0x58u64 << 56) | 0xFEFF;
    let mut command = 0x5a5au16;
    // SAFETY: each pointer is null (to prove rejection) or names a live local.
    let ok = unsafe {
        narf_pci_config_write32(UNKNOWN, 0x10, 0) == -22
            && narf_pci_config_write32(UNKNOWN, 0x100, 0) == -22
            && narf_pci_config_write32(UNKNOWN, 0x81, 0) == -22
            && narf_pci_config_write32(UNKNOWN, 0x80, 0) == -19
            && narf_pci_command(UNKNOWN, 0, 0, core::ptr::null_mut()) == -22
            && narf_pci_command(UNKNOWN, 0x1, 0, &mut command) == -22
            && narf_pci_command(UNKNOWN, 0, 0x4, &mut command) == -19
    };
    if !ok || command != 0x5a5a {
        return TestResult::Fail("a PCI config-window export accepted a malformed argument");
    }
    register_all();
    let denied = crate::manifest::Manifest::default();
    for name in ["narf_pci_config_write32", "narf_pci_command"] {
        match crate::symbols::resolve(name, None, &denied) {
            Err(crate::symbols::ResolveError::CapMissing(CapKind::BusDevice)) => {}
            _ => return TestResult::Fail("a PCI config-window export resolved without BusDevice"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("modules/kabi", smoke_kabi_pci_cfg_window_exports_validate);

// ── narf_firmware_signer (iwlwifi.ko) ──────────────────────────────────

/// `narf_firmware_signer` refuses a null or short output before any lookup,
/// answers `-EBADF` for a handle the caller does not hold, and needs the
/// `Firmware` cap to link.
fn smoke_kabi_firmware_signer_validates_arguments() -> TestResult {
    use narf_capabilities::CapKind;
    let mut key = [0x5au8; 32];
    // SAFETY: the pointer is null (to prove rejection) or names 32 bytes.
    let ok = unsafe {
        narf_firmware_signer(1, core::ptr::null_mut(), 32) == -22
            && narf_firmware_signer(1, key.as_mut_ptr(), 31) == -22
            && narf_firmware_signer(u64::MAX, key.as_mut_ptr(), 32) == -9
    };
    if !ok || key != [0x5a; 32] {
        return TestResult::Fail("narf_firmware_signer accepted a malformed output or handle");
    }
    register_all();
    let denied = crate::manifest::Manifest::default();
    match crate::symbols::resolve("narf_firmware_signer", None, &denied) {
        Err(crate::symbols::ResolveError::CapMissing(CapKind::Firmware)) => TestResult::Pass,
        _ => TestResult::Fail("narf_firmware_signer resolved without the Firmware cap"),
    }
}
kernel_test_in!(
    "modules/kabi",
    smoke_kabi_firmware_signer_validates_arguments
);
