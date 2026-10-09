//! Declarative macros for dual-build NARF drivers.
//!
//! A driver written against [`narf_driver!`] compiles two ways from one
//! source, selected by cargo feature:
//!
//!   * **built-in** (`feature = "builtin"`, the default): the crate is an
//!     rlib dependency of a subsystem facade. The facade calls the generated
//!     [`register`](crate#the-generated-register-fn) from a `Stage::Subsys`
//!     initcall. No module glue is compiled, so nothing collides with the
//!     kernel's single `#[panic_handler]`.
//!   * **module** (`feature = "module"`): the crate builds to a relocatable
//!     `.ko` (via `cargo xtask build-module`). The macro emits the
//!     `narf_module_init` entry point the loader calls, the `.modinfo`
//!     key=value lines it parses, and the module's own `#[panic_handler]` —
//!     exactly the shape of `modules/test-module/`.
//!
//! The two builds are made mutually exclusive by `compile_error!` guards the
//! macro expands into the driver crate, so a misconfigured feature set fails
//! at build time rather than linking a module entry point into the kernel.
//!
//! This crate deliberately depends on nothing: see the crate's `Cargo.toml`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

/// Copy the first `N` bytes of `s` into a fixed-size array.
///
/// Used by [`__modinfo_line!`] to materialise a `key=value\0` string as the
/// bytes of a `.modinfo` static, rather than a pointer to them. `N` is always
/// `s.len()` at the call site, so the whole string (including its trailing
/// NUL) is copied.
#[doc(hidden)]
pub const fn modinfo_bytes<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = b[i];
        i += 1;
    }
    out
}

/// Emit one `.modinfo` line as a NUL-terminated byte array placed in the
/// `.modinfo` section.
///
/// The loader (`narf_modules::manifest::Manifest::parse`) reads `.modinfo` as
/// NUL-separated `key=value` strings. Each invocation lands its own `#[used]`
/// static in a fresh `const _` scope, so repeated use never collides.
#[doc(hidden)]
#[macro_export]
macro_rules! __modinfo_line {
    ($key:literal = $val:literal) => {
        const _: () = {
            const S: &str = concat!($key, "=", $val, "\0");
            #[used]
            #[link_section = ".modinfo"]
            static LINE: [u8; S.len()] = $crate::modinfo_bytes::<{ S.len() }>(S);
        };
    };
}

/// Declare a NARF driver once; compile it as a built-in or a loadable module.
///
/// ```ignore
/// narf_driver! {
///     name: "e1000",
///     module: {
///         version: "0.1.0",
///         license: "GPL-2.0-or-later",
///         author: "narf",
///         description: "Intel 8254x/8257x NIC",
///         target_domain: "net",
///     },
///     register: crate::register_pci_driver,
/// }
/// ```
///
/// Expands to:
///   * `pub fn register()` — calls the driver's own registration function.
///     Present in **both** builds; the built-in initcall and the module's
///     `narf_module_init` both funnel through it, so there is exactly one
///     registration code path.
///   * `compile_error!` guards requiring exactly one of `builtin`/`module`.
///   * Under `feature = "module"` only: the `.modinfo` lines, a
///     `#[no_mangle] extern "C" fn narf_module_init() -> i32`, and a
///     `#[panic_handler]`.
///
/// The `kernel_abi` modinfo line is emitted as a `0x00000000` placeholder;
/// `cargo xtask build-module` stamps it with the running kernel's ABI hash.
#[macro_export]
macro_rules! narf_driver {
    (
        name: $name:literal,
        module: {
            version: $version:literal,
            license: $license:literal,
            author: $author:literal,
            description: $description:literal,
            target_domain: $domain:literal $(,)?
        },
        register: $register:path $(,)?
    ) => {
        #[cfg(all(feature = "builtin", feature = "module"))]
        compile_error!("a NARF driver builds either `builtin` or `module`, not both");
        #[cfg(not(any(feature = "builtin", feature = "module")))]
        compile_error!("select exactly one of the `builtin` or `module` features");

        /// Register this driver's PCI match(es).
        ///
        /// Called from the subsystem facade's `Stage::Subsys` initcall when
        /// built-in, and from `narf_module_init` when loaded as a `.ko`.
        pub fn register() {
            $register();
        }

        #[cfg(feature = "module")]
        mod __narf_module_glue {
            $crate::__modinfo_line!("name" = $name);
            $crate::__modinfo_line!("version" = $version);
            $crate::__modinfo_line!("license" = $license);
            $crate::__modinfo_line!("author" = $author);
            $crate::__modinfo_line!("description" = $description);
            $crate::__modinfo_line!("target_domain" = $domain);
            // Overwritten in place by `xtask build-module` with the running
            // kernel's `/sys/kernel/abi_hash`; a mismatch is rejected at load.
            $crate::__modinfo_line!("kernel_abi" = "0x00000000");

            /// Module entry point. The loader calls this once relocations are
            /// applied and the image is sealed. A `0` return promotes the
            /// module to Live; a negative errno is surfaced through
            /// `sys_init_module`.
            #[unsafe(no_mangle)]
            pub extern "C" fn narf_module_init() -> i32 {
                super::register();
                0
            }

            // A `no_std` staticlib for `*-unknown-none` carries its own panic
            // handler. The kernel never invokes it; it would only fire if the
            // module itself panicked. Quiescent spin, matching test-module.
            #[cfg(not(test))]
            #[panic_handler]
            fn panic(_info: &core::panic::PanicInfo) -> ! {
                loop {
                    core::hint::spin_loop();
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    // Exercise the `.modinfo` materialisation path on the host. The full
    // `narf_driver!` expansion (with its `builtin`/`module` feature guards and
    // module entry point) is exercised by the first real adopter, the e1000
    // driver crate; here we only prove the byte-array helper and the modinfo
    // line macro compile and produce the expected bytes.

    #[test]
    fn modinfo_bytes_copies_whole_string_including_nul() {
        const S: &str = "name=e1000\0";
        let bytes = super::modinfo_bytes::<{ S.len() }>(S);
        assert_eq!(&bytes, b"name=e1000\0");
        assert_eq!(*bytes.last().unwrap(), 0);
    }

    #[test]
    fn modinfo_line_expands_at_module_scope() {
        // A fresh `const _` scope per line — two lines must not collide.
        __modinfo_line!("version" = "0.1.0");
        __modinfo_line!("license" = "GPL-2.0-or-later");
    }
}
