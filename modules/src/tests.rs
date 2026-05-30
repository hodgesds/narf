//! No-op host-side test module so `cfg(test)` doesn't fail. All real
//! tests live in `tests_smoke.rs` and are registered through
//! `kernel_test_in!` to land in the `narf.tests` ELF section.
