# verification/kernel-test — In-Kernel Test Framework

`narf-kernel-test` is the zero-dependency foundation of NARF's in-kernel
test system. It defines the shape of a test case, the macros that register
one, the ELF-section mechanism that collects them, and the result and
summary types the runner reports. It is deliberately tiny and
dependency-free so that any driver or library crate can register its own
smoke tests against it without creating a dependency cycle through the
higher-level harness.

## How it works

A test is a pure `fn() -> TestResult` carrying a name and a *subsystem*
path — a string like `drivers/net/r8169` or `audio/hda` identifying which
driver, module, library, or feature owns it. Registration macros emit each
test into a dedicated `narf.tests` ELF section; the linker synthesises the
start and end symbols, and a collector walks the section to yield every
registered test at boot. Because tests self-register through the section,
no central list has to be maintained and no crate has to be imported just
to be tested. A result is pass, fail, or skip with a static reason string,
and the runner groups its output by subsystem so a failure in one area
doesn't drown out the others.

## Relationships

This crate underlies the `kernel-test` feature across the workspace: a
driver or library crate turns on that feature, depends on
`narf-kernel-test`, and registers subsystem-aware smokes without pulling
in the full harness. The higher-level `narf-verification` crate re-exports
these types and adds the runner that executes the collected tests and
prints results to the console. `cargo xtask test` is what boots the kernel
with the test feature enabled and drives the suite, optionally narrowed to
a single subsystem. The subsystem strings registered here are the same
ones `xtask affected` maps changed crates onto when selecting which
subsystems a diff can affect.
