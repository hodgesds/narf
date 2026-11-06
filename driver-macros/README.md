# driver-macros — Dual-build driver macros

`narf-driver-macros` (`narf_driver_macros`) is the declarative-macro crate
for NARF drivers. `narf_driver!` lets a driver declare its identity and
registration once and compile two ways from one source, selected by cargo
feature: as a built-in (`builtin`, the default), where the crate is an rlib
dependency of a subsystem facade and the generated `register()` is called
from a `Stage::Subsys` initcall; or as a loadable `.ko` (`module`), where
the macro emits the `narf_module_init` entry point, the `.modinfo` key=value
lines the loader parses, and the module's own `#[panic_handler]`.
`compile_error!` guards require exactly one of the two features, so a
misconfigured feature set fails at build time. A hidden `__modinfo_line!`
helper (backed by the `modinfo_bytes` const fn) materialises each `.modinfo`
line as a NUL-terminated byte array in the `.modinfo` section.

The crate is intentionally dependency-free: a module build's only undefined
symbols must be the kernel's C-ABI exports, and a declarative macro emits no
object code of its own, so a module driver can depend on this crate without
dragging a kernel crate into its image. (A proc-macro crate would instead
pull syn/quote and compile host-side — the wrong tool for a pure
token-pasting expansion used across the driver tree.)

Consumers are the dual-build drivers — the e1000 NIC was the first adopter —
including the net drivers (`e1000`, `igc`, `ixgbe`, `mlx5`, …), `nvme`, the
storage drivers (`ahci`, `megaraid`, …), `graphics`, `thunderbolt`, and
wireless `mt76`.
