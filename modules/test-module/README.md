# modules/test-module — Reference Loadable Kernel Module

`narf-test-module` is a minimal, human-readable NARF kernel module. It
exists for two reasons: it is the canonical reference for the authoring
shape every out-of-tree NARF module follows, and it is the real input the
module loader's end-to-end smokes exercise. It is intentionally tiny — the
whole point is that a module is small and links *against* the running
kernel rather than bundling kernel crates of its own.

## What it demonstrates

The module compiles to a relocatable object — NARF's equivalent of a
`.ko`, produced by `cargo xtask build-module`. It shows every element of
the authoring shape: the `.modinfo` key/value lines emitted into a
dedicated ELF section (the way Linux's `MODULE_INFO` macros do), the
lifecycle C-ABI entry points the loader invokes after relocations are
applied and on teardown, and a plain exported symbol returning a known
constant for the loader's symbol-resolution smoke. It records init and
exit firing in atomics the kernel side can observe.

Most importantly, it calls a kernel function (`narf_printk`) that it only
*declares* — the symbol stays undefined in the built object, so the loader
has to resolve it through the kernel symbol table (KSYMTAB) and patch the
call site. That is what makes this an exercise of the loading *mechanism*
rather than just its shape: it produces a genuine PLT-class relocation on
x86_64 and, on aarch64, a call relocation that needs a PLT veneer because
kernel text sits further away than the relocation can reach directly.

## Relationships

A module depends on nothing: it declares what it calls from the kernel in
an `extern "C"` block and relies on the loader to bind those symbols at
load time — depending on the loader crate would wastefully compile a
second copy of the kernel's memory, filesystem, console, and time code
into the module. The kernel's own in-tree smokes synthesize an equivalent
ELF in-line so they don't require the cross-compiler to be set up; this
crate is the readable reference those smokes track, and the one
out-of-tree authors copy from.
