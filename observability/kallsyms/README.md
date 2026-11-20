# narf-kallsyms

The compact kernel symbol table behind `/proc/kallsyms`: the byte format,
an allocation-free `no_std` decoder the kernel reads the image's `.kallsyms`
section with (`narf_observability::kallsyms`), and — behind the `alloc`
feature — the encoder `build/xtask` runs after every kernel link. It follows
Linux's `scripts/kallsyms.c` (offsets from `_text`, best-pair token table,
markers) and adds name deduplication and front coding for Rust's long,
repetitive symbol paths. The crate has no kernel dependencies, performs no
unsafe operations, and never panics on a malformed table. See
[specification/spec.md](specification/spec.md).
