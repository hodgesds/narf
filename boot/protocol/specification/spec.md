# boot protocol — Specification

## 1. Purpose & scope

Owns safe parsing of the x86_64 kernel ELF's load plan, bounded memory-map
normalization, and construction of standard Multiboot2 information bytes.
Does not allocate physical memory, dereference addresses, or change CPU state.

## 2. Assumptions

Inputs are untrusted bytes. Physical placement and the continued validity of
backing storage are the loader's responsibility. The kernel's existing
Multiboot2 entry requires addresses and its physical entry below 4 GiB.

## 3. Public interface

`BootBundle::parse` validates the version-1 `.narf` PE section. Its 256-byte
header contains the 16-byte `NARF_EFI_BUNDLE\0` magic, u32 version/header size,
u64 total size, three u64 offset/length pairs (kernel, initramfs, UTF-8 command
line), three 32-byte SHA-256 digests, and 80 reserved zero bytes. Parts are
contiguous, eight-byte aligned, and bounded by the total size; the parser
allows trailing PE padding. The archive starts with `070701`, the kernel is
nonempty, and the command line has no NUL and fits `CMDLINE_CAP`. This parser
validates structure; callers must verify digests and kernel format. The loader
verifies all three SHA-256 digests before loading the ELF. Authenticity comes
from the outer PE signature and firmware trust policy.

`ElfImage::parse(&[u8])` validates little-endian x86_64 ELF64 `ET_EXEC`,
bounded program headers, file/memory sizes, address arithmetic, alignment,
nonoverlapping physical segments, and a file-backed executable physical
entry. `segments()` and `segment_bytes()` expose the validated load plan.
`load_start..load_end` includes BSS and page rounding. The load span is capped
at 1 GiB and must remain in `[1 MiB, 4 GiB)`.

`normalize_memory_map(input, output)` sorts and checks regions, merging only
adjacent regions of the same kind. It rejects empty/overlapping/wrapping
regions, insufficient usable RAM, and output capacity overflow.

`Multiboot2Builder` writes little-endian headers, eight-byte tag alignment,
zero padding, and the final terminator into caller-owned bytes. Typed methods
encode command line (type 1), initramfs module (3), normalized memory map (6),
and the complete EFI descriptor map (17). `tag` accepts other protocol tags.
Command lines must fit the kernel's 2048-byte capacity, including NUL. Module
addresses must be page-aligned and representable in the protocol's u32 fields.
EFI descriptor extension bytes are retained with their advertised stride.

## 4. Invariants

No unsafe code or heap allocation. Parsing never authorizes memory access.
Capacity errors never silently truncate input. The loader keeps the kernel,
archive, bridge, information block, and live EFI image reserved. Multiboot2
backing storage is eight-byte aligned and remains accessible after paging
changes. No memory is reclaimed while a kernel borrower can still reference it.

## 5. Architecture notes

x86_64: the native EFI loader returns to 32-bit protected mode and passes the
standard Multiboot2 EAX magic and EBX information pointer to the existing
kernel entry. aarch64 retains its FDT/Linux-compatible ABI and existing loader;
the ELF validator in this crate deliberately rejects aarch64 images.

## 6. Dependencies

Only Rust `core`. Used by `build/xtask` and `build/uefi-loader`. Host tests use
`std` solely for fixture construction.

## 7. Stage assignment

Stage 5: native x86_64 source builds and default distribution packages.
Existing Limine media commands and explicit legacy packages remain available.

## 8. Open questions

Native 64-bit handoff, relocatable EFI placement, early-userspace boot policy,
and archive reclamation are follow-ups. EFI runtime descriptors are retained
in tag 17; activating kernel runtime services is a separate contract.
