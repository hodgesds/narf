# Efivarfs Linux compatibility audit

Audit baseline: NARF `ba89584b16c17500b84608dda90734a4de64b5df` and the
Linux tree installed at `/usr/src/linux` on 2026-08-01.

## References and call-chain audit

The primary behavioral reference is Linux `fs/efivarfs/{super,inode,file,vars}.c`.
Runtime dispatch and error behavior were checked against
`drivers/firmware/efi/{runtime-wrappers,vars,efi}.c` and
`include/linux/efi.h`. The UEFI 2.10 §8.2 variable-service contract remains
the wire-format authority.

Semcode MCP was run against branch `efivarfs-compat` at the baseline commit.
`find_callchain(get_variable)` found only the EFI runtime unit smokes and
`read_secure_boot_state`; no boot or filesystem caller reached it.
`find_callchain(empty)` found `userspace::mount_api::build_fs_with_options`,
confirming that the old efivarfs mount ended in a generic empty `MemFs`.
Repository search then confirmed that no boot path calls
`narf_efi::runtime::install`.

## Compatibility matrix

| Linux behavior | NARF status |
|---|---|
| Filename is `VariableName-GUID` | Implemented; canonical lower-case GUID output |
| Variable-name case sensitive, GUID case insensitive | Implemented |
| UTF-8 projection of EFI UCS-2 names | Implemented; invalid UCS-2 becomes U+FFFD |
| Hide Linux random-seed configuration-table GUID | Implemented |
| Enumerate with `GetNextVariableName` | Implemented with 64 KiB name, 4096-entry, and duplicate-loop bounds |
| Read format: native four-byte attributes then data | Implemented (both NARF architectures are little-endian) |
| Whole-value write, offset ignored | Implemented |
| Attribute-mask validation | Implemented through `EFI_VARIABLE_APPEND_WRITE` |
| Append and authenticated writes | Passed unchanged to firmware; post-write size is re-read |
| Delete through unlink / zero-attribute empty SetVariable | Implemented |
| Empty newly-created, uncommitted variable | Implemented as a zero-length inode |
| Default immutable for variables outside Linux's safe whitelist | Implemented for write and unlink |
| `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS` immutable bit | Implemented |
| Linux validation of BootOrder, BootNext, Timeout, Boot####/Driver####, console paths, language | Implemented |
| Root/file mode and ownership | 0755 root, 0644 files, `uid=` and `gid=` |
| Stable inode identity | Implemented from the case-sensitive name and binary GUID |
| `statfs` from `QueryVariableInfo` | Implemented with byte-sized blocks; unsupported firmware reports zero capacity |
| Firmware status to errno class | Implemented through `FsError` (`ENOENT`, `ENOSPC`, `EROFS`, `EACCES`, `EIO`, `EOPNOTSUPP`) |
| Classic mount and fsopen/fsconfig | Both select the real backend; unavailable runtime returns `EOPNOTSUPP` |
| Serialize firmware variable operations | Implemented with an await-safe mutex |
| No fake persistence | Implemented; mount never falls back to `MemFs` |

## Runtime-service availability

The runtime backend is intentionally not available on current production
boots. `RawBootInfo` carries only a protocol magic and payload, and validated
`BootInfo` has no EFI system-table pointer or runtime memory descriptors. The
aarch64 removable-media loader calls `ExitBootServices` and discards its final
memory map; x86_64 boots through Limine/multiboot/PVH without an EFI runtime
handoff. Consequently, `narf_efi::runtime::install` has no production caller
and `EfivarFs::from_options` truthfully returns `Unsupported`.

Making real firmware calls reachable requires a separate TCB/interface change:

1. Extend the boot ABI with the runtime-services pointer and the final EFI
   memory descriptors, while preserving the aarch64 Linux `x0 = DTB` entry.
2. Reserve runtime code/data pages from allocation and establish the firmware's
   required virtual mappings (including the one-shot SetVirtualAddressMap
   transition where applicable).
3. Add architecture wrappers that satisfy firmware execution constraints and
   restore NARF address-space/domain state around every call.
4. Resolve the security-model concern that post-PKS firmware executes at Ring
   0 without respecting NARF's supervisor protection keys.

Those steps touch `boot/`, the `memory/` domain manager, and likely `frame/`;
they are TCB changes requiring a machine-checkable safety argument, signed
commit, security review, and two maintainers. This filesystem change does not
weaken that boundary or pretend the mappings exist.

## Remaining filesystem gaps

- NARF's `FileOps` has no close/release callback. A created but never committed
  zero-length inode therefore remains visible until unlink or unmount, whereas
  Linux removes it after the final close.
- The immutable-flag ioctl is enforced by the file capability and ownership
  checks available today; NARF has no separate Linux `CAP_LINUX_IMMUTABLE`
  credential bit.
- Linux's x86 `efi_no_storage_paranoia` reserved-space quirk is not projected;
  `f_bavail` equals firmware-reported remaining bytes rather than inventing an
  architecture-specific reservation.
- Firmware-side notifications and freeze/thaw rescan are not present. Reads
  always query firmware, but an out-of-band variable addition is not added to
  the cached directory until a remount.
- Live hardware conformance is blocked until the reviewed runtime-mapping work
  above lands. Fake-runtime functional tests cover the wire and filesystem ABI
  without claiming firmware persistence.
