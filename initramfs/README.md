# initramfs — Initial RAM Filesystem Staging & Handoff

`narf-initramfs` owns the kernel's handling of the initial RAM
filesystem: the handoff of the archive from the bootloader, its one-
time staging for the rest of the kernel, and its appearance as a
read-only filesystem early in boot. The initramfs is the only in-
memory filesystem the kernel has until userspace mounts a real root
over a transport such as virtiofs or 9p, so a handful of cross-
cutting consumers — the firmware blob registry, the loader for the
initial userspace binary, and others — all need to read it.

The archive itself is a CPIO newc image that the bootloader places at
a reserved, page-aligned physical region. The handoff is multi-
architecture: multiboot2 and PVH on x86_64 carry it as a module
tagged with the canonical name `initramfs`, while U-Boot/FDT on
aarch64 carries it through the device tree's `chosen` node. The boot
layer turns whichever form it finds into a memory region, and this
crate consumes that region. A no-initramfs path is fully supported
for raw-kernel and smoke-test boots, in which case staging simply
reports the archive absent.

The central design is "stage once, borrow forever." A single early-
stage initcall reads the boot-supplied region, parses the CPIO
archive into an enumerable value whose file entries borrow directly
from the physical bytes (the only allocation being the entry vector
itself), and installs it into a process-global slot. Installation is
idempotent — first install wins — and there is no unstaging, because
the initramfs is a boot artifact that lives until kernel shutdown.
Thereafter every consumer borrows the same parsed archive rather than
re-reading the raw image. One subtlety the crate handles explicitly:
the first staging necessarily happens before the MMU is brought up
and therefore mints its byte slice from identity addresses that stop
resolving once the low identity map is dropped, so the boot path re-
parses against the direct map and swaps the instance in, leaking the
superseded one. The parsed archive is also exposed through the normal
VFS: a helper mounts it read-only at a well-known boot mount point
through the standard filesystem registry.

The CPIO parser and the parsed-archive type physically still live in
the filesystem crate for orphan-rule reasons documented in the spec;
this crate re-exports them so that consumers can import the whole
surface — parser, archive, staging, and errors — from one place and
remain unaffected if the parser later moves here. Parsing is
defensive, rejecting truncated, mis-magicked, or overflowing archives
with typed errors rather than panicking.

The crate also carries a boot-time secret path: when the kernel
command line requests a LUKS keyfile by path (optionally scoped to a
specific container UUID), the early initcall installs a passphrase
provider backed by that exact regular-file entry in the staged,
measured archive. The keyfile is size-capped, copied into zeroizing
storage for each unlock attempt, and treated as raw bytes; the
source bytes remain in the permanently staged archive and are a boot-
lifetime secret.

Compression (handled by the bootloader), initramfs writes, pivot-
root, and runtime hot-replace are all out of scope. The crate is
`no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
