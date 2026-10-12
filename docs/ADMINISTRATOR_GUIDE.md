# Administrator guide

NARF is still a development operating system. QEMU on x86_64 and aarch64 is
the repeatable test environment. The x86_64 Linux-compatible userspace is much
further along than aarch64, while physical AMD laptop bring-up is active Stage
5 work rather than a generally supported deployment. Check
[STATUS.md](../STATUS.md) before treating any device or workload as supported.

## Build boot media

Builds are optimized by default; use `--debug` only when its diagnostics are
needed.

```sh
cargo xtask image --arch=x86_64
cargo xtask image --arch=aarch64
cargo xtask iso-boot --arch=x86_64
cargo xtask iso-boot --arch=aarch64
```

`image` creates the bootable image. `iso-boot` builds removable-media output
and boots it under OVMF/AAVMF for a UEFI check. To write the generated x86_64
ISO to a USB device, resolve the exact block device first, then run:

```sh
cargo xtask disk-write --device /dev/sdX
```

That command wipes the selected device. A successful QEMU ISO boot or USB
write does not prove that NARF supports the target machine. The current
physical-hardware target is the AMD Renoir/HawkPoint laptop set in
[STATUS.md](../STATUS.md); Secure Boot and a general installer/upgrade service
are not finished administration features.

## Choose a boot profile

Commands that accept build arguments support
`--hw-profile full|minimal|virtio-only|legacy-only`. `full` is the default;
`minimal` is useful for serial-only fault isolation. QEMU graphical runs can
select `--gpu-backend virtio-2d` or `virgl` (the latter also needs a
GL-capable display, such as `--display gtk,gl=on`). Cargo features can be
passed as a comma-separated `--features` list. Do not enable development-only
features such as `firmware-allow-unsigned` or `module-allow-unsigned` on a
production image.

## Assign a host PCIe device to QEMU

On x86_64, `--passthrough-device BDF` assigns a Linux host PCI function through
VFIO. Repeat it for every function that belongs to the device, such as a GPU
and its HD-audio function:

```sh
cargo xtask passthrough -d 03:00.0 -d 03:00.1
cargo xtask run --arch=x86_64 \
  --passthrough-device 03:00.0 \
  --passthrough-device 03:00.1
```

The first command is a read-only readiness check. The second repeats that
preflight, injects QEMU `vfio-pci` devices, and boots NARF. The Linux host must
have KVM and an enabled IOMMU, and every assigned endpoint must already be
bound to `vfio-pci`. xtask checks IOMMU-group completeness and whether the
device BARs fit NARF's mapped physical windows, but never rebinds host
hardware. Prefer the distribution's early-boot VFIO configuration; detaching
the GPU driving an active desktop can terminate the session and may leave the
card unable to reset until reboot. See
[Running on Linux](RUNNING_ON_LINUX.md#311-pass-through-a-physical-pcie-device)
for the host/guest boundary and troubleshooting details.

## Userspace, storage, and networking

On x86_64, `boot-init` starts the in-tree init/getty/shell path and can run
unmodified musl and glibc binaries through the Linux-compatible syscall layer.
The detailed root-filesystem workflow is in
[Running on Linux](RUNNING_ON_LINUX.md#5-running-real-linux-software-the-rootfs-image-model).
Persistent and distribution root filesystems are prepared as host-side disk
images; NARF does not yet provide a mature installer, package manager, or
fleet-management plane.

For a live network check, use:

```sh
cargo xtask net-smoke --arch=x86_64
cargo xtask e1000-module-net-smoke --arch=x86_64
```

Both network commands verify host-to-guest TCP, host-to-guest UDP, and a guest
DNS query through QEMU SLIRP. The second command builds and ABI-stamps
`e1000.ko`, loads it into `driver2` before PCI probing, suppresses the built-in
e1000 claimant for that boot, and requires the module-owned NIC to carry all
three exchanges. `redis-smoke` adds an unmodified application TCP check. These
commands validate the virtual test topology, not every physical NIC or
production network configuration. The current network contracts and legacy
in-kernel IPv4 path are described in
[net/specification/spec.md](../net/specification/spec.md).

## Build and authenticate runtime modules

Read the kernel's exported-ABI hash and stamp it into the module. The e1000
crate is the current dual-build reference:

```sh
cat /sys/kernel/abi_hash
cargo xtask build-module --package narf-drivers-net-e1000 \
  --no-default-features --features module \
  --arch x86_64 --kernel-abi 0x1f3a90c2
```

Add `--compress` for the bounded LZ4 envelope. Production kernels embed raw
Ed25519 trust roots from the absolute build-time path in
`NARF_MODULE_TRUSTED_KEYS`. Sign `BLAKE3(the exact final .ko or .ko.lz4
bytes)`, then attach the detached signature and public key:

```sh
cargo xtask build-module --package <crate> --arch x86_64 \
  --kernel-abi 0x1f3a90c2 --compress --out module.ko.lz4
# Produce module.sig and module.pub with the authorized release signer.
cargo xtask attach-module-signature --module module.ko.lz4 \
  --signature module.sig --public-key module.pub
```

The loader authenticates a compressed envelope before decompression. Unsigned
loads are accepted only when the kernel was deliberately built with the
developer/CI `module-allow-unsigned` feature.

## Load, inspect, and unload modules

The Linux-shaped `init_module` and `finit_module` syscalls load an in-memory
image or an image from an open file descriptor; `delete_module` unloads it.
They require module-load authority (`CAP_SYS_MODULE` in the compatibility
boundary). Module dependencies listed in `depends=` must already be live:
there is no kernel dependency autoloader. A userspace `insmod`/`rmmod` client
may drive these syscalls, but do not assume a complete Linux `modprobe` policy
and alias database exists.

Boot-critical drivers can instead be named from the initramfs on the
bootloader-supplied kernel command line:

```text
modules_load=lib/modules/e1000.ko modules_domain=driver2
```

The comma-separated `modules_load=` list is processed before PCI device
probing. `modules_domain=` is the administrator's placement override for those
images. It does not bypass signatures, ABI matching, declared capability
checks, or the rule that runtime-loaded text cannot enter `FRAME`.

The manifest's `target_domain=` is the author's default. The authorized caller
can pass `domain=net`, `block`, `graphics`, `input`, `crypto`, `bpf`,
`scratch`, or `driver0` through `driver4` to the load syscall. This override
changes the effective isolation domain for a runtime module; `FRAME` is always
rejected.
By contrast, a driver compiled into the kernel has a statically assigned
domain and cannot be moved by a module parameter.

Inspect live state through `/proc/modules`, `/sys/kernel/abi_hash`, and
`/sys/module/<name>/` (including `refcnt`, `initstate`, dependency holders,
sections, and declared parameters). The selected domain is currently a loader
decision rather than a sysfs attribute, so retain the load parameters in the
operator record. Unload refuses a module with live references, removes
registered callbacks/interfaces, invokes the optional exit function, and
releases its resources. A known safety gap
remains: there is not yet a full SMP grace period between making module text
unreachable and unmapping it. Treat runtime unload on SMP production systems
as experimental and see [modules/DESIGN.md](../modules/DESIGN.md) for the
current limitation.

Load failures should be diagnosed from the kernel log and module sysfs state.
Common causes are a mismatched `/sys/kernel/abi_hash`, absent/invalid
signature, a missing dependency, an undeclared capability required by an
import, an unexported symbol, or an invalid domain name. The full manifest and
ABI rules are in [MODULE_AUTHORING.md](../modules/MODULE_AUTHORING.md).

## Security boundary

Runtime modules execute privileged native code, but the loader constrains
their accepted image, imports, capabilities, memory permissions, and isolation
domain. The stable boundary is a curated primitive/`repr(C)` C ABI; Rust trait
objects and `repr(Rust)` layouts never cross it. A valid signature establishes
publisher trust, not safety. Required capabilities still gate sensitive
exports, and the module cannot select the FRAME domain.

NARF has no conventional all-powerful root authority. Operational access is
capability-based even where the Linux-compatibility layer presents familiar
UIDs and syscall names. Review the [security model](../security-model/specification/spec.md)
and [module design](../modules/DESIGN.md) before deploying custom privileged
code.
