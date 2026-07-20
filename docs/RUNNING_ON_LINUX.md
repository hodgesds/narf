# Running NARF on a Linux system

A practical, end-to-end guide for a developer on an ordinary Linux
workstation: build NARF, boot it under QEMU, log in over the serial
console, run the test suite, and run **real, unmodified Linux software**
on top of the NARF kernel.

Everything here is grounded in the actual build orchestrator
(`build/xtask/src/main.rs`), the rootfs regeneration scripts under
`verification/data/musl-demo/`, and the CI workflow (`.github/workflows/ci.yml`).
See also [`README.md`](../README.md) (project overview) and
[`TESTING.md`](../TESTING.md) (the full testing surface).

> **Architecture note.** **x86_64** is the first-class, full path: it runs
> the interactive shell, `boot-init`, the ELF loader, real musl/glibc
> binaries, and off-box networking. **aarch64** boots under
> `qemu-system-aarch64 -M virt` and runs the async demo + kernel-test
> suite, but its userspace is a stub — `run-interactive`, `net-smoke`,
> `redis-smoke`, and `musl-demo` all bail with "only x86_64 is wired"
> because `boot-init`/the shell are gated to
> `cfg(all(feature = "boot-init", target_arch = "x86_64"))`. Follow this
> guide with `--arch=x86_64` unless a step says otherwise.

---

## 1. Prerequisites

### 1.1 Rust toolchain

NARF pins a nightly toolchain in [`rust-toolchain.toml`](../rust-toolchain.toml):

```toml
channel = "nightly-2025-09-14"
components = ["rust-src", "llvm-tools", "clippy", "rustfmt"]
profile = "minimal"
```

`rustup` picks up the pin automatically on the first `cargo` invocation
in the repo — you do **not** need `+nightly`. The build compiles
`core`/`alloc`/`compiler_builtins` from source per target via
`-Zbuild-std` (there are no precompiled cross targets), so **`rust-src`
is required**. `llvm-tools` is needed for the ISO/objcopy paths.

If your `rustup` hasn't fetched the pin yet:

```sh
rustup show active-toolchain || rustup toolchain install
rustup component add rust-src llvm-tools clippy rustfmt
```

### 1.2 Host packages (QEMU + friends)

The authoritative package list is CI's "Install host build deps" step
(`.github/workflows/ci.yml`), which on Ubuntu installs:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  qemu-system-x86 \
  qemu-system-arm \
  cpio \
  mtools \
  dosfstools \
  e2fsprogs \
  ovmf
```

What each is for:

| Package | Provides | Needed for |
|---|---|---|
| `qemu-system-x86` | `qemu-system-x86_64` | every x86_64 boot/run/test command |
| `qemu-system-arm` | `qemu-system-aarch64` | `--arch=aarch64` runs |
| `cpio` | (also built in-process) | initramfs firmware CPIO |
| `mtools` / `dosfstools` | FAT tooling | `xtask image` / `iso-boot` (ESP) |
| `e2fsprogs` | `mke2fs`, `debugfs` | building/editing the ext2 rootfs image |
| `ovmf` | OVMF UEFI firmware | `xtask iso-boot` (UEFI boot path) |

On Arch the equivalents are `qemu-full` (or `qemu-system-x86` +
`qemu-system-aarch64`), `cpio`, `mtools`, `dosfstools`, `e2fsprogs`,
`libisoburn` (for `xorriso`), and `edk2-ovmf`. Building an ext2 rootfs
also needs `e2fsprogs >= 1.43` (for `mke2fs -d`) plus `curl` and `tar`.

### 1.3 KVM (fast runs)

QEMU auto-selects an accelerator: **KVM when `/dev/kvm` exists**, otherwise
single-threaded TCG. KVM makes boots and the test suite dramatically
faster (TCG on a CI runner is ~5–10x slower). Make sure your user can
access `/dev/kvm`:

```sh
ls -l /dev/kvm                 # should exist
sudo usermod -aG kvm "$USER"   # then log out/in
```

You don't pass any flag to opt into KVM — it's automatic. You *can*
force an accelerator with `XTASK_QEMU_ACCEL` (see §7).

---

## 2. Get the code & first build

```sh
git clone <your-narf-remote> narf
cd narf

# Cross-compile the kernel (default: narf-frame, x86_64-unknown-none, debug)
cargo xtask build --arch=x86_64
```

`cargo xtask build` (dispatched to `cargo_build` in
`build/xtask/src/main.rs`) runs, in effect:

```sh
cargo build -p narf-frame --target x86_64-unknown-none \
  -Z build-std=core,compiler_builtins,alloc \
  -Z build-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128
```

The kernel ELF lands at `target/<triple>/<profile>/narf-frame`
(e.g. `target/x86_64-unknown-none/debug/narf-frame`).

`BuildArgs` (shared by most subcommands) knobs:

| Flag | Default | Meaning |
|---|---|---|
| `--arch` | `x86_64` | `x86_64` or `aarch64` |
| `--release` | off | build with `--release` |
| `--package` | `narf-frame` | crate to build |
| `--features` | *(empty)* | comma-separated cargo features |
| `--display` | `none` | QEMU display (`none`, `gtk`, …) |
| `--hw-profile` | `full` | `full` / `minimal` / `virtio-only` / `legacy-only` |

The first build is slow (build-std compiles the sysroot crates); later
builds are incremental.

---

## 3. Boot it & log in

### 3.1 The async demo

```sh
cargo xtask run --arch=x86_64
```

This builds the kernel and launches `qemu-system-x86_64` with a q35
machine, `-cpu max`, a NUMA/HMAT topology, serial on stdio, and the
full virtio + legacy device set (see `qemu_args` in main.rs). Without
`boot-init`, the kernel runs the async demo and halts. There's a 600s
watchdog (`XTASK_QEMU_TIMEOUT_SECS`) that kills a hung boot.

### 3.2 The interactive shell + login

To get a real login shell, boot with `boot-init` on. The easiest way is
`run-interactive`, which turns on `boot-init` + `firmware-allow-unsigned`
for you, waits for the prompt, types a command, and asserts output:

```sh
# Type `echo hello world` at the shell and assert `hello world`
cargo xtask run-interactive --arch=x86_64 \
  --cmd "echo hello world" --expect "hello world"
```

`RunInteractiveArgs` adds two flags on top of `BuildArgs`:

| Flag | Default | Meaning |
|---|---|---|
| `--cmd` | `echo hello world` | line typed at the shell (harness appends `\n`) |
| `--expect` | `hello world` | substring asserted on serial stdout afterward |

To drive the console **yourself**, boot with a display and interact over
`-serial stdio`:

```sh
# boot-init on, GTK window; the serial console is your terminal
cargo xtask run --arch=x86_64 --features boot-init --display=gtk
```

**Boot flow and login.** With `boot-init`, the kernel spawns `init`, then
`getty` (in place of a bare shell). `getty` sets up a login session
(`setsid` → controlling tty → foreground process group) and execs
`/bin/shell`, so the shell runs with real job control
(`frame/src/bare_main.rs`). The boot seeds a credential store at `/etc`:

- `/etc/passwd`: `root:x:0:0:root:/root:/bin/shell`
- `/etc/shadow`: root's password hash (`$n1$…`), mode `0600` owned by uid/gid 0

**The login is user `root`, password `narf`** (salt `n4rf`; verified by
the host-tested login-core hasher — regenerate the hash there if you
change it). Log in over the serial console, and you land at the shell
prompt (`narf> `).

**What works at the prompt.** The in-tree shell parses pipes and
conditionals and runs built-ins (`echo`, `pwd`, `ls`, `cat`, `cd`, …)
plus a large set of named ELF programs baked into the image — for
example `oci_smoke`, `distro_init`, `chroot_run`, and the many
`*_smoke` binaries registered in `bare_main.rs`. Each is launched
through the real execve + ELF loader + syscall-instruction dispatch
path. Example:

```sh
cargo xtask run-interactive --arch=x86_64 \
  --cmd "oci_smoke" --expect "oci-smoke-ok"
```

---

## 4. Test suite & smokes

### 4.1 Full kernel-test suite

```sh
cargo xtask test --arch=x86_64
```

`Cmd::Test` runs two phases:

1. **Kernel-test phase** — forces the `kernel-test` feature on, boots,
   and runs every in-kernel smoke. The runner calls `exit_kernel(0)`
   only when all pass; xtask gates on QEMU's exit status (a failing
   suite → nonzero → the command fails). Kernel-test builds use a
   separate disk (`target/narf-vblk-test.img`) so they never clobber
   your Alpine rootfs.
2. **Boot-smoke phase** — re-boots *without* `kernel-test` (real init
   flow) and scans serial output for panic markers + success markers.

### 4.2 Real-init boot smoke

```sh
cargo xtask boot-smoke --arch=x86_64
```

Forces the `boot-smoke` feature on (clean ACPI/isa-debug-exit shutdown
after init drains), streams serial output, and fails on any panic
marker (`*** KERNEL PANIC ***`, `panicked at`, `double fault`, `general
protection`, `kernel page fault`, `unsafe precondition`) or on a timeout
without a clean exit. Timeout: `XTASK_BOOT_SMOKE_TIMEOUT_SECS` (default 90).

### 4.3 The linux-compat demo binaries

```sh
cargo xtask musl-demo --arch=x86_64   # x86_64 only
```

Runs two `run-interactive` boots verifying `/bin/hello` (hand-rolled
`int 0x80` asm) and `/bin/hello_musl` (stock musl-static ELF) print
through the shell + execve + ELF loader + `int 0x80`/`syscall` dual
dispatch + `CR4.OSFXSR`.

### 4.4 Off-box network smokes

```sh
cargo xtask net-smoke   --arch=x86_64   # guest TCP echo server, host round-trip
cargo xtask redis-smoke --arch=x86_64   # unmodified redis-server, host SET/GET
```

Both force `boot-init` + `firmware-allow-unsigned` + `qemu-net` on, add
a QEMU hostfwd, wait for the auto-spawned server, then open a real host
TCP socket and round-trip. See §6 for how the forwarding works.

---

## 5. Running real Linux software (the rootfs-image model)

NARF runs unmodified Linux userlands using a **container-runtime model**:
you build an ext2 disk image holding a real distro rootfs, NARF mounts it
on the virtio-blk device at `/mnt` (with `/dev` bind-mounted and a
writable `/tmp`), and a small launcher `chroot()`s into it and `execve`s
the distro's own binaries. The kernel is never rebuilt to change what
runs inside — you edit the image.

> The rootfs images are **not committed to git** (only the `REGEN_*.sh`
> scripts are). Build the image locally first.

### 5.1 Build an Alpine (musl) rootfs

Alpine is musl-based, matching NARF's strongest ABI support. The
regeneration script is
[`verification/data/musl-demo/REGEN_alpine_rootfs.sh`](../verification/data/musl-demo/REGEN_alpine_rootfs.sh):

```sh
sh verification/data/musl-demo/REGEN_alpine_rootfs.sh
```

It downloads `alpine-minirootfs-3.21.0-x86_64.tar.gz`, unpacks it, and
builds a ~28 MiB **plain ext2** image at `target/narf-vblk.img`:

```sh
mke2fs -q -F -t ext2 -b 1024 \
  -O ^has_journal,^extent,^64bit,^metadata_csum,^dir_index,^resize_inode,^huge_file,^flex_bg,^ext_attr \
  -d "$WORK/root" target/narf-vblk.img 28672
```

The plain-ext2 options (no journal/extents/64bit/csum) deliberately
exercise NARF's indirect-block + fast-symlink read paths. `target/narf-vblk.img`
is exactly the path `xtask`'s `virtio_blk_image_path()` uses: if the file
already exists xtask uses it **verbatim**; only when it's absent does
xtask drop a tiny placeholder ext2 image (a single `/hello.txt`) so the
`mnt-mount-ext2` boot step has something to mount. So build the Alpine
image *before* running the distro/chroot demos.

### 5.2 Boot into the distro

The Alpine launcher is `distro_init`, which chroots into `/mnt` and execs
Alpine's own busybox:

```sh
cargo xtask run-interactive --arch=x86_64 \
  --cmd distro_init --expect alpine-shell-ran
```

Inside the chroot, `uname` prints `NARF x86_64` — Alpine's unmodified
busybox + musl running on the NARF kernel.

### 5.3 Iterate on arbitrary programs via `/probe.sh`

The generic launcher is `chroot_run`
([`verification/data/musl-demo/chroot_run.c`](../verification/data/musl-demo/chroot_run.c)).
It chroots into `/mnt`, sets `PATH`/`LD_LIBRARY_PATH`, and runs
`/probe.sh` through the distro's busybox:

```c
char *argv[] = { "busybox", "sh", "/probe.sh", NULL };
execve("/bin/busybox", argv, environ);
```

So the "run real Linux software, see what breaks" loop is: put a
`/probe.sh` into the rootfs image, then:

```sh
cargo xtask run-interactive --arch=x86_64 --cmd chroot_run --expect PROBE-DONE
```

(By convention `/probe.sh` ends by printing `PROBE-DONE`, so
`--expect PROBE-DONE` asserts it ran to completion — pick whatever
`--expect` substring matches your script's output.)

**Editing `/probe.sh` inside the image without rebuilding.** The
`REGEN_alpine_rootfs.sh` script does not seed a `/probe.sh` — you add
one. Because the image is plain ext2, `debugfs` (from `e2fsprogs`, which
you already installed) can write into it offline:

```sh
# author your script on the host
cat > /tmp/probe.sh <<'EOF'
#!/bin/sh
busybox uname -a
busybox echo "hello from inside the distro"
echo PROBE-DONE
EOF

# inject it into the rootfs image (-w = writable)
debugfs -w -R "rm /probe.sh" target/narf-vblk.img 2>/dev/null || true
debugfs -w -R "write /tmp/probe.sh probe.sh" target/narf-vblk.img
```

Then re-run the `chroot_run` command above. To iterate on a different
program, drop its binary in and call it from `/probe.sh` the same way.
(If `debugfs` write-in-place gives you trouble on your `e2fsprogs`
version, the always-works fallback is to unpack the rootfs, add the file,
and rebuild the image with `mke2fs -d` as the REGEN script does.)

### 5.4 glibc / systemd (debootstrap)

For a glibc userland (and toward systemd), build a Debian rootfs into the
same `target/narf-vblk.img` path instead of Alpine, e.g. with
`debootstrap`:

```sh
sudo debootstrap --arch=amd64 --variant=minbase trixie /tmp/debroot
# then pack /tmp/debroot into an ext2 image at target/narf-vblk.img,
# mirroring REGEN_alpine_rootfs.sh's mke2fs -d invocation.
```

Dynamic Debian glibc + `systemd --version`/`--test` run on NARF under
KVM today (with caveats around AVX-512/XSAVE and mount fstype breadth);
this is an active bring-up area rather than a one-command flow, so treat
it as advanced. There is **no** committed debootstrap REGEN script — you
assemble the image yourself.

---

## 6. Off-box networking

The off-box smokes use QEMU's user-mode (SLIRP) backend plus a host→guest
port forward. The `qemu-net` feature statically configures the guest's
virtio-net iface with the well-known SLIRP lease (10.0.2.15/24, gw
10.0.2.2) at boot, so a guest server is reachable from the host via a
QEMU `hostfwd`.

- **`net-smoke`** sets `XTASK_QEMU_HOSTFWD=tcp:127.0.0.1:17777-:7777`,
  boots the auto-spawned `netserve` echo server on guest `:7777`, and
  round-trips a line from host `127.0.0.1:17777`.
- **`redis-smoke`** forwards host `16379` → guest `6379`, waits for the
  unmodified `redis-server` to print `Ready to accept connections`, then
  does RESP `SET`/`GET` from the host.

You can also request forwarding manually for `xtask run` by exporting
`XTASK_QEMU_HOSTFWD` yourself (form: `tcp:HOSTIP:HOSTPORT-:GUESTPORT`).
For higher-fidelity / multi-queue networking, `XTASK_QEMU_TAP=<ifname>`
switches to a real host tap backend (the guest is reachable directly at
its static IP; you pre-create + bring up the tap), and
`XTASK_QEMU_QUEUES=N` requests N virtio-net queue pairs on a
`multi_queue` tap. `XTASK_QEMU_NETDUMP=<path>` pcaps the wire.

---

## 7. Performance knobs

All of these are environment variables read by `qemu_args`/the command
handlers in `build/xtask/src/main.rs`:

| Env var | Effect | Default |
|---|---|---|
| *(automatic)* | KVM used when `/dev/kvm` exists, else TCG | auto |
| `XTASK_QEMU_ACCEL` | force accel, e.g. `kvm` or `tcg,thread=multi` | unset (auto) |
| `NARF_QEMU_SMP` | vCPU count; also drops the 16-CPU NUMA/HMAT topology (e.g. `NARF_QEMU_SMP=2` cuts boot time under TCG) | unset → `16,sockets=2,cores=8` |
| `NARF_QEMU_MEM_MB` | total guest RAM in MiB (must be even; split across 2 NUMA nodes) | `1024` |
| `NARF_QEMU_CPU` | QEMU CPU model, e.g. `max,-x2apic,-tsc-deadline` | `max` |
| `NARF_QEMU_EXTRA` | extra whitespace-separated QEMU args (e.g. `-gdb tcp::1234`) | unset |
| `XTASK_QEMU_APPEND` | kernel cmdline via multiboot2 `-append` | unset |
| `XTASK_QEMU_TIMEOUT_SECS` | `run` watchdog | `600` |
| `XTASK_BOOT_SMOKE_TIMEOUT_SECS` | `boot-smoke` timeout | `90` |
| `XTASK_RI_PROMPT_TIMEOUT_SECS` | `run-interactive` prompt wait | `120` |
| `XTASK_RI_ECHO_TIMEOUT_SECS` | `run-interactive` per-command wait | `120` |

Fast local iteration on a KVM host: keep the defaults (KVM is picked
automatically). On a machine without KVM (TCG), set `NARF_QEMU_SMP=2` to
skip the expensive 16-AP bring-up for user-program smokes.

---

## 8. Feature flags (reference)

xtask enables the right features per command via `ensure_feature`, so you
rarely pass `--features` by hand. The ones worth knowing (defined in
`frame/Cargo.toml` and forwarded to sub-crates):

| Feature | Turns on |
|---|---|
| `boot-init` | Spawn `init` → `getty` → `/bin/shell`; the interactive/userspace path. Implies `linux-compat`. Auto-added by `run-interactive`, `net-smoke`, `redis-smoke`, `image`, `iso-boot`. x86_64 only in practice. |
| `linux-compat` | Linux-shaped syscall surface (epoll, eventfd, timerfd, clone3, mmap, fcntl, statx, mount/chroot, POSIX timers, …). Pulled in by `boot-init`. |
| `container` | PID/mount/network/UTS/IPC namespace isolation (the OCI persona). |
| `qemu-net` | Static SLIRP guest network config for off-box serving. Auto-added by the net/redis smokes. |
| `cgroup` / `cgroup-all` | cgroup-v2 unified hierarchy at `/sys/fs/cgroup`; `cgroup-all` enables every controller (pids/misc/memory/cpu/cpuset/io/psi). A kernel only *enforces* a controller it was built with. |
| `boot-smoke` | Clean shutdown after the real init flow drains (used by `boot-smoke`/`test` phase 2). |
| `firmware-allow-unsigned` | Accept unsigned firmware blobs (bring-up; signed-key infra isn't wired yet). Auto-added alongside `boot-init`. |
| `kernel-test` | In-kernel smoke-test runner (auto-added by `test` phase 1). |

`--no-default-features` pins user tasks to the BSP (the default feature
set is `user-task-smp`, which lets user tasks migrate onto APs).

---

## 9. Troubleshooting

**No `/dev/kvm` / permission denied.** QEMU silently falls back to TCG
(much slower) if `/dev/kvm` is missing or unreadable. Check
`ls -l /dev/kvm` and add yourself to the `kvm` group. Force behavior
with `XTASK_QEMU_ACCEL=kvm` (fail loudly if KVM is unavailable) or
`XTASK_QEMU_ACCEL=tcg`.

**Missing rootfs image / distro demo prints `chroot-fail`.** If
`target/narf-vblk.img` doesn't hold a real distro, xtask drops a tiny
placeholder (just `/hello.txt`) and the chroot launchers fail. Run
`sh verification/data/musl-demo/REGEN_alpine_rootfs.sh` first. Note the
kernel-test suite uses a *separate* disk (`narf-vblk-test.img`), so
running `cargo xtask test` won't clobber your rootfs — but any command
that *creates* the placeholder does so only when the file is absent.

**`chroot_run` runs but nothing happens / `exec-fail`.** You haven't put
a `/probe.sh` into the image (§5.3), or it isn't executable via busybox.
`debugfs -R "stat /probe.sh" target/narf-vblk.img` to confirm it's there.

**Command bails with "only x86_64 is wired".** `run-interactive`,
`net-smoke`, `redis-smoke`, and `musl-demo` are x86_64-only because
`boot-init`/the shell are gated to x86_64. Use `--arch=x86_64`.

**QEMU host crash during virtio-balloon bring-up.** Some packaged QEMU
builds (notably GitHub Actions' `qemu-system-x86`) SIGSEGV negotiating
the balloon device. Set `XTASK_QEMU_NO_BALLOON=1` to drop the device;
the balloon smokes then Skip. CI sets this globally.

**Buddy-allocator pressure / QEMU host crash under the full suite.** The
~5000-smoke suite sits near the buddy margin at the 1 GiB default and a
DMA-heavy probe can crash the emulator. Raise headroom with
`NARF_QEMU_MEM_MB=2048` (CI does this).

**x2APIC-gated smokes Skip under TCG.** CI's `qemu64` falls back to
xAPIC, so x2APIC-gated shootdown smokes Skip rather than run. If you need
them, run on a KVM host or use `XTASK_QEMU_ACCEL=tcg,thread=multi` with a
CPU model that exposes x2APIC.

**Boot hangs.** `run` kills a hung QEMU after `XTASK_QEMU_TIMEOUT_SECS`
(default 600). For a live debug session, attach gdb with
`NARF_QEMU_EXTRA="-gdb tcp::1234 -S"`.

---

## See also

- [`README.md`](../README.md) — project overview & quick start
- [`TESTING.md`](../TESTING.md) — the full testing surface (ISO, USB, real hardware)
- [`docs/PERSONAS.md`](PERSONAS.md) — the `linux-compat` + `container` feature personas
- `build/xtask/src/main.rs` — the orchestrator every command here comes from
