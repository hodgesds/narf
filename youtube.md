# YouTube/browser bring-up handoff

## Goal

Run an installed CachyOS KDE desktop under the NARF kernel in QEMU and verify
Firefox and Chromium can play YouTube with video and audio. The physical USB
installation is the later target; do not modify the base CachyOS disk image.

## Current VM

The currently running interactive VM is an immutable snapshot of
`target/cachyos-narf-test.raw`, launched by:

```text
target/debug/xtask systemd-pid1 --arch=x86_64 --features=container \
  --hw-profile=virtio-only --display=gtk,gl=on --gpu-backend=virgl
```

It is QEMU/KVM with 8 vCPUs, 8 GiB RAM, VirGL/virtio-gpu, user-mode networking,
and PipeWire virtio-sound. Its QMP socket is
`/tmp/narf-cachyos-audio.qmp`. Do not stop or restart it while the user is
using the desktop; changes to the kernel need a deliberate relaunch to test.

## Chromium: remaining startup work

### Observed failures

Chromium/Crashpad has reported, in sequence:

```text
memory_map.cc:162 format error
auxiliary_vector.h:59 value not found
ptracer.cc:44 Invalid argument
process_reader_linux.cc:400 couldn't initialize main thread
process_reader_linux.cc:472 no exe mappings
elf_image_reader.cc:456 unexpected image type
ptrace input/output error (5)
incorrect ELF magic number
```

The current high-confidence remaining cause is `/proc/<pid>/maps` loader
provenance. Crashpad groups VMAs by `(device, inode)`, locates that image's
offset-zero VMA, then reads its ELF header. NARF used to render loader mappings
with the right range, permissions, offset, and pathname but rendered every
mapping's identity as `00:00 0`. Crashpad therefore treated the executable
mapping as anonymous and could read a code page as an ELF header, producing the
remaining incorrect-magic failure.

### Uncommitted implementation already present

The following currently uncommitted changes carry VFS identity from exec into
the procfs maps snapshot:

- `userspace/src/process.rs`
  - `LoadedMapping` now has `device` and `inode`.
  - Main executable segments inherit `FileOps::inode_attrs().dev` and
    `FileOps::ino()`.
  - VFS-loaded `PT_INTERP` segments inherit their own identity too.
  - `read_path_and_file_from_vfs()` retains the interpreter `FileOps` long
    enough to capture that identity; the existing `read_path_from_vfs()` API
    keeps returning only the bytes.
- `userspace/src/handlers/compat.inc.rs`
  - The exec-owned `/proc/maps` side table retains `device` and `inode`.
  - Proc task snapshot rendering publishes those fields with each matching
    VMA.
- `filesystem/src/procfs/mod.rs`
  - `ProcVma` represents packed Linux `st_dev` and `st_ino`.
  - `/proc/<pid>/{maps,smaps}` decodes Linux `new_encode_dev()` and emits the
    real `major:minor inode` token pair.
- `userspace/src/abi_proc2_tests.rs`
  - The production procfs-hook test now asserts e.g.
    `08:13 42`, not `00:00 0`, alongside the nonzero file offset and pathname.
- `filesystem/src/procfs/mod.rs`
  - A renderer test asserts identity, offset, and pathname together.
- `filesystem/specification/spec.md` and `userspace/specification/spec.md`
  - Updated the public contract for exec-published map provenance.

This deliberately leaves later ordinary file-backed `mmap()` provenance
unchanged. The immediate Crashpad bootstrap requires the executable and
interpreter mappings. If Chromium starts but Crashpad later fails while walking
DSOs, extend the existing mapped-file ownership table to expose `FileOps`
identity/offset/path for ordinary file mappings as a follow-up; do not invent
synthetic identities.

### Validation status

- Passed: `cargo fmt --check`
- Passed: `git diff --check`
- Passed: `cargo check -p narf-filesystem -p narf-userspace`
- A focused kernel-test build was launched with:

  ```text
  cargo xtask test --arch=x86_64 \
    --subsystem=filesystem/procfs,syscall_abi --kernel-tests-only
  ```

  The host-side process finished, but its terminal output was lost by the
  tool/session boundary. Re-run it from a persistent terminal before claiming
  the tests passed. Do not treat it as a pass yet.

### Next Chromium steps

1. Re-run the focused test command above and collect its full result.
2. Run changed-package lint:

   ```text
   cargo xtask clippy-changed --arch=x86_64 \
     --packages '["narf-filesystem","narf-userspace"]'
   ```

3. Relaunch the CachyOS VM with the rebuilt kernel, then start Chromium.
4. If it still fails, record the *first* current Crashpad error and inspect
   `/proc/<chromium-pid>/maps` and `/proc/<chromium-pid>/auxv` from inside the
   guest. Confirm the executable's segments share a nonzero device/inode and
   include an offset-zero segment. Only after that use targeted ptrace/syscall
   tracing.

## Firefox: `PR_IO_TIMEOUT`

This is independent of Chromium's ELF/Crashpad startup path. It indicates that
Firefox established neither a timely HTTP/TLS response nor a timely socket
connection; it is not evidence of a Firefox profile problem.

Earlier observations include intermittent DNS delays, `resolvectl` failing an
interface-index ioctl, transient packet loss, and user-mode QEMU networking.
Another branch/agent has been working on network performance; do not discard
or duplicate its changes blindly.

### Required focused diagnosis

After launching a kernel that contains the current network work, collect from
the guest terminal (replace `youtube.com` only if testing another origin):

```text
ip -br addr
ip route
resolvectl query -4 youtube.com
curl -4 -v --connect-timeout 5 --max-time 20 \
  https://www.youtube.com/generate_204
```

Interpretation:

- DNS query stalls/fails: inspect resolver/netlink ioctl behavior and DNS
  request/reply delivery.
- DNS succeeds but `curl` never connects: inspect TCP SYN/SYN-ACK, routing,
  virtio-net TX completion, and QEMU user-mode NAT.
- TCP connects but TLS/HTTP stalls: inspect TCP receive/ACK progress, socket
  wakeups, and certificate/time only after transport progress is known.

Use the project debugging sequence: review the implicated code and existing
tests, add a regression test at the relevant layer, implement the smallest
fix, then use targeted tracing only if the test/review does not explain the
failure. Do not paper over timeouts in Firefox.

## Video/audio after startup and transport work

1. Play a short YouTube video in Firefox, then Chromium.
2. Check separate outcomes: page load, first frame, continuous video, audio,
   and seek.
3. For audio, verify the QEMU process still has:

   ```text
   -audiodev pipewire,id=snd0
   -device virtio-sound-pci,audiodev=snd0,disable-legacy=on,disable-modern=off
   ```

   This support was committed in `758b1535` and should remain in the helper.
4. For GPU issues, coordinate with the separate AMDGPU work. Do not mix its
   unrelated working-tree changes into browser/procfs commits.

## Working-tree discipline

Current branch: `youtube-fixes`.

Other agents have unrelated modifications under `drivers/gpu/` and
`drivers/virtio/`, plus `.kwin-pre-gpu/` and `cachy.md`. Preserve them. The
procfs/loader changes above should be reviewed and committed separately only
after the focused kernel test and changed-package Clippy pass.
