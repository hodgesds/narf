# S4 hibernation: plan of work

Status: planned on `feat/raphael-power-followups` (2026-11-22). Nothing
below the security layer exists yet. This note is the order of work and
the decisions it rests on. The interfaces land in `specification/spec.md`
§3 with each lane.

## Decisions

- **Both arches.** x86_64 enters `\_S4` through PM1; aarch64 powers off
  through PSCI `SYSTEM_OFF`. Each arch has its own restore trampoline.
- **TPM sealing** unlocks the first end-to-end resume (`TpmAnchor`,
  `suspend_service/tpm_anchor.rs`). Passphrase and token factors keep
  their existing slots.
- **The image is a file on the persistent filesystem.** This follows
  Linux's swap-file hibernation: at hibernate time the running kernel
  preallocates the file and maps its extents to device blocks. The image
  header records the device and that extent list, and the resume
  environment reads raw blocks through them, with no filesystem driver.
  This replaces §5's "pre-configured partition".

## What exists

The security layer in `suspend_service/` (key custody and slots, the
sealed format, the verify-before-execute reader, the hook fan-out, policy,
and the TPM, token and passphrase anchors) and its `attempt_resume` entry.
A polled virtio-mmio early reader. `SystemSleepState::S4` and the async
prepare for it (amdgpu's `prepare_graphics_hibernate`). S3 entry with an
`arch/` resume trampoline (`arch/src/x86_64/s3_resume.rs`).

## Lanes, in order

1. ~~**Entry and exit.**~~ Done (`hibernation_power_down`,
   `narf_aml::evaluate_s4`). `\_PTS(4)` and the PM1 S4 write, falling
   back to S5 as Linux's `power_down` does; `Shutdown` mode, and so PSCI
   `SYSTEM_OFF` on aarch64, without `\_S4`. QEMU's DSDT carries no `\_S4_`
   unless the machine sets ICH9's `disable_s4=0`. The end-to-end test
   (lane 9) needs it to exercise the platform mode. The coordinator that
   claims the transition beside S3 and s2idle comes with lane 3.
2. ~~**Freezer.**~~ Done (`narf_power::freezer`, spec
   §3.6.0b). Its freeze points are in `narf-userspace`'s user-task poll and
   park loops, so the executor core is untouched. `verification/freezer`
   freezes a real user task in user mode on each arch.
   `freeze_kernel_threads` freezes the `WQ_FREEZABLE` workqueues.
3. ~~**Device callbacks.**~~ Done (`freeze_all_devices` and the rest,
   `HibernationFns`, `hibernate_is_recovering`). amdgpu follows
   `amdgpu_pmops_*`: freeze is the suspend, thaw resumes only while
   recovering, poweroff skips a device the thaw left suspended, and restore
   is the resume.
4. **Non-boot CPUs.** Take them offline for the snapshot and restore
   (`pm_sleep_disable_secondary_cpus`), through `cpu_take_offline`.
5. ~~**Snapshot.**~~ Done (`hibernate::snapshot`, spec §3.6.0c). The
   walk uses the allocator's free-state index, so free blocks and cached
   frames are skipped and everything else in known RAM is saved (NVS
   included, in place of `suspend_nvs_save`). The copy frames are
   preallocated and marked so the copy skips them, and the copy allocates
   nothing. A system with less free memory than it uses fails cleanly.
6. ~~**Sealed streaming write.**~~ Done, except the coordinator glue:
   - the sealer reads an `ImageSource`;
   - `hibernate::payload` streams the snapshot with its header (kernel
     base and bounds, RAM-layout hash, arch record);
   - `hibernate::image_file` preallocates, maps (ext2 `bmap`) and proves
     the image file, and writes through its extents;
   - the resume locator is `narf.resume=<device>
     narf.resume_offset=<block>`.

   The SMS is TPM-sealed through the existing `TpmAnchor` slot.
7. ~~**Early readers.**~~ Not needed. The resume follows Linux's
   `software_resume`: a late initcall, reading through the normal block
   and TPM drivers, then quiescing the devices before the jump. The early
   virtio-mmio reader stays for the existing resume environment.
8. **Resume.** x86_64 done (`hibernate::software_resume`,
   `hibernate::arch`, `hibernate::restore`, spec §3.6.0f). It reuses S3's
   wake trampoline after a relocated copy loop, and the hibernation
   coordinator (`hibernate::hibernate`) is wired to `/sys/power/state`'s
   `disk`. aarch64's restore remains. The original outline:
   - TPM unseal, then whole-image verification (`attempt_resume`);
   - refuse a changed memory map (`hibernation_e820_mismatch`);
   - load the pages into frames the boot kernel does not need;
   - run the per-arch trampoline (temporary page tables, copy, jump to
     the image kernel's saved context at its own slide);
   - in the image kernel: device restore, then thaw.
   A refused or failed image boots normally and invalidates the image.
9. **End-to-end test.** `cargo xtask hibernate-e2e` (x86_64, one CPU)
   boots QEMU twice on one ext4 disk. The first boot fills 16 MiB with a
   token-seeded pattern and hibernates (guest half:
   `power/src/hibernate/e2e.rs`). The second resumes through `narf.resume=`
   and must report the same token and digest. OFF policy unless
   `--tpm-socket` names a swtpm. aarch64 follows its restore.

## Linux references

- `kernel/power/hibernate.c`: `hibernate`, `hibernation_snapshot`,
  `create_image`, `hibernation_platform_enter`, `software_resume`,
  `resume_target_kernel`.
- `kernel/power/snapshot.c` (`swsusp_save`, the nosave regions) and
  `swap.c` (the image writer, `swsusp_check`).
- `kernel/power/process.c` (`freeze_processes`) and `kernel/freezer.c`.
- `arch/x86/power/hibernate*.c` and `hibernate_asm_64.S`;
  `arch/arm64/kernel/hibernate.c` and `hibernate-asm.S`.
- `arch/x86/power/hibernate.c`: `arch_hibernation_header_save`, which
  carries the restore jump address and the e820 checksum.
