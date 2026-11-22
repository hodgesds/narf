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
2. **Freezer.** ~~User tasks~~ done (`narf_power::freezer`, spec
   §3.6.0b). Its freeze points are in `narf-userspace`'s user-task poll and
   park loops, so the executor core is untouched. `verification/freezer`
   freezes a real user task in user mode on each arch.
   `freeze_kernel_threads` (freezable workqueues) remains.
3. ~~**Device callbacks.**~~ Done (`freeze_all_devices` and the rest,
   `HibernationFns`, `hibernate_is_recovering`). amdgpu follows
   `amdgpu_pmops_*`: freeze is the suspend, thaw resumes only while
   recovering, poweroff skips a device the thaw left suspended, and restore
   is the resume.
4. **Non-boot CPUs.** Take them offline for the snapshot and restore
   (`pm_sleep_disable_secondary_cpus`), through `cpu_take_offline`.
5. **Snapshot.** Enumerate the frame allocator's allocated frames, minus
   the nosave regions (the image buffers themselves, firmware-reserved
   memory). Copy them atomically into free frames, with interrupts off
   on the boot CPU, as `swsusp_save` does. The copy needs free memory at
   least equal to what is in use. A fuller system fails the hibernation
   cleanly.
6. **Sealed streaming write.** The sealer takes a page source rather than
   one buffer. The SMS is TPM-sealed. Then preallocate the image file,
   map its extents, and write the header with the extent list, the
   kernel's KASLR slide and entry, and a hash of the firmware memory map.
   The resume locator follows Linux's `resume=` and `resume_offset=`:
   `narf.resume=<device>` and `narf.resume_offset=<block>`.
7. **Early readers.** Add polled PCI front ends for virtio-blk (QEMU on
   x86_64) and NVMe (hardware) beside the virtio-mmio one, plus early TPM
   access (CRB/TIS) for the unseal.
8. **Resume.** Probe after memory init and before device init. Then:
   - TPM unseal, then whole-image verification (`attempt_resume`);
   - refuse a changed memory map (`hibernation_e820_mismatch`);
   - load the pages into frames the boot kernel does not need;
   - run the per-arch trampoline (temporary page tables, copy, jump to
     the image kernel's saved context at its own slide);
   - in the image kernel: device restore, then thaw.
   A refused or failed image boots normally and invalidates the image.
9. **End-to-end test.** An xtask mode that boots QEMU twice on one disk:
   the first boot hibernates, the second resumes and checks state a
   kernel test left behind. Run it on both arches.

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
