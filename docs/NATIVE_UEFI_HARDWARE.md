# Native EFI hardware acceptance

Physical acceptance is pending. Emulator results do not qualify a laptop's
firmware, GOP layout, keyboard timing, storage transport, or firmware blobs.
Run this procedure on each supported Renoir/Phoenix machine; retain the model,
firmware version, boot configuration, image SHA-256, git revision, serial log,
and result for every case. No physical boot has been performed for this
change. A target console and boot/power access are required.

## Prepare the image

Use the pinned Rust toolchain and follow [native EFI](NATIVE_UEFI.md). Start
with the in-tree initramfs and `narf.disks=boot-only`; add hardware firmware
through explicit `--initramfs-firmware` selections. For a laptop console:

```sh
cargo xtask efi-image \
  --cmdline 'narf.disks=boot-only console=ttyS0 console=tty0'
python3 packaging/native-efi.py target/narf-x86_64.efi
sha256sum target/narf-x86_64.efi
git rev-parse HEAD
git diff --stat
```

Copy the image to a removable FAT ESP as `EFI/BOOT/BOOTX64.EFI`, or use the
manual separate-directory workflow in the guide. Select it with the
firmware's one-time boot menu. Retain a known-good recovery boot option.
For Secure Boot, sign the completed image using an administrator-controlled
enrolled certificate, verify with `sbverify`, and record the certificate
fingerprint. The test suite's ephemeral keys are never enrollment keys for
an installed machine.

## Acceptance cases

| Case | Required observation |
| --- | --- |
| Cold boot, Secure Boot off | Firmware executes the single EFI file; kernel reaches login; `echo hello world` works. |
| Warm reboot | The same image returns to login without a firmware allocation or memory-map failure. |
| Graphical console | BGRX GOP framebuffer displays login; serial remains available for unsupported GOP formats. |
| Selected firmware | Required device loads the selected, policy-accepted firmware from the embedded archive. Record the device and driver evidence. |
| Secure Boot on, enrolled signer | Firmware accepts the image and EFI entry reports `SecureBoot=Some(1) SetupMode=Some(0)`. |
| Unsigned / modified image | Firmware refuses execution. Record its authentication error; a hang is not acceptance evidence. Test copies on removable media only. |
| Serial LUKS unlock | Correct passphrase mounts the intended root at `/dev/cryptroot`; verify a known file from that filesystem. |
| Wrong passphrase / cancel / timeout | Retry count is bounded; cancellation or exhaustion stops boot without a fallback login or secret in the log. |
| `root-ro` | Root and unrelated disks retain their pre-boot filesystem state. A distro overlay is discarded at shutdown. |
| `root-rw` on a disposable btrfs fixture | Existing btrfs write gate accepts the image; written data survives remount and host `btrfs check --readonly`. Whole-disk and unrelated partition writes remain refused. |

Encrypted-root credentials currently use a real serial connection. The EFI
loader does not prompt, and USB/graphical unlock is not implemented. Use a
disposable encrypted filesystem for write qualification before selecting an
installed operating system's root. Never include passphrases or private keys
in acceptance logs.

## Record results

Store results with the test artifacts or attach them to the hardware issue.
Use `PASS`, `FAIL`, or `NOT RUN` for each table row. Include kernel panic/fatal
output in full and the last successful boot stage. A successful OVMF run can
be cited separately using `target/secure-boot-native/report.json` and
`target/native-luks-tests/report.json`; it must not be recorded as a physical
machine pass.
