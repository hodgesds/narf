# UEFI Secure Boot

NARF supports administrator- and distribution-signed native UEFI packages on
x86_64 and aarch64. The project does not ship a universal signing key and the
release workflow does not access private keys. A machine will accept a NARF
loader only when the certificate that signed it is already trusted by that
machine's UEFI `db` or by the active shim/MOK policy.

Secure Boot covers the complete NARF boot chain rather than only the first EFI
executable:

- On x86_64, the default native image embeds kernel, initramfs, and command
  line in its `.narf` PE section. Firmware verifies the complete image before
  entry; the loader verifies the three embedded SHA-256 hashes before parsing
  the kernel. EFI load options cannot override the embedded policy.
- Explicit legacy `--limine-efi` packages retain the enrolled configuration
  digest and BLAKE2b-bound kernel path enforced by Limine's Secure Boot policy.
- On aarch64, packaging binds the exact kernel's BLAKE2b-512 digest into the
  NARF EFI loader before signing. The loader rejects a missing binding or a
  different kernel before parsing its ELF headers or copying any segment.

Changing the loader, configuration, or kernel therefore breaks the verified
chain. Signing only an unbound loader is intentionally not treated as Secure
Boot support.

## Use an existing sbctl policy

Install the unsigned native package first, leaving the distribution kernel as
the default. Then ask `narf-uefi` to sign the bound loader with the existing
`sbctl` database key:

```sh
sudo sbctl status
sudo narf-uefi install --sign-with-sbctl
sudo narf-uefi status
sudo sbctl verify /efi/EFI/NARF/narf.efi
```

Replace `/efi` in the verification command with the machine's actual ESP mount
point. The explicit signing choice is remembered under `/var/lib/narf`; package
upgrades re-sign the new loader before atomically publishing it. Use
`sudo narf-uefi install --no-sbctl-sign` to stop that behavior.

`narf-uefi` never creates or enrolls keys. If the machine does not already have
an `sbctl` policy, follow the distribution and firmware documentation before
changing PK, KEK, or `db`. In particular, preserving the Microsoft and firmware
vendor certificates may be required for option ROMs, Windows, or device
firmware. A failed enrollment policy can leave other installed operating
systems or hardware initialization unbootable.

The upstream [`sbctl` documentation](https://github.com/Foxboron/sbctl/blob/master/docs/sbctl.8.txt)
describes key creation, enrollment, signing, verification, and its option-ROM
warnings. Treat enrollment as a machine administration operation, not a NARF
package-install step.

After enrollment and signing, enable Secure Boot in firmware, keep the existing
distribution entry as the default, and select NARF once. If it fails, return to
the distribution entry rather than clearing keys from an unverified recovery
environment.

## Build a distribution-signed package

Distributions can sign while producing a package. Both key and certificate are
required, and `sbsign` plus `sbverify` must be installed:

```sh
packaging/build-release.sh \
  --version 0.5.0 \
  --arch x86_64 \
  --limine-efi /usr/share/limine/BOOTX64.EFI \
  --secure-boot-key /secure/db.key \
  --secure-boot-cert /secure/db.crt
```

For aarch64, first build the UEFI image/payload, then package its loader:

```sh
cargo xtask image --arch=aarch64
packaging/build-release.sh \
  --version 0.5.0 \
  --arch aarch64 \
  --uefi-loader target/narf-uefi-aarch64/narf.efi \
  --secure-boot-key /secure/db.key \
  --secure-boot-cert /secure/db.crt
```

The optional Cargo frontend exposes the same `--arch`, `--uefi-loader`,
`--secure-boot-key`, and `--secure-boot-cert` arguments. Never place private
keys in the checkout, package payload, CI artifact, or release archive.

The certificate used for the resulting package must be enrolled before boot.
NARF does not sign the host's GRUB, systemd-boot, rEFInd, shim, or firmware
drivers; every earlier component in the selected boot path must already be
trusted by that machine's policy.

## Verification

The ordinary packaging test checks binding metadata, both architectures, and
the persistent `sbctl` upgrade path. Firmware acceptance has separate gates:

```sh
packaging/test-secure-boot.sh
packaging/test-aarch64-package-boot.sh
```

The x86_64 gate creates an ephemeral certificate, signs and installs the native
package, enrolls that certificate in a disposable OVMF variable store, and
requires a clean boot with the EFI entry reporting `SecureBoot=1` and `SetupMode=0`. It then
requires explicit firmware authentication rejection of unsigned images and
independent modifications to the embedded kernel, initramfs, and command line.
A timeout alone is not a passing rejection. Logs and a JSON report are retained
under `target/secure-boot-native/`; no private key is retained. The explicit
legacy gate is `packaging/test-secure-boot.sh --limine`. The aarch64 gate boots
the native package under AAVMF and checks a tampered separate kernel.

Physical-machine qualification uses [native hardware acceptance](NATIVE_UEFI_HARDWARE.md)
and remains separate from OVMF results. Test keys are never production keys.

Secure Boot authentication is distinct from TPM measured boot, rollback
protection, certificate revocation, and key rotation. Those policies remain
owned by the deploying administrator or distribution; passing the Secure Boot
gate must not be presented as implementing all four.
