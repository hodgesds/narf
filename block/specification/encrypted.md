# narf-block-encrypted — Specification

> Status: **v0.3** (Stage 5 implementation).
> 
> Transparent block-level encryption (AES-XTS) for native NARF volumes and
> read/write interoperability with existing LUKS1/LUKS2 volumes.

## 1. Purpose & scope

**Owns:**
- **Encrypted Block Adapter**: A wrapper that implements `BlockDeviceSync` by 
  encrypting/decrypting sectors as they pass through.
- **On-disk Metadata Format**: A standard header for storing the TPM-sealed key 
  and algorithm parameters.
- **Key Unsealing Protocol**: Interaction with `narf-tpm` to retrieve the 
  Volume Key (VK) only if the system TCB is in a verified state.
- **LUKS1 unlock**: Strict parsing, bounded PBKDF2 work, anti-forensic stripe
  merge, volume-key authentication, and a payload-offset block adapter.
- **LUKS2 unlock**: Redundant checksummed metadata selection, bounded JSON
  parsing, PBKDF2 or Argon2i/Argon2id key derivation, anti-forensic merge,
  digest authentication, and segment-offset/tweak mapping.

**Does NOT own:**
- Concrete block drivers (NVMe, VirtIO).
- Filesystem-level encryption (e.g. per-file encryption).
- Hardware-specific crypto offload (uses `narf-crypto` software primitives).
- Keyslot creation/deletion, LUKS formatting, metadata repair, integrity
  profiles, or in-progress reencryption activation.
- Passphrase acquisition policy (early console, keyfile, or TPM); boot owns it.

## 2. On-disk Metadata Format (Header)

The encrypted volume starts with a 4096-byte metadata block (LBA 0).

| Offset | Field | Size | Description |
| :--- | :--- | :--- | :--- |
| `0x00` | Magic | 8 bytes | `NARF_ENC` |
| `0x08` | Version | 4 bytes | `0x00000001` |
| `0x0C` | Algorithm | 4 bytes | `0x00000001` (AES-256-XTS) |
| `0x10` | Key Size | 4 bytes | `64` (512 bits for XTS) |
| `0x14` | Salt | 32 bytes | Random salt for KDF (if used) |
| `0x34` | Sealed Key Len | 4 bytes | Length of the TPM-sealed blob |
| `0x38` | Sealed Key Blob | Variable | The TPM-sealed Volume Key (VK) |

## 3. Key Management

1. **Volume Key (VK)**: A random 512-bit key used for AES-256-XTS.
2. **Key Encryption Key (MK/KEK)**: A key stored in the TPM, or the TPM 
   itself acts as the MK by unsealing the VK directly.
3. **TCG Policy**: The VK is sealed against PCRs **0, 4, 9, 10**:
   - **PCR 0**: SRTM / Frame binary.
   - **PCR 4**: Bootloader handoff data.
   - **PCR 9**: Initramfs.
   - **PCR 10**: Peripheral firmware (attested via SPDM).

### 3.1 Existing LUKS1 volumes

```rust
pub fn Luks1Header::parse(bytes: &[u8]) -> Result<Luks1Header, Luks1Error>;
pub fn EncryptedBlockDevice::open_luks1(
    inner: Arc<dyn BlockDeviceSync>,
    passphrase: &[u8],
) -> Result<EncryptedBlockDevice, Luks1Error>;
pub fn EncryptedBlockDevice::open_luks1_with_policy(
    inner: Arc<dyn BlockDeviceSync>,
    passphrase: &[u8],
    policy: Luks1UnlockPolicy,
) -> Result<EncryptedBlockDevice, Luks1Error>;
pub fn EncryptedBlockDevice::open_luks2(
    inner: Arc<dyn BlockDeviceSync>,
    passphrase: &[u8],
) -> Result<EncryptedBlockDevice, Luks2Error>;
pub fn EncryptedBlockDevice::open_luks2_with_policy(
    inner: Arc<dyn BlockDeviceSync>,
    passphrase: &[u8],
    policy: Luks2UnlockPolicy,
) -> Result<EncryptedBlockDevice, Luks2Error>;
pub fn load_header(inner: &dyn BlockDeviceSync) -> Result<Luks2Header, Luks2Error>;
pub fn install_luks_passphrase_provider(provider: LuksPassphraseProvider);
pub fn probe_luks_volume(
    inner: &dyn BlockDeviceSync,
) -> Result<Option<LuksVolumeInfo>, LuksOpenError>;
pub fn open_luks_with_provider(
    inner: Arc<dyn BlockDeviceSync>,
) -> Result<EncryptedBlockDevice, LuksOpenError>;
```

The supported compatibility profile is LUKS version 1, `aes`,
`xts-plain64`, a 64-byte AES-256-XTS key, 512-byte encryption sectors, and
PBKDF2-HMAC-SHA1/SHA256/SHA512. The fixed header is big-endian. Keyslot
material is decrypted with a relative sector tweak beginning at zero, merged
with the LUKS anti-forensic diffuser, then authenticated against `mkDigest`
before the payload mapping becomes visible.

The default policy rejects any single PBKDF2 invocation over 10,000,000
iterations, more than 25,000,000 aggregate iterations across enabled slots,
or any keyslot allocation over 16 MiB. Callers may lower the work bounds, but
raising them is an explicit availability tradeoff. Parsing and open are
read-only with respect to LUKS metadata.

### 3.2 Existing LUKS2 volumes

Both metadata copies are read and authenticated with their declared SHA-256
or SHA-512 checksum; the valid copy with the greatest sequence ID is selected
without modifying the disk. The supported activation profile is a single
normal `crypt` segment using `aes-xts-plain64`, 512/1024/2048/4096-byte
encryption sectors, and a 32-byte AES-128-XTS or 64-byte AES-256-XTS volume
key. Keyslots use the LUKS1 AF layout with 4000 stripes and PBKDF2-HMAC or
Argon2i/Argon2id. Candidate keys must pass their bound PBKDF2 digest before
the mapping is returned.

Unknown mandatory requirements, integrity profiles, linear/multi-segment
reencryption states, and priority-zero keyslots in automatic mode are rejected.
The default policy caps PBKDF2 iterations, per-slot and aggregate Argon2
memory/time work, Argon2 lanes, keyslot area size, and the number of automatic
attempts. Loading and opening never repair stale metadata or write either
header.

### 3.3 Boot credential seam

Boot orchestration installs one `LuksPassphraseProvider` callback. The block
layer probes the non-secret LUKS version/UUID, calls the provider without
holding its registry lock, and keeps the returned passphrase in
`Zeroizing<Vec<u8>>` only through KDF/keyslot authentication. The initramfs
integration supplies an opt-in measured keyfile provider with
`rd.luks.key=/path` and optional `rd.luks.uuid=<uuid>` selection. Keyfile bytes
are consumed exactly; text decoding and newline stripping are forbidden.

## 4. Operation: Read/Write Flow

- **Read(LBA, N)**:
  1. Expose logical blocks of `max(inner LBA size, encryption-sector size)`;
     translate each visible block into the corresponding underlying LBAs at
     the authenticated segment offset.
  2. Decrypt each encryption sector using AES-128-XTS or AES-256-XTS and the
     `plain64` data-unit number derived from `iv_tweak` plus its 512-byte
     dm-crypt sector offset.
  3. Return plaintext to the caller.
- **Write(LBA, N)**:
  1. Encrypt each complete visible block with the same authenticated geometry
     and tweak mapping.
  2. Translate it to one or more underlying LBAs and write ciphertext at the
     segment offset. Partial encryption-sector I/O is never exposed.

## 5. Security Properties

- **TCB-Anchored**: If the kernel image or initramfs is tampered with, the 
  TPM will refuse to unseal the volume key, making the data inaccessible.
- **Sector Isolation**: AES-XTS ensures that the same plaintext at different 
  LBAs results in different ciphertext.
- **Zero-Secret Persistence**: The Volume Key is never written to disk
  unencrypted and is stored in the redacted, zeroizing `VkBytes` wrapper.
- **Header distrust:** all offsets, products, allocations, and KDF work factors
  derived from LUKS metadata are checked before I/O or allocation.
- **Authentication before exposure:** a candidate volume key is never used for
  payload I/O unless its PBKDF2 digest matches the header in constant time.
- **Current isolation limitation:** until the Stage-5 domain-entry hook is
  live, `VkBytes::new` permits FRAME during early boot. Explicit derived-key
  byte buffers are zeroized, but strict KEYS-only execution remains an exit
  gate.

## 6. Dependencies

- `narf-block`: For `BlockDeviceSync` trait.
- `narf-crypto`: For AES-128/256-XTS and SHA primitives.
- `narf-tpm`: For PCR-based unsealing.
- `capabilities`: For `TpmCap` and `BlockCap`.
- `zeroize`: For passphrase-derived keys, decrypted AF material, and digest
  scratch storage.
- `argon2`: For LUKS2 Argon2i/Argon2id KDFs with caller-owned zeroized memory.
- `serde` / `serde_json`: For typed LUKS2 metadata decoding.

## 7. References

- LUKS1 On-Disk Format Specification, cryptsetup project.
- LUKS2 On-Disk Format Specification, cryptsetup project.
- cryptsetup `lib/luks1/af.c` for the interoperable AF merge/diffuse layout.
- `~/git/linux/drivers/md/dm-crypt.c` for `plain64` little-endian sector IVs
  and the default 512-byte encryption-sector behavior.
