# narf-block-encrypted — Specification

> Status: **v0.2** (Stage 5 implementation).
> 
> Transparent block-level encryption (AES-256-XTS) for native NARF volumes
> and read/write interoperability with existing LUKS1 volumes.

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

**Does NOT own:**
- Concrete block drivers (NVMe, VirtIO).
- Filesystem-level encryption (e.g. per-file encryption).
- Hardware-specific crypto offload (uses `narf-crypto` software primitives).
- LUKS2, keyslot creation/deletion, or LUKS formatting.
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

## 4. Operation: Read/Write Flow

- **Read(LBA, N)**:
  1. Read `N` sectors from the underlying device at `LBA + 8` (skipping 
     header sectors).
  2. Decrypt each sector using AES-256-XTS with `sector_id = LBA + i`.
  3. Return plaintext to the caller.
- **Write(LBA, N)**:
  1. Encrypt each sector using AES-256-XTS with `sector_id = LBA + i`.
  2. Write `N` sectors to the underlying device at `LBA + 8`.

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
- `narf-crypto`: For AES-256-XTS primitives.
- `narf-tpm`: For PCR-based unsealing.
- `capabilities`: For `TpmCap` and `BlockCap`.
- `zeroize`: For passphrase-derived keys, decrypted AF material, and digest
  scratch storage.

## 7. References

- LUKS1 On-Disk Format Specification, cryptsetup project.
- cryptsetup `lib/luks1/af.c` for the interoperable AF merge/diffuse layout.
- `~/git/linux/drivers/md/dm-crypt.c` for `plain64` little-endian sector IVs
  and the default 512-byte encryption-sector behavior.
