# narf-block-encrypted — Specification

> Status: **v0.1** (Stage 4 implementation). 
> 
> Transparent block-level encryption (AES-256-XTS) for the NARF ecosystem.
> Anchored in Measured Boot PCRs via TPM 2.0 unsealing.

## 1. Purpose & scope

**Owns:**
- **Encrypted Block Adapter**: A wrapper that implements `BlockDeviceSync` by 
  encrypting/decrypting sectors as they pass through.
- **On-disk Metadata Format**: A standard header for storing the TPM-sealed key 
  and algorithm parameters.
- **Key Unsealing Protocol**: Interaction with `narf-tpm` to retrieve the 
  Volume Key (VK) only if the system TCB is in a verified state.

**Does NOT own:**
- Concrete block drivers (NVMe, VirtIO).
- Filesystem-level encryption (e.g. per-file encryption).
- Hardware-specific crypto offload (uses `narf-crypto` software primitives).

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
- **Zero-Secret Persistence**: The Volume Key exists only in the 
  `DomainId::KEYS` domain and is never written to disk unencrypted.

## 6. Dependencies

- `narf-block`: For `BlockDeviceSync` trait.
- `narf-crypto`: For AES-256-XTS primitives.
- `narf-tpm`: For PCR-based unsealing.
- `capabilities`: For `TpmCap` and `BlockCap`.
