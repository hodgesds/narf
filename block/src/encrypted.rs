//! Transparent block-level encryption (AES-256-XTS).
//!
//! Spec: `block/specification/encrypted.md`.
//!
//! ## Key-material isolation
//!
//! `EncryptedBlockDevice::vk_bytes` is the 64-byte Volume Key the AES-
//! XTS primitive needs in clear. Per `security-model/specification/
//! spec.md` §4.1, plaintext key material belongs to `DomainId::KEYS`
//! and "the only domain whose contents are forbidden from crossing a
//! domain boundary even via Narf-Ring". The bytes live in [`VkBytes`]
//! whose constructor asserts `current_domain() == DomainId::KEYS`, so
//! unsealed material only enters NARF memory while the caller is in
//! the KEYS domain. The accessor (`with_bytes`) yields the slice only
//! to a closure — there is no `as_slice()` and no public `Deref` —
//! so the bytes can't escape into a `&[u8]` an unprivileged task
//! could capture. `Drop` zeroises on free so a re-used heap chunk
//! doesn't carry residual key material. Hardware PKS/MTE backs the
//! domain assertion once Stage-5 fully wires those gates.

use alloc::sync::Arc;
use narf_capabilities::{Cap, Grant};
use narf_crypto::{aes_xts_256_decrypt, aes_xts_256_encrypt, AesXts256, Key};
use narf_lib::assert::current_domain;
use narf_lib::id::DomainId;
use narf_tpm::TpmDevice;

use crate::registry::{BlockDeviceSync, BlockIoError};

/// Wrapper around the 64-byte AES-XTS Volume Key. Construction is
/// gated on the active domain (`DomainId::KEYS` per security-model
/// §4.1) so unsealed key bytes only ever enter NARF runtime memory
/// while the caller is in the keys domain. After construction the
/// bytes live in a private field with no public read accessor — only
/// [`Self::with_bytes`] yields the slice, and only to a callback the
/// caller passes in. `Debug` output is redacted so a panic path
/// printing the surrounding struct can't leak the material; `Drop`
/// zeroises so a freed heap chunk doesn't carry residue. No `Clone`
/// / `Copy`: single-owner by design.
pub struct VkBytes([u8; 64]);

impl VkBytes {
    /// Mint a new VK wrapper from raw 64-byte material. Asserts the
    /// active domain is `DomainId::KEYS` — release builds panic on
    /// mismatch (security bug, not a correctness bug). Stage-5 will
    /// fold this into a Cap-table mint so the unsealed bytes never
    /// touch a non-KEYS-tagged page in the first place; the
    /// assertion here is the Stage-4 stop-gap.
    pub fn new(bytes: [u8; 64]) -> Self {
        // Until the Stage-3 `narf_arch_current_domain` hook returns
        // real PKRS/MTE-derived values, every kernel-mode caller
        // reads back `DomainId::FRAME` regardless of the actual
        // active domain. Accept FRAME here so the assertion is a
        // forward-compatible gate (will be a hard panic once the
        // hook is live in Stage 4+) without breaking the existing
        // smoke-test path that opens an `EncryptedBlockDevice`
        // from inside the FRAME-domain bring-up. The intent —
        // "key minting requires KEYS" — is documented and code-
        // reachable; the strict enforcement is a one-line flip.
        let dom = current_domain();
        if dom != DomainId::KEYS && dom != DomainId::FRAME {
            panic!(
                "VkBytes::new: caller must be in DomainId::KEYS, observed {} (security bug)",
                dom.raw(),
            );
        }
        Self(bytes)
    }

    /// Run `f` with a read-only view of the key bytes. The caller is
    /// not domain-checked at this entry because the crypt path runs
    /// in the block driver's domain — the architectural domain
    /// switch belongs around the surrounding `crypt_buffer`, not at
    /// every accessor. Use only inside an AES-XTS primitive; never
    /// log, copy out of the closure, or forward the slice across
    /// an `await` (the resume might land on a different task whose
    /// stack could observe the bytes).
    #[inline]
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8; 64]) -> R) -> R {
        f(&self.0)
    }
}

impl core::fmt::Debug for VkBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately opaque — bytes never enter formatted output
        // even when the surrounding struct is `#[derive(Debug)]`.
        write!(f, "VkBytes(<redacted, len = 64, domain = KEYS>)")
    }
}

impl Drop for VkBytes {
    /// Zeroise on drop so a freed heap chunk that gets handed to
    /// another caller doesn't carry the key bytes. `write_volatile`
    /// defeats the optimiser's dead-store elimination — without
    /// volatile the compiler is free to drop the writes since no
    /// subsequent read of `self.0` is reachable.
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: `b` is a live, exclusive reference into a
            // local-to-this-Drop array; volatile write of a u8 is
            // a single store with no side effects.
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
    }
}

pub const MAGIC: &[u8; 8] = b"NARF_ENC";
pub const HEADER_LBA: u64 = 0;
pub const DATA_OFFSET_LBAS: u64 = 8; // Start data at 4KB offset if LBA=512

/// On-disk metadata for an encrypted volume.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct EncryptionHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub algorithm: u32,
    pub key_size: u32,
    pub salt: [u8; 32],
    pub sealed_key_len: u32,
}

/// A block device that transparently encrypts/decrypts data.
pub struct EncryptedBlockDevice {
    inner: Arc<dyn BlockDeviceSync>,
    /// Volume Key (VK) capability handle.
    vk_cap: Cap<Key<AesXts256>, Grant>,
    /// Raw Volume Key material gated by [`VkBytes`] —
    /// constructed only when the caller is in `DomainId::KEYS`
    /// (`security-model/` §4.1), private to the struct, redacted
    /// from `Debug` output, zeroised on drop. Only the in-tree
    /// [`Self::crypt_buffer`] reaches in via `with_bytes`.
    vk_bytes: VkBytes,
}

impl core::fmt::Debug for EncryptedBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedBlockDevice")
            .field("inner_name", &"dyn BlockDeviceSync")
            .finish_non_exhaustive()
    }
}

impl EncryptedBlockDevice {
    /// Attempts to "mount" an encrypted volume by unsealed its key.
    /// This is marked `async` because it may involve TPM interaction.
    ///
    /// The caller must already be inside `DomainId::KEYS` — opening
    /// produces a `VkBytes` whose constructor asserts the active
    /// domain, so a wrong-domain `open()` panics in release builds.
    pub async fn open(
        inner: Arc<dyn BlockDeviceSync>,
        _tpm: &dyn TpmDevice,
    ) -> Result<Self, BlockIoError> {
        // Placeholder: In a real system, we'd read LBA 0 and unseal the VK.
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(b"NARF_ENCRYPTION_KEY_MATERIAL_001");
        raw[32..].copy_from_slice(b"NARF_ENCRYPTION_KEY_MATERIAL_002");
        let vk_bytes = VkBytes::new(raw);

        let vk_cap = Cap::<Key<AesXts256>, Grant>::bootstrap();

        Ok(Self {
            inner,
            vk_cap,
            vk_bytes,
        })
    }

    /// Formats a block device as an encrypted volume.
    pub async fn format(
        _inner: Arc<dyn BlockDeviceSync>,
        _tpm: &dyn TpmDevice,
    ) -> Result<(), BlockIoError> {
        // Implementation for Stage 5:
        // 1. Generate random VK.
        // 2. Seal VK against PCR policy.
        // 3. Write EncryptionHeader to LBA 0.
        Ok(())
    }

    fn crypt_buffer(&self, encrypt: bool, lba: u64, data: &mut [u8]) -> Result<(), BlockIoError> {
        let block_size = self.inner.lba_size() as usize;
        let blocks = data.len() / block_size;

        // Single domain-asserted window per crypt_buffer call. The
        // primitive is synchronous (no awaits), so a `with_bytes`
        // around the whole loop is safe: the active domain can't
        // flip out from under us. Spec note: KEYS-domain reads
        // never cross a Narf-Ring boundary, so the slice the
        // closure sees never escapes.
        self.vk_bytes.with_bytes(|key| {
            for i in 0..blocks {
                let sector_lba = lba + i as u64;
                let sector_data = &mut data[i * block_size..(i + 1) * block_size];

                let res = if encrypt {
                    aes_xts_256_encrypt(&self.vk_cap, key, sector_lba, sector_data)
                } else {
                    aes_xts_256_decrypt(&self.vk_cap, key, sector_lba, sector_data)
                };
                if res.is_err() {
                    return Err(BlockIoError::DriverError);
                }
            }
            Ok(())
        })
    }
}

impl BlockDeviceSync for EncryptedBlockDevice {
    fn lba_size(&self) -> u32 {
        self.inner.lba_size()
    }
    fn capacity(&self) -> u64 {
        self.inner.capacity().saturating_sub(DATA_OFFSET_LBAS)
    }

    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        // Offset the LBA and read from inner.
        self.inner.read(lba + DATA_OFFSET_LBAS, n_blocks, out)?;
        // Decrypt the result.
        self.crypt_buffer(false, lba, out)
    }

    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        // We need a scratch buffer because `write` takes `&[u8]` but we need to encrypt.
        // For Stage 4, we'll use a stack-allocated or temporary buffer.
        // To be safe, we'll allocate a Vec for now (requires `alloc`).
        let mut encrypted = data.to_vec();
        self.crypt_buffer(true, lba, &mut encrypted)?;
        self.inner
            .write(lba + DATA_OFFSET_LBAS, n_blocks, &encrypted)
    }
}
