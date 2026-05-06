//! Transparent block-level encryption (AES-256-XTS).
//!
//! Spec: `block/specification/encrypted.md`.

use alloc::sync::Arc;
use narf_capabilities::{Cap, Grant};
use narf_crypto::{aes_xts_256_decrypt, aes_xts_256_encrypt, AesXts256, Key};
use narf_tpm::TpmDevice;

use crate::registry::{BlockDeviceSync, BlockIoError};

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
    /// Raw Volume Key material.
    /// TODO: Stage 4/5: Secret should be restricted to DomainId::KEYS.
    vk_bytes: [u8; 64],
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
    pub async fn open(
        inner: Arc<dyn BlockDeviceSync>,
        _tpm: &dyn TpmDevice,
    ) -> Result<Self, BlockIoError> {
        // Placeholder: In a real system, we'd read LBA 0 and unseal the VK.
        let mut vk_bytes = [0u8; 64];
        vk_bytes[..32].copy_from_slice(b"NARF_ENCRYPTION_KEY_MATERIAL_001");
        vk_bytes[32..].copy_from_slice(b"NARF_ENCRYPTION_KEY_MATERIAL_002");

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

        for i in 0..blocks {
            let sector_lba = lba + i as u64;
            let sector_data = &mut data[i * block_size..(i + 1) * block_size];

            if encrypt {
                aes_xts_256_encrypt(&self.vk_cap, &self.vk_bytes, sector_lba, sector_data)
                    .map_err(|_| BlockIoError::DriverError)?;
            } else {
                aes_xts_256_decrypt(&self.vk_cap, &self.vk_bytes, sector_lba, sector_data)
                    .map_err(|_| BlockIoError::DriverError)?;
            }
        }
        Ok(())
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
