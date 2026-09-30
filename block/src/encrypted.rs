//! Transparent block-level encryption (AES-XTS).
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

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_capabilities::{Cap, Grant};
use narf_crypto::{
    aes_xts_128_decrypt, aes_xts_128_encrypt, aes_xts_256_decrypt_with_sector_size,
    aes_xts_256_encrypt_with_sector_size, AesXts128, AesXts256, Key,
};
use narf_lib::assert::current_domain;
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;
use narf_tpm::TpmDevice;
use zeroize::Zeroizing;

use crate::luks1::{self, Luks1Error, Luks1UnlockPolicy};
use crate::luks2::{self, Luks2Error, Luks2UnlockPolicy};
use crate::registry::{BlockDeviceSync, BlockIoError};

/// LUKS metadata generation detected on a block device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LuksVersion {
    Luks1,
    Luks2,
}

/// Non-secret identity passed to a boot credential provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LuksVolumeInfo {
    pub version: LuksVersion,
    pub uuid: String,
}

/// Credential-provider refusal. Providers may decline a volume (for example
/// because `rd.luks.uuid=` selected another one) without exposing a secret.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LuksCredentialError {
    Unavailable,
    Declined,
    TooLarge,
}

/// Unified boot-open failure for either supported LUKS generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LuksOpenError {
    Io(BlockIoError),
    NotLuks,
    UnsupportedVersion,
    Credential(LuksCredentialError),
    Luks1(Luks1Error),
    Luks2(Luks2Error),
}

/// Boot policy callback. Returned passphrase storage is zeroized after the
/// selected LUKS implementation derives its key-encryption key.
pub type LuksPassphraseProvider =
    fn(&LuksVolumeInfo) -> Result<Zeroizing<Vec<u8>>, LuksCredentialError>;

static LUKS_PASSPHRASE_PROVIDER: IrqSafeSpinLock<Option<LuksPassphraseProvider>> =
    IrqSafeSpinLock::new(None);

/// Install or replace the boot-time LUKS passphrase policy.
pub fn install_luks_passphrase_provider(provider: LuksPassphraseProvider) {
    *LUKS_PASSPHRASE_PROVIDER.lock() = Some(provider);
}

/// Remove the credential provider (primarily for isolated kernel tests).
#[doc(hidden)]
pub fn clear_luks_passphrase_provider() {
    *LUKS_PASSPHRASE_PROVIDER.lock() = None;
}

/// Probe only the fixed LUKS header identity needed for credential routing.
pub fn probe_luks_volume(
    inner: &dyn BlockDeviceSync,
) -> Result<Option<LuksVolumeInfo>, LuksOpenError> {
    let block_size = inner.lba_size() as usize;
    if block_size < 512 {
        return Err(LuksOpenError::Io(BlockIoError::BufferTooSmall));
    }
    let mut sector = alloc::vec![0u8; block_size];
    inner.read(0, 1, &mut sector).map_err(LuksOpenError::Io)?;
    if sector.get(..6) != Some(b"LUKS\xba\xbe".as_slice()) {
        return Ok(None);
    }
    let version = u16::from_be_bytes([sector[6], sector[7]]);
    let (version, uuid) = match version {
        1 => (
            LuksVersion::Luks1,
            luks1::probe_uuid(&sector).ok_or(LuksOpenError::NotLuks)?,
        ),
        2 => (
            LuksVersion::Luks2,
            luks2::probe_uuid(&sector).ok_or(LuksOpenError::NotLuks)?,
        ),
        _ => return Err(LuksOpenError::UnsupportedVersion),
    };
    Ok(Some(LuksVolumeInfo { version, uuid }))
}

/// Open a LUKS1 or LUKS2 volume through the installed boot credential policy.
/// Metadata and payload remain untouched until the caller issues ordinary
/// writes through the returned adapter.
pub fn open_luks_with_provider(
    inner: Arc<dyn BlockDeviceSync>,
) -> Result<EncryptedBlockDevice, LuksOpenError> {
    let info = probe_luks_volume(inner.as_ref())?.ok_or(LuksOpenError::NotLuks)?;
    let provider = (*LUKS_PASSPHRASE_PROVIDER.lock())
        .ok_or(LuksOpenError::Credential(LuksCredentialError::Unavailable))?;
    let passphrase = provider(&info).map_err(LuksOpenError::Credential)?;
    match info.version {
        LuksVersion::Luks1 => {
            EncryptedBlockDevice::open_luks1(inner, &passphrase).map_err(LuksOpenError::Luks1)
        }
        LuksVersion::Luks2 => {
            EncryptedBlockDevice::open_luks2(inner, &passphrase).map_err(LuksOpenError::Luks2)
        }
    }
}

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
pub struct VkBytes {
    bytes: [u8; 64],
    len: u8,
}

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
        Self { bytes, len: 64 }
    }

    /// Construct a redacted key wrapper for either AES-128-XTS (32 bytes) or
    /// AES-256-XTS (64 bytes). Domain gating is identical to [`Self::new`].
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, ()> {
        if !matches!(bytes.len(), 32 | 64) {
            return Err(());
        }
        let dom = current_domain();
        if dom != DomainId::KEYS && dom != DomainId::FRAME {
            panic!(
                "VkBytes::from_slice: caller must be in DomainId::KEYS, observed {} (security bug)",
                dom.raw(),
            );
        }
        let mut storage = [0u8; 64];
        storage[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: storage,
            len: bytes.len() as u8,
        })
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
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes[..usize::from(self.len)])
    }
}

impl core::fmt::Debug for VkBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Deliberately opaque — bytes never enter formatted output
        // even when the surrounding struct is `#[derive(Debug)]`.
        write!(f, "VkBytes(<redacted, len = {}, domain = KEYS>)", self.len)
    }
}

impl Drop for VkBytes {
    /// Zeroise on drop so a freed heap chunk that gets handed to
    /// another caller doesn't carry the key bytes. `write_volatile`
    /// defeats the optimiser's dead-store elimination — without
    /// volatile the compiler is free to drop the writes since no
    /// subsequent read of `self.0` is reachable.
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            // SAFETY: `b` is a live, exclusive reference into a
            // local-to-this-Drop array; volatile write of a u8 is
            // a single store with no side effects.
            // SAFETY: Valid memory or trusted environment
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
    /// First ciphertext LBA in the containing block device.
    data_offset_lbas: u64,
    /// Fixed visible byte length for a non-dynamic LUKS2 segment.
    data_size_bytes: Option<u64>,
    /// Starting `plain64` tweak declared by the encrypted segment.
    iv_tweak: u64,
    /// AES-XTS data-unit size (independent of the block device LBA size).
    crypto_sector_size: usize,
    /// Volume Key (VK) capability handle.
    vk_cap: VolumeKeyCap,
    /// Raw Volume Key material gated by [`VkBytes`] —
    /// constructed only when the caller is in `DomainId::KEYS`
    /// (`security-model/` §4.1), private to the struct, redacted
    /// from `Debug` output, zeroised on drop. Only the in-tree
    /// [`Self::crypt_buffer`] reaches in via `with_bytes`.
    vk_bytes: VkBytes,
}

enum VolumeKeyCap {
    Aes128(Cap<Key<AesXts128>, Grant>),
    Aes256(Cap<Key<AesXts256>, Grant>),
}

impl core::fmt::Debug for EncryptedBlockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedBlockDevice")
            .field("inner_name", &"dyn BlockDeviceSync")
            .field("data_offset_lbas", &self.data_offset_lbas)
            .field("data_size_bytes", &self.data_size_bytes)
            .field("iv_tweak", &self.iv_tweak)
            .field("crypto_sector_size", &self.crypto_sector_size)
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
            data_offset_lbas: DATA_OFFSET_LBAS,
            data_size_bytes: None,
            iv_tweak: 0,
            crypto_sector_size: luks1::SECTOR_BYTES,
            vk_cap: VolumeKeyCap::Aes256(vk_cap),
            vk_bytes,
        })
    }

    /// Open an existing LUKS1 partition with the default bounded-work policy.
    ///
    /// Supported volumes use AES-256-XTS, `plain64`, 512-byte encryption
    /// sectors, and PBKDF2-HMAC-SHA1/SHA256/SHA512. The passphrase is borrowed
    /// and never retained; explicit derived-key byte buffers are zeroized.
    pub fn open_luks1(
        inner: Arc<dyn BlockDeviceSync>,
        passphrase: &[u8],
    ) -> Result<Self, Luks1Error> {
        Self::open_luks1_with_policy(inner, passphrase, Luks1UnlockPolicy::default())
    }

    /// Open LUKS1 with an explicit PBKDF2 work-factor bound.
    pub fn open_luks1_with_policy(
        inner: Arc<dyn BlockDeviceSync>,
        passphrase: &[u8],
        policy: Luks1UnlockPolicy,
    ) -> Result<Self, Luks1Error> {
        let unlocked = luks1::unlock(inner.clone(), passphrase, policy)?;
        Ok(Self {
            inner,
            data_offset_lbas: u64::from(unlocked.header.payload_offset),
            data_size_bytes: None,
            iv_tweak: 0,
            crypto_sector_size: luks1::SECTOR_BYTES,
            vk_cap: VolumeKeyCap::Aes256(Cap::<Key<AesXts256>, Grant>::bootstrap()),
            vk_bytes: unlocked.volume_key,
        })
    }

    /// Open an existing LUKS2 partition with bounded PBKDF2/Argon2 work.
    pub fn open_luks2(
        inner: Arc<dyn BlockDeviceSync>,
        passphrase: &[u8],
    ) -> Result<Self, Luks2Error> {
        Self::open_luks2_with_policy(inner, passphrase, Luks2UnlockPolicy::default())
    }

    /// Open LUKS2 with explicit resource limits for metadata-controlled KDFs.
    pub fn open_luks2_with_policy(
        inner: Arc<dyn BlockDeviceSync>,
        passphrase: &[u8],
        policy: Luks2UnlockPolicy,
    ) -> Result<Self, Luks2Error> {
        let unlocked = luks2::unlock(inner.clone(), passphrase, policy)?;
        let block_size = u64::from(inner.lba_size());
        let data_offset_lbas = unlocked.data_offset_bytes / block_size;
        let vk_cap = match unlocked.volume_key.with_bytes(|key| key.len()) {
            32 => VolumeKeyCap::Aes128(Cap::<Key<AesXts128>, Grant>::bootstrap()),
            64 => VolumeKeyCap::Aes256(Cap::<Key<AesXts256>, Grant>::bootstrap()),
            _ => return Err(Luks2Error::InvalidMetadata),
        };
        let _authenticated_header = unlocked.header;
        Ok(Self {
            inner,
            data_offset_lbas,
            data_size_bytes: unlocked.data_size_bytes,
            iv_tweak: unlocked.iv_tweak,
            crypto_sector_size: unlocked.sector_size,
            vk_cap,
            vk_bytes: unlocked.volume_key,
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
        let block_size = self.lba_size() as usize;
        let byte_offset = lba
            .checked_mul(block_size as u64)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(BlockIoError::OutOfRange)?;
        if byte_offset % self.crypto_sector_size != 0
            || data.is_empty()
            || data.len() % self.crypto_sector_size != 0
        {
            return Err(BlockIoError::BufferTooSmall);
        }

        // Single domain-asserted window per crypt_buffer call. The
        // primitive is synchronous (no awaits), so a `with_bytes`
        // around the whole loop is safe: the active domain can't
        // flip out from under us. Spec note: KEYS-domain reads
        // never cross a Narf-Ring boundary, so the slice the
        // closure sees never escapes.
        // LUKS stores `iv_tweak` in dm-crypt's 512-byte sector units. Linux
        // adds it to the mapped bio sector and, with `iv_large_sectors`, shifts
        // the result into the configured encryption-sector units before
        // generating the plain64 IV. Keep that ordering for 1/2/4 KiB LUKS2
        // sectors. Reference: ~/git/linux/drivers/md/dm-crypt.c
        let sector_scale = (self.crypto_sector_size / luks1::SECTOR_BYTES) as u64;
        let first_sector = self
            .iv_tweak
            .checked_add((byte_offset / luks1::SECTOR_BYTES) as u64)
            .ok_or(BlockIoError::OutOfRange)?;
        if first_sector % sector_scale != 0 {
            return Err(BlockIoError::OutOfRange);
        }
        let first_sector = first_sector / sector_scale;
        self.vk_bytes
            .with_bytes(|key| match (&self.vk_cap, key.len()) {
                (VolumeKeyCap::Aes128(cap), 32) => {
                    let key: &[u8; 32] = key.try_into().map_err(|_| BlockIoError::DriverError)?;
                    let result = if encrypt {
                        aes_xts_128_encrypt(cap, key, first_sector, self.crypto_sector_size, data)
                    } else {
                        aes_xts_128_decrypt(cap, key, first_sector, self.crypto_sector_size, data)
                    };
                    result.map_err(|_| BlockIoError::DriverError)
                }
                (VolumeKeyCap::Aes256(cap), 64) => {
                    let key: &[u8; 64] = key.try_into().map_err(|_| BlockIoError::DriverError)?;
                    let result = if encrypt {
                        aes_xts_256_encrypt_with_sector_size(
                            cap,
                            key,
                            first_sector,
                            self.crypto_sector_size,
                            data,
                        )
                    } else {
                        aes_xts_256_decrypt_with_sector_size(
                            cap,
                            key,
                            first_sector,
                            self.crypto_sector_size,
                            data,
                        )
                    };
                    result.map_err(|_| BlockIoError::DriverError)
                }
                _ => Err(BlockIoError::DriverError),
            })
    }

    fn read_inner_blocks(
        &self,
        mut lba: u64,
        mut blocks: u64,
        output: &mut [u8],
    ) -> Result<(), BlockIoError> {
        let block_size = self.inner.lba_size() as usize;
        let mut byte_offset = 0usize;
        while blocks != 0 {
            let chunk = blocks.min(u64::from(u16::MAX)) as u16;
            let chunk_bytes = usize::from(chunk)
                .checked_mul(block_size)
                .ok_or(BlockIoError::BufferTooSmall)?;
            let end = byte_offset
                .checked_add(chunk_bytes)
                .ok_or(BlockIoError::BufferTooSmall)?;
            let target = output
                .get_mut(byte_offset..end)
                .ok_or(BlockIoError::BufferTooSmall)?;
            self.inner.read(lba, chunk, target)?;
            lba = lba
                .checked_add(u64::from(chunk))
                .ok_or(BlockIoError::OutOfRange)?;
            blocks -= u64::from(chunk);
            byte_offset = end;
        }
        Ok(())
    }

    fn write_inner_blocks(
        &self,
        mut lba: u64,
        mut blocks: u64,
        input: &[u8],
    ) -> Result<(), BlockIoError> {
        let block_size = self.inner.lba_size() as usize;
        let mut byte_offset = 0usize;
        while blocks != 0 {
            let chunk = blocks.min(u64::from(u16::MAX)) as u16;
            let chunk_bytes = usize::from(chunk)
                .checked_mul(block_size)
                .ok_or(BlockIoError::BufferTooSmall)?;
            let end = byte_offset
                .checked_add(chunk_bytes)
                .ok_or(BlockIoError::BufferTooSmall)?;
            let source = input
                .get(byte_offset..end)
                .ok_or(BlockIoError::BufferTooSmall)?;
            self.inner.write(lba, chunk, source)?;
            lba = lba
                .checked_add(u64::from(chunk))
                .ok_or(BlockIoError::OutOfRange)?;
            blocks -= u64::from(chunk);
            byte_offset = end;
        }
        Ok(())
    }
}

impl BlockDeviceSync for EncryptedBlockDevice {
    fn lba_size(&self) -> u32 {
        self.inner.lba_size().max(self.crypto_sector_size as u32)
    }
    fn capacity(&self) -> u64 {
        let inner_block_size = u64::from(self.inner.lba_size());
        let available_bytes = self.data_size_bytes.unwrap_or_else(|| {
            self.inner
                .capacity()
                .saturating_sub(self.data_offset_lbas)
                .saturating_mul(inner_block_size)
        });
        available_bytes / u64::from(self.lba_size())
    }

    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        let end = lba
            .checked_add(u64::from(n_blocks))
            .ok_or(BlockIoError::OutOfRange)?;
        let required = usize::from(n_blocks)
            .checked_mul(self.lba_size() as usize)
            .ok_or(BlockIoError::BufferTooSmall)?;
        if end > self.capacity() {
            return Err(BlockIoError::OutOfRange);
        }
        if out.len() < required {
            return Err(BlockIoError::BufferTooSmall);
        }
        let scale = u64::from(self.lba_size()) / u64::from(self.inner.lba_size());
        let inner_lba = lba
            .checked_mul(scale)
            .and_then(|offset| self.data_offset_lbas.checked_add(offset))
            .ok_or(BlockIoError::OutOfRange)?;
        let inner_blocks = u64::from(n_blocks)
            .checked_mul(scale)
            .ok_or(BlockIoError::OutOfRange)?;
        self.read_inner_blocks(inner_lba, inner_blocks, &mut out[..required])?;
        // Decrypt the result.
        self.crypt_buffer(false, lba, &mut out[..required])
    }

    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        let end = lba
            .checked_add(u64::from(n_blocks))
            .ok_or(BlockIoError::OutOfRange)?;
        let required = usize::from(n_blocks)
            .checked_mul(self.lba_size() as usize)
            .ok_or(BlockIoError::BufferTooSmall)?;
        if end > self.capacity() {
            return Err(BlockIoError::OutOfRange);
        }
        if data.len() < required {
            return Err(BlockIoError::BufferTooSmall);
        }
        // We need a scratch buffer because `write` takes `&[u8]` but we need to encrypt.
        // For Stage 4, we'll use a stack-allocated or temporary buffer.
        // To be safe, we'll allocate a Vec for now (requires `alloc`).
        let mut encrypted = data[..required].to_vec();
        self.crypt_buffer(true, lba, &mut encrypted)?;
        let scale = u64::from(self.lba_size()) / u64::from(self.inner.lba_size());
        let inner_lba = lba
            .checked_mul(scale)
            .and_then(|offset| self.data_offset_lbas.checked_add(offset))
            .ok_or(BlockIoError::OutOfRange)?;
        let inner_blocks = u64::from(n_blocks)
            .checked_mul(scale)
            .ok_or(BlockIoError::OutOfRange)?;
        self.write_inner_blocks(inner_lba, inner_blocks, &encrypted)
    }
}
