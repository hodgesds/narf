//! Image writer and the verify-before-any-execute reader
//! (power-suspend design §3.3, §6.2).
//!
//! The reader is a typestate pipeline that structurally enforces the
//! design's trust order — no API yields image plaintext before the
//! whole image has verified:
//!
//! 1. [`parse_claims`] reads the header preamble into
//!    [`ImageClaims`]: untrusted hints used only to select a factor
//!    and drive its interaction.
//! 2. [`open_with_sms`] unwraps the SMK with the epoch's SMS and
//!    verifies the header seal (which authenticates the preamble,
//!    policy record included) → [`OpenedImage`]. Plaintext is still
//!    unreachable: `OpenedImage` has no chunk-reading method.
//! 3. [`OpenedImage::verify_all`] checks the manifest root against
//!    the sealed header, then AEAD-opens every chunk into scratch →
//!    [`TrustedImage`].
//! 4. Only [`TrustedImage::read_chunk`] delivers plaintext, and it
//!    re-opens that chunk's AEAD at delivery time (with the tag
//!    re-read from the manifest), so a store mutated between verify
//!    and delivery still fails closed.
//!
//! The writer commits the header page *last*: a torn write leaves a
//! header whose seal cannot verify, which the reader refuses — never
//! a half-valid image.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract};
use zeroize::Zeroizing;

use super::custody::Secret32;
use super::format::{
    self, ImageClaims, ImageStore, PolicyLevel, RecordedPolicy, SealedBody, CHUNK_LEN,
    FORMAT_VERSION, IMAGE_MAGIC, PAGE_LEN, SEALED_BODY_LEN, SEALED_BODY_STORED, TAG_LEN,
    WRAPPED_SMK_LEN,
};
use super::slots::{read_records_from, write_records, Cursor, SlotRecord};
use super::ServiceError;

const INFO_SLOT_EPOCH: &[u8] = b"narf-suspend/slot-epoch";
const INFO_IMAGE_KEY: &[u8] = b"narf-suspend/image";
const INFO_MANIFEST_KEY: &[u8] = b"narf-suspend/manifest";
const INFO_HOOK: &[u8] = b"narf-suspend/hook/";
const INFO_HOOK_ANCHOR: &[u8] = b"narf-suspend/hook-anchor/";

/// HKDF-SHA256 (extract + expand to 32 bytes) — the hierarchy's one
/// derivation primitive (design §3.1: leaves are HKDF outputs, never
/// ad-hoc hashes of secrets).
pub(crate) fn derive32(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let prk = hkdf_extract(None, ikm);
    let okm = hkdf_expand(&prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Zeroizing::new(out)
}

/// The per-epoch wrapping key for the SMK wrap:
/// `HKDF(SMS, "narf-suspend/slot-epoch" ‖ epoch)`. Because the epoch
/// is in the info string, one epoch's SMS material can never unwrap
/// another epoch's image keys — the wrong-epoch negative the fixtures
/// pin.
fn slot_epoch_key(sms: &Secret32, epoch: u64) -> Zeroizing<[u8; 32]> {
    sms.with_bytes(|sms| {
        let mut info = Vec::with_capacity(INFO_SLOT_EPOCH.len() + 8);
        info.extend_from_slice(INFO_SLOT_EPOCH);
        info.extend_from_slice(&epoch.to_le_bytes());
        derive32(sms, &info)
    })
}

fn image_key(smk: &Secret32) -> Zeroizing<[u8; 32]> {
    smk.with_bytes(|smk| derive32(smk, INFO_IMAGE_KEY))
}

fn manifest_key(smk: &Secret32) -> Zeroizing<[u8; 32]> {
    smk.with_bytes(|smk| derive32(smk, INFO_MANIFEST_KEY))
}

/// P2 seam (design §3.4): derive a hook's seal key from the image
/// key hierarchy — `HKDF(SMK, "narf-suspend/hook/" ‖ name)`. P2's
/// hook directory writer/reader consumes this; this lane defines the
/// derivation so hook blobs written later sit inside the image's
/// AEAD perimeter from the start.
pub fn derive_hook_key(smk: &Secret32, name: &str) -> Zeroizing<[u8; 32]> {
    smk.with_bytes(|smk| {
        let mut info = Vec::with_capacity(INFO_HOOK.len() + name.len());
        info.extend_from_slice(INFO_HOOK);
        info.extend_from_slice(name.as_bytes());
        derive32(smk, &info)
    })
}

/// P2 seam (design §3.4): derive a hook's key from the *SMS* for
/// anchor hooks, whose blobs are sealed before the SMK exists —
/// `HKDF(SMS, "narf-suspend/hook-anchor/" ‖ name)`.
pub fn derive_hook_anchor_key(sms: &Secret32, name: &str) -> Zeroizing<[u8; 32]> {
    sms.with_bytes(|sms| {
        let mut info = Vec::with_capacity(INFO_HOOK_ANCHOR.len() + name.len());
        info.extend_from_slice(INFO_HOOK_ANCHOR);
        info.extend_from_slice(name.as_bytes());
        derive32(sms, &info)
    })
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Everything the writer needs, assembled by the service (which owns
/// entropy and custody); the writer itself draws no randomness.
pub(crate) struct WriteRequest<'a> {
    pub policy: RecordedPolicy,
    pub sms: &'a Secret32,
    pub sms_epoch: u64,
    pub slots: &'a [SlotRecord],
    pub smk: &'a Secret32,
    pub image_id: [u8; 16],
    pub smk_wrap_nonce: [u8; 12],
    pub image: &'a [u8],
    /// Encoded hook region (P2, design §5): already AEAD-sealed
    /// blobs from the seal fan-out, written between the manifest
    /// and the chunks; its length is recorded in the sealed body,
    /// so the region's extent is authenticated even though the
    /// blobs authenticate themselves individually. Empty for a
    /// hookless seal (the P1 behaviour, byte for byte).
    pub hook_region: &'a [u8],
}

/// Seal `image` into `store` per the format. Chunks and manifest are
/// written first and the header page last (the commit point — see
/// the module docs).
pub(crate) fn write_image(
    store: &mut dyn ImageStore,
    req: &WriteRequest<'_>,
) -> Result<(), ServiceError> {
    let image_len = req.image.len() as u64;
    if image_len == 0 {
        return Err(ServiceError::EmptyImage);
    }
    let hook_region_len = req.hook_region.len() as u64;
    if format::image_total_len(image_len, hook_region_len) > store.len_bytes() {
        return Err(ServiceError::ImageTooLarge);
    }
    let chunk_count = image_len.div_ceil(CHUNK_LEN);
    let img_key = image_key(req.smk);
    let man_key = manifest_key(req.smk);

    // Chunks first: AEAD each under the image key, collecting tags.
    let mut tags: Vec<[u8; TAG_LEN]> = Vec::with_capacity(chunk_count as usize);
    for index in 0..chunk_count {
        let start = (index * CHUNK_LEN) as usize;
        let end = core::cmp::min(start + CHUNK_LEN as usize, req.image.len());
        let mut buf = req.image[start..end].to_vec();
        let tag = chacha20_poly1305_seal(
            &img_key,
            &format::chunk_nonce(index),
            &format::chunk_aad(&req.image_id, index),
            &mut buf,
        );
        store.write_all(
            format::chunk_offset(chunk_count, hook_region_len, index),
            &buf,
        )?;
        tags.push(tag);
    }

    // Manifest: the tags, page-padded.
    let root = format::manifest_root(&tags);
    let manifest_bytes = chunk_count * TAG_LEN as u64;
    let manifest_padded = manifest_bytes.div_ceil(PAGE_LEN) * PAGE_LEN;
    let mut manifest = vec![0u8; manifest_padded as usize];
    for (i, tag) in tags.iter().enumerate() {
        manifest[i * TAG_LEN..(i + 1) * TAG_LEN].copy_from_slice(tag);
    }
    store.write_all(format::manifest_offset(), &manifest)?;

    // Hook region: the seal fan-out's blobs, between manifest and
    // chunks (design §3.3 layout). Written before the header like
    // everything else; an interrupted write simply never commits.
    if hook_region_len > 0 {
        store.write_all(format::hook_offset(chunk_count), req.hook_region)?;
    }

    // Preamble: plaintext claims, then the wrapped SMK.
    let mut preamble = Vec::new();
    preamble.extend_from_slice(IMAGE_MAGIC);
    preamble.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    preamble.extend_from_slice(&req.image_id);
    preamble.extend_from_slice(&req.sms_epoch.to_le_bytes());
    preamble.push(req.policy.level.code());
    preamble.extend_from_slice(&req.policy.policy_epoch.to_le_bytes());
    write_records(req.slots, &mut preamble);
    preamble.extend_from_slice(&req.smk_wrap_nonce);
    let wrap_key = slot_epoch_key(req.sms, req.sms_epoch);
    let smk_aad = format::smk_wrap_aad(&req.image_id, req.sms_epoch, req.policy.level);
    let mut smk_ct = Zeroizing::new([0u8; 32]);
    req.smk.with_bytes(|smk| smk_ct.copy_from_slice(smk));
    let smk_tag = chacha20_poly1305_seal(&wrap_key, &req.smk_wrap_nonce, &smk_aad, &mut *smk_ct);
    preamble.extend_from_slice(&*smk_ct);
    preamble.extend_from_slice(&smk_tag);

    if preamble.len() as u64 + SEALED_BODY_STORED > PAGE_LEN {
        return Err(ServiceError::Malformed);
    }

    // Sealed body under the manifest key, AAD = the whole preamble:
    // this is what makes the recorded policy (and every other claim)
    // authenticated rather than believed.
    let mut body = [0u8; SEALED_BODY_LEN];
    body[0..8].copy_from_slice(&chunk_count.to_le_bytes());
    body[8..16].copy_from_slice(&image_len.to_le_bytes());
    body[16..24].copy_from_slice(&hook_region_len.to_le_bytes());
    body[24..56].copy_from_slice(&root);
    let body_tag = chacha20_poly1305_seal(
        &man_key,
        &format::header_nonce(&req.image_id),
        &preamble,
        &mut body,
    );

    // Header page last: the commit point.
    let mut page = vec![0u8; PAGE_LEN as usize];
    page[..preamble.len()].copy_from_slice(&preamble);
    let body_at = (PAGE_LEN - SEALED_BODY_STORED) as usize;
    page[body_at..body_at + SEALED_BODY_LEN].copy_from_slice(&body);
    page[body_at + SEALED_BODY_LEN..].copy_from_slice(&body_tag);
    store.write_all(0, &page)?;
    store.flush()
}

/// Step 1 of the trust order: parse the header preamble into
/// untrusted claims. Only structural facts are established here
/// (magic, version, lengths); nothing is believed yet.
pub fn parse_claims(store: &dyn ImageStore) -> Result<ImageClaims, ServiceError> {
    if store.len_bytes() < PAGE_LEN {
        return Err(ServiceError::Truncated);
    }
    let mut page = vec![0u8; PAGE_LEN as usize];
    store.read_exact(0, &mut page)?;
    let mut cur = Cursor::new(&page);
    if cur.take(8)? != IMAGE_MAGIC {
        return Err(ServiceError::BadMagic);
    }
    let version = cur.u32()?;
    if version != FORMAT_VERSION {
        return Err(ServiceError::BadVersion);
    }
    let image_id = cur.array::<16>()?;
    let sms_epoch = cur.u64()?;
    let level = PolicyLevel::from_code(cur.u8()?).ok_or(ServiceError::Malformed)?;
    let policy_epoch = cur.u64()?;
    let slots = read_records_from(&mut cur)?;
    for record in &slots {
        if record.epoch != sms_epoch {
            return Err(ServiceError::Malformed);
        }
    }
    let smk_wrap_nonce = cur.array::<12>()?;
    let smk_wrap = cur.array::<WRAPPED_SMK_LEN>()?;
    let preamble_len = page.len() - cur.remaining();
    Ok(ImageClaims {
        image_id,
        sms_epoch,
        policy: RecordedPolicy {
            level,
            policy_epoch,
        },
        slots,
        smk_wrap_nonce,
        smk_wrap,
        preamble: page[..preamble_len].to_vec(),
    })
}

/// Step 2–3 of the trust order: unwrap the SMK under `sms` and verify
/// the header seal. On success the claims are authenticated (policy
/// included); image plaintext is still unreachable from the result.
pub fn open_with_sms(
    store: &dyn ImageStore,
    claims: ImageClaims,
    sms: &Secret32,
) -> Result<OpenedImage, ServiceError> {
    // Unwrap the SMK. Failure here is indistinguishable between a
    // wrong SMS, a wrong epoch, and a tampered wrap: one error.
    let wrap_key = slot_epoch_key(sms, claims.sms_epoch);
    let aad = format::smk_wrap_aad(&claims.image_id, claims.sms_epoch, claims.policy.level);
    let mut smk_buf = Zeroizing::new([0u8; 32]);
    smk_buf.copy_from_slice(&claims.smk_wrap[..32]);
    let mut smk_tag = [0u8; TAG_LEN];
    smk_tag.copy_from_slice(&claims.smk_wrap[32..]);
    if !chacha20_poly1305_open(
        &wrap_key,
        &claims.smk_wrap_nonce,
        &aad,
        &mut *smk_buf,
        &smk_tag,
    ) {
        return Err(ServiceError::AuthenticationFailed);
    }
    let smk = Secret32::mint(*smk_buf);

    let man_key = manifest_key(&smk);
    let img_key = image_key(&smk);

    // Verify the header seal: opens the sealed body and thereby
    // authenticates the entire preamble (AAD), policy included.
    let mut stored = [0u8; SEALED_BODY_LEN + TAG_LEN];
    store.read_exact(PAGE_LEN - SEALED_BODY_STORED, &mut stored)?;
    let (body_ct, body_tag) = stored.split_at(SEALED_BODY_LEN);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(body_tag);
    let mut body = [0u8; SEALED_BODY_LEN];
    body.copy_from_slice(body_ct);
    if !chacha20_poly1305_open(
        &man_key,
        &format::header_nonce(&claims.image_id),
        &claims.preamble,
        &mut body,
        &tag,
    ) {
        return Err(ServiceError::AuthenticationFailed);
    }
    let body = SealedBody {
        chunk_count: u64::from_le_bytes(body[0..8].try_into().unwrap()),
        image_len: u64::from_le_bytes(body[8..16].try_into().unwrap()),
        hook_region_len: u64::from_le_bytes(body[16..24].try_into().unwrap()),
        manifest_root: body[24..56].try_into().unwrap(),
    };
    if body.image_len == 0
        || body.chunk_count != body.image_len.div_ceil(CHUNK_LEN)
        || format::image_total_len(body.image_len, body.hook_region_len) > store.len_bytes()
    {
        return Err(ServiceError::Truncated);
    }
    Ok(OpenedImage {
        claims,
        body,
        smk,
        image_key: img_key,
    })
}

/// An image whose header seal verified under the epoch's SMS. The
/// recorded policy in [`OpenedImage::claims`] is now authenticated.
/// Chunk plaintext remains unreachable until
/// [`OpenedImage::verify_all`].
pub struct OpenedImage {
    claims: ImageClaims,
    body: SealedBody,
    smk: Secret32,
    image_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for OpenedImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedImage")
            .field("sms_epoch", &self.claims.sms_epoch)
            .field("policy", &self.claims.policy)
            .field("image_len", &self.body.image_len)
            .field("chunk_count", &self.body.chunk_count)
            .finish_non_exhaustive()
    }
}

impl OpenedImage {
    /// The authenticated header claims (policy record included).
    pub fn claims(&self) -> &ImageClaims {
        &self.claims
    }

    /// Plaintext length of the image.
    pub fn image_len(&self) -> u64 {
        self.body.image_len
    }

    /// Number of AEAD chunks.
    pub fn chunk_count(&self) -> u64 {
        self.body.chunk_count
    }

    /// Length of the hook region (P2 seam: nonzero once hook blobs
    /// are written; the reader already bounds-checks it).
    pub fn hook_region_len(&self) -> u64 {
        self.body.hook_region_len
    }

    /// P2 seam: derive a named hook's seal key from this image's SMK
    /// without exposing the SMK itself (see [`derive_hook_key`]).
    pub fn hook_key(&self, name: &str) -> Zeroizing<[u8; 32]> {
        derive_hook_key(&self.smk, name)
    }

    fn read_manifest(&self, store: &dyn ImageStore) -> Result<Vec<[u8; TAG_LEN]>, ServiceError> {
        let bytes = (self.body.chunk_count * TAG_LEN as u64) as usize;
        let mut raw = vec![0u8; bytes];
        store.read_exact(format::manifest_offset(), &mut raw)?;
        let mut tags = Vec::with_capacity(self.body.chunk_count as usize);
        for chunk in raw.chunks_exact(TAG_LEN) {
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(chunk);
            tags.push(tag);
        }
        Ok(tags)
    }

    fn open_chunk(
        &self,
        store: &dyn ImageStore,
        tags: &[[u8; TAG_LEN]],
        index: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        let len = if index + 1 == self.body.chunk_count {
            self.body.image_len - index * CHUNK_LEN
        } else {
            CHUNK_LEN
        };
        let mut buf = vec![0u8; len as usize];
        store.read_exact(
            format::chunk_offset(self.body.chunk_count, self.body.hook_region_len, index),
            &mut buf,
        )?;
        if !chacha20_poly1305_open(
            &self.image_key,
            &format::chunk_nonce(index),
            &format::chunk_aad(&self.claims.image_id, index),
            &mut buf,
            &tags[index as usize],
        ) {
            return Err(ServiceError::AuthenticationFailed);
        }
        Ok(buf)
    }

    /// Step 4 of the trust order: verify the manifest root against
    /// the sealed header, then AEAD-open *every* chunk (into scratch,
    /// discarded). Only the [`TrustedImage`] this returns can deliver
    /// plaintext. Consumes `self`: there is no path from an unverified
    /// opened image to chunk data.
    pub fn verify_all(self, store: &dyn ImageStore) -> Result<TrustedImage, ServiceError> {
        let tags = self.read_manifest(store)?;
        let root = format::manifest_root(&tags);
        if !ct_eq(&root, &self.body.manifest_root) {
            return Err(ServiceError::AuthenticationFailed);
        }
        for index in 0..self.body.chunk_count {
            // Plaintext is verified then discarded; delivery happens
            // per chunk on TrustedImage, re-opening at that time.
            let _verified = self.open_chunk(store, &tags, index)?;
        }
        Ok(TrustedImage { opened: self })
    }
}

/// A fully verified image: header seal, manifest root, and every
/// chunk's AEAD tag checked. The only type that yields plaintext.
pub struct TrustedImage {
    opened: OpenedImage,
}

impl fmt::Debug for TrustedImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedImage")
            .field("sms_epoch", &self.opened.claims.sms_epoch)
            .field("policy", &self.opened.claims.policy)
            .field("image_len", &self.opened.body.image_len)
            .finish_non_exhaustive()
    }
}

impl TrustedImage {
    /// The authenticated header claims (policy record included).
    pub fn claims(&self) -> &ImageClaims {
        self.opened.claims()
    }

    /// P2 seam: derive a named hook's seal key from this image's SMK
    /// (see [`OpenedImage::hook_key`]).
    pub fn hook_key(&self, name: &str) -> Zeroizing<[u8; 32]> {
        self.opened.hook_key(name)
    }

    /// Read the image's hook region (P2, design §5). The region's
    /// *length* is authenticated (it sits in the sealed header
    /// body), but the bytes returned here are not yet trusted: each
    /// blob inside authenticates itself when the unseal fan-out
    /// AEAD-opens it in staging, before any hook callback runs.
    /// Only a `TrustedImage` can read the region at all — the hook
    /// surface inherits the image's verify-before-execute order.
    pub fn read_hook_region(&self, store: &dyn ImageStore) -> Result<Vec<u8>, ServiceError> {
        let len = self.opened.body.hook_region_len;
        let mut out = vec![0u8; len as usize];
        if len > 0 {
            store.read_exact(format::hook_offset(self.opened.body.chunk_count), &mut out)?;
        }
        Ok(out)
    }

    /// Plaintext length of the image.
    pub fn image_len(&self) -> u64 {
        self.opened.body.image_len
    }

    /// Number of AEAD chunks.
    pub fn chunk_count(&self) -> u64 {
        self.opened.body.chunk_count
    }

    /// Read and authenticate chunk `index`, appending its plaintext
    /// to `out`. The tag is re-read from the manifest and the chunk
    /// re-opened at delivery time, so this fails closed even if the
    /// store changed after `verify_all`.
    pub fn read_chunk(
        &self,
        store: &dyn ImageStore,
        index: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), ServiceError> {
        if index >= self.opened.body.chunk_count {
            return Err(ServiceError::Malformed);
        }
        let tags = self.opened.read_manifest(store)?;
        let plain = self.opened.open_chunk(store, &tags, index)?;
        out.extend_from_slice(&plain);
        Ok(())
    }

    /// Reassemble the whole plaintext image (convenience over
    /// [`Self::read_chunk`]; the resume path pages chunks instead).
    pub fn read_all(&self, store: &dyn ImageStore) -> Result<Vec<u8>, ServiceError> {
        let mut out = Vec::with_capacity(self.opened.body.image_len as usize);
        for index in 0..self.opened.body.chunk_count {
            self.read_chunk(store, index, &mut out)?;
        }
        Ok(out)
    }
}
