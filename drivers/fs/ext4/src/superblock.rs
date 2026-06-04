//! ext4 superblock — strict-flavour contract.
//!
//! Re-exports the shared superblock decoder from `drivers/fs/ext2/`
//! (which already parses all ext4 fields: `s_blocks_count_hi`,
//! `s_desc_size`, the feature-flag triplet). Adds an ext4-specific
//! validator that REJECTS any superblock that doesn't carry the
//! `EXTENTS` incompat bit — ext4-by-feature-flag is the canonical
//! definition (see Linux `fs/ext4/super.c::ext4_fill_super` and the
//! `EXT4_FEATURE_INCOMPAT_*` mask there).
//!
//! References:
//! - Linux `fs/ext4/super.c::ext4_fill_super` — feature-flag check
//!   that classifies a volume as ext4 and refuses to mount otherwise.
//! - Linux `include/linux/ext4_fs.h::EXT4_FEATURE_INCOMPAT_EXTENTS`,
//!   `..._64BIT`, `..._FLEX_BG`.

pub use narf_drivers_fs_ext2::superblock::{
    compat, incompat, ro_compat, ExtFlavour, FeatureError, Superblock,
    EXT2_VALID_FS as EXT4_VALID_FS,
};

/// ext4-side errors when validating that a parsed superblock really
/// matches the ext4 contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ext4SuperblockError {
    /// Magic field wasn't 0xEF53. Not even an ext-family volume.
    BadMagic,
    /// `s_feature_incompat::EXTENTS` is clear — this is an ext2/3
    /// volume, not ext4. The sibling `narf-drivers-fs-ext2` crate
    /// handles those flavours.
    NotExt4Flavour,
    /// `s_feature_incompat` carries a bit the driver doesn't
    /// implement. Refuse the mount per the ext4 spec contract.
    UnsupportedIncompat(u32),
}

/// Validate that `buf` is an ext4 superblock — magic OK, EXTENTS
/// bit set, no unknown incompat features. Returns the decoded
/// superblock on success.
///
/// Mirrors the gating in Linux `fs/ext4/super.c::ext4_fill_super`:
/// magic check, feature-flag check, refuse if unknown incompat.
pub fn validate(buf: &[u8]) -> Result<Superblock, Ext4SuperblockError> {
    let sb = match Superblock::parse(buf) {
        Some(s) => s,
        None => return Err(Ext4SuperblockError::BadMagic),
    };
    // ext4-defining: must carry EXTENTS.
    if !sb.uses_extents() {
        return Err(Ext4SuperblockError::NotExt4Flavour);
    }
    if let Err(FeatureError::UnsupportedIncompat(unknown)) = sb.check_incompat_features() {
        return Err(Ext4SuperblockError::UnsupportedIncompat(unknown));
    }
    // Belt-and-braces: classification must agree with the
    // EXTENTS-bit check above (it can disagree only if EXTENTS is
    // clear AND another ext4-only bit is set — caller is mounting
    // a corrupt or half-converted volume).
    if sb.flavour() != ExtFlavour::Ext4 {
        return Err(Ext4SuperblockError::NotExt4Flavour);
    }
    Ok(sb)
}

/// True iff the volume reports the ext4 64BIT layout — group
/// descriptors are 64 bytes and `blocks_count_hi` is meaningful.
/// Linux `EXT4_FEATURE_INCOMPAT_64BIT`.
pub fn is_64bit(sb: &Superblock) -> bool {
    sb.feature_incompat & incompat::SIXTYFOURBIT != 0
}

/// True iff the volume reports FLEX_BG — group descriptor tables
/// for adjacent block groups are colocated in the same flex group's
/// first BG. Cosmetic for the read path; the BGDT decoder still
/// works either way. Linux `EXT4_FEATURE_INCOMPAT_FLEX_BG`.
pub fn is_flex_bg(sb: &Superblock) -> bool {
    sb.feature_incompat & incompat::FLEX_BG != 0
}
