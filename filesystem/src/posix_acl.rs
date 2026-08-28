//! POSIX.1e draft-17 Access Control Lists.
//!
//! A faithful port of Linux 7.0.0-rc7 `fs/posix_acl.c` plus the uapi
//! encoding from `include/uapi/linux/posix_acl.h` and
//! `include/uapi/linux/posix_acl_xattr.h`. The entry points are:
//!
//! * [`PosixAcl::from_xattr`] / [`PosixAcl::to_xattr`] — the on-the-wire
//!   `system.posix_acl_access` / `system.posix_acl_default` encoding
//!   (`posix_acl_from_xattr` / `posix_acl_to_xattr`).
//! * [`PosixAcl::valid`] — `posix_acl_valid`.
//! * [`PosixAcl::from_mode`] / [`PosixAcl::equiv_mode`] — the mode-bit
//!   bridge (`posix_acl_from_mode` / `posix_acl_equiv_mode`).
//! * [`posix_acl_permission`] — the access algebra
//!   (`fs/posix_acl.c::posix_acl_permission`), consumed by
//!   [`crate::posix_access_ok_with_acl`].
//! * [`PosixAcl::create_masq`] / [`PosixAcl::chmod_masq`] /
//!   [`posix_acl_create`] / [`posix_acl_update_mode`] — the
//!   mode↔ACL coherence rules.
//!
//! What NARF cannot express, stated once here rather than repeated at
//! every call site:
//!
//! LINUX-GAP (idmapped mounts): Linux runs every uid/gid in this file
//! through `make_vfsuid`/`i_uid_into_vfsuid` so an idmapped mount can
//! shift ownership per-mount. NARF has no `mnt_idmap`, so every
//! comparison here is against the raw filesystem id — equivalent to
//! Linux on a non-idmapped mount (`nop_mnt_idmap`), which is every mount
//! NARF creates today.
//!
//! LINUX-GAP (user namespaces): `posix_acl_valid` additionally requires
//! `kuid_has_mapping(user_ns, e_uid)`, and `posix_acl_from_xattr` maps
//! raw ids through `make_kuid(userns, ...)`. Both are the identity in the
//! initial user namespace, which is the only namespace an ACL is decoded
//! in here; [`PosixAcl::from_xattr`] keeps the one part that is *not*
//! identity — rejecting `ACL_UNDEFINED_ID` as a `ACL_USER`/`ACL_GROUP`
//! id, which is what `uid_valid()` catches in Linux.

use alloc::vec::Vec;

use narf_block::BlockError;

use crate::{Accessor, FileOwner, FsError};

// ── uapi constants (include/uapi/linux/posix_acl.h) ────────────────

/// `ACL_UNDEFINED_ID` — `(-1)` widened to the `__le32 e_id` field.
pub const ACL_UNDEFINED_ID: u32 = u32::MAX;

/// `e_tag` values. The numeric order is also the order
/// `posix_acl_valid` requires entries to appear in.
pub const ACL_USER_OBJ: u16 = 0x01;
/// A named user entry; `e_id` is the uid.
pub const ACL_USER: u16 = 0x02;
/// The owning group's entry.
pub const ACL_GROUP_OBJ: u16 = 0x04;
/// A named group entry; `e_id` is the gid.
pub const ACL_GROUP: u16 = 0x08;
/// The mask that caps every entry except `ACL_USER_OBJ` and `ACL_OTHER`.
pub const ACL_MASK: u16 = 0x10;
/// The catch-all entry.
pub const ACL_OTHER: u16 = 0x20;

/// `e_perm` bits.
pub const ACL_READ: u16 = 0x04;
pub const ACL_WRITE: u16 = 0x02;
pub const ACL_EXECUTE: u16 = 0x01;

/// `POSIX_ACL_XATTR_VERSION` — the only `a_version` Linux accepts;
/// anything else is `-EOPNOTSUPP` (`posix_acl_fix_xattr_common`).
pub const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;

/// `XATTR_NAME_POSIX_ACL_ACCESS` (include/uapi/linux/xattr.h).
pub const XATTR_NAME_POSIX_ACL_ACCESS: &str = "system.posix_acl_access";
/// `XATTR_NAME_POSIX_ACL_DEFAULT` (include/uapi/linux/xattr.h).
pub const XATTR_NAME_POSIX_ACL_DEFAULT: &str = "system.posix_acl_default";

/// `sizeof(struct posix_acl_xattr_header)`.
const XATTR_HEADER_LEN: usize = 4;
/// `sizeof(struct posix_acl_xattr_entry)` — `__le16 e_tag`,
/// `__le16 e_perm`, `__le32 e_id`.
const XATTR_ENTRY_LEN: usize = 8;

/// Which of an inode's two ACLs is meant.
///
/// Mirrors `ACL_TYPE_ACCESS` / `ACL_TYPE_DEFAULT`; the numeric values are
/// not part of NARF's ABI, so this is a plain enum rather than the raw
/// `0x8000`/`0x4000` constants.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AclType {
    /// `system.posix_acl_access` — governs access to this inode.
    Access,
    /// `system.posix_acl_default` — a directory's template for children.
    /// Meaningless on a non-directory (`set_posix_acl` returns `-EACCES`).
    Default,
}

impl AclType {
    /// `posix_acl_xattr_name()` (include/linux/posix_acl_xattr.h).
    pub fn xattr_name(self) -> &'static str {
        match self {
            AclType::Access => XATTR_NAME_POSIX_ACL_ACCESS,
            AclType::Default => XATTR_NAME_POSIX_ACL_DEFAULT,
        }
    }

    /// `posix_acl_type()` — recognise an xattr name, or `None`.
    pub fn from_xattr_name(name: &str) -> Option<Self> {
        match name {
            XATTR_NAME_POSIX_ACL_ACCESS => Some(AclType::Access),
            XATTR_NAME_POSIX_ACL_DEFAULT => Some(AclType::Default),
            _ => None,
        }
    }
}

/// One `struct posix_acl_entry`.
///
/// `id` is only meaningful for [`ACL_USER`] (a uid) and [`ACL_GROUP`] (a
/// gid); for every other tag Linux leaves the union unset and writes
/// [`ACL_UNDEFINED_ID`] back out, which is what the decoder here
/// normalises to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AclEntry {
    pub tag: u16,
    /// `ACL_READ | ACL_WRITE | ACL_EXECUTE`.
    pub perm: u16,
    pub id: u32,
}

impl AclEntry {
    /// An entry for a tag that carries no id.
    pub const fn tagged(tag: u16, perm: u16) -> Self {
        AclEntry {
            tag,
            perm,
            id: ACL_UNDEFINED_ID,
        }
    }

    /// A named-user or named-group entry.
    pub const fn with_id(tag: u16, id: u32, perm: u16) -> Self {
        AclEntry { tag, perm, id }
    }
}

/// `struct posix_acl` — an ordered list of entries.
///
/// Order is load-bearing twice over: [`PosixAcl::valid`] enforces the
/// USER_OBJ → USER* → GROUP_OBJ → GROUP* → MASK → OTHER sequence, and
/// [`posix_acl_permission`] finds the mask by scanning *forward* from the
/// matched entry, so a mask placed before its subject silently stops
/// limiting it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PosixAcl {
    pub entries: Vec<AclEntry>,
}

impl PosixAcl {
    /// An ACL with no entries. Not a valid ACL — `posix_acl_valid`
    /// rejects it, because the state machine never reaches state 0.
    pub const fn new() -> Self {
        PosixAcl {
            entries: Vec::new(),
        }
    }

    pub fn from_entries(entries: Vec<AclEntry>) -> Self {
        PosixAcl { entries }
    }

    /// `posix_acl_from_mode()` — the three-entry ACL exactly equivalent to
    /// a mode word.
    pub fn from_mode(mode: u16) -> Self {
        PosixAcl {
            entries: alloc::vec![
                AclEntry::tagged(ACL_USER_OBJ, (mode & 0o700) >> 6),
                AclEntry::tagged(ACL_GROUP_OBJ, (mode & 0o070) >> 3),
                AclEntry::tagged(ACL_OTHER, mode & 0o007),
            ],
        }
    }

    /// Serialised length, `posix_acl_xattr_size()`.
    pub fn xattr_size(&self) -> usize {
        XATTR_HEADER_LEN + self.entries.len() * XATTR_ENTRY_LEN
    }

    /// `posix_acl_to_xattr()` — little-endian header + entries.
    ///
    /// Every tag other than `ACL_USER`/`ACL_GROUP` is written with
    /// `e_id == ACL_UNDEFINED_ID`, matching the `default:` arm of the
    /// switch in Linux.
    pub fn to_xattr(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.xattr_size());
        out.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.tag.to_le_bytes());
            out.extend_from_slice(&e.perm.to_le_bytes());
            let id = match e.tag {
                ACL_USER | ACL_GROUP => e.id,
                _ => ACL_UNDEFINED_ID,
            };
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    /// `posix_acl_from_xattr()` + `posix_acl_fix_xattr_common()`.
    ///
    /// `Ok(None)` is Linux's "valid header, zero entries" result — not an
    /// error, and not the same as an empty [`PosixAcl`]: it means the
    /// inode has no ACL at all.
    ///
    /// Errors follow Linux's:
    ///   * short buffer / ragged entry array → `InvalidData` (`-EINVAL`)
    ///   * `a_version != 2` → `Unsupported` (`-EOPNOTSUPP`)
    ///   * unknown tag, or an `ACL_USER`/`ACL_GROUP` whose id is
    ///     `ACL_UNDEFINED_ID` (`!uid_valid()`) → `InvalidData` (`-EINVAL`)
    pub fn from_xattr(value: &[u8]) -> Result<Option<PosixAcl>, FsError> {
        if value.len() < XATTR_HEADER_LEN {
            return Err(FsError::InvalidData);
        }
        let version = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
        if version != POSIX_ACL_XATTR_VERSION {
            return Err(FsError::Unsupported);
        }
        let body = &value[XATTR_HEADER_LEN..];
        if body.len() % XATTR_ENTRY_LEN != 0 {
            return Err(FsError::InvalidData);
        }
        let count = body.len() / XATTR_ENTRY_LEN;
        if count == 0 {
            return Ok(None);
        }
        let mut entries = Vec::with_capacity(count);
        for chunk in body.chunks_exact(XATTR_ENTRY_LEN) {
            let tag = u16::from_le_bytes([chunk[0], chunk[1]]);
            let perm = u16::from_le_bytes([chunk[2], chunk[3]]);
            let id = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            match tag {
                // Linux ignores e_id for these tags entirely; normalise so
                // a re-encode is byte-identical to what it would write.
                ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_MASK | ACL_OTHER => {
                    entries.push(AclEntry::tagged(tag, perm));
                }
                ACL_USER | ACL_GROUP => {
                    // `!uid_valid(make_kuid(userns, id))` — see the
                    // user-namespace LINUX-GAP in the module docs.
                    if id == ACL_UNDEFINED_ID {
                        return Err(FsError::InvalidData);
                    }
                    entries.push(AclEntry::with_id(tag, id, perm));
                }
                _ => return Err(FsError::InvalidData),
            }
        }
        Ok(Some(PosixAcl { entries }))
    }

    /// `posix_acl_valid()` — the ordering + completeness state machine.
    ///
    /// An ACL is valid when its entries appear in tag order
    /// `USER_OBJ, USER*, GROUP_OBJ, GROUP*, [MASK,] OTHER`, every
    /// `e_perm` is within `rwx`, and a `MASK` is present whenever any
    /// named `ACL_USER` or `ACL_GROUP` entry is (`needs_mask`).
    ///
    /// Returns `Err(FsError::InvalidData)` for Linux's `-EINVAL`.
    pub fn valid(&self) -> Result<(), FsError> {
        // `state` holds the tag that may come next, exactly as Linux's
        // local of the same name does; 0 means "OTHER has been seen".
        let mut state = ACL_USER_OBJ;
        let mut needs_mask = false;
        for pa in &self.entries {
            if pa.perm & !(ACL_READ | ACL_WRITE | ACL_EXECUTE) != 0 {
                return Err(FsError::InvalidData);
            }
            match pa.tag {
                ACL_USER_OBJ => {
                    if state != ACL_USER_OBJ {
                        return Err(FsError::InvalidData);
                    }
                    state = ACL_USER;
                }
                ACL_USER => {
                    if state != ACL_USER {
                        return Err(FsError::InvalidData);
                    }
                    needs_mask = true;
                }
                ACL_GROUP_OBJ => {
                    if state != ACL_USER {
                        return Err(FsError::InvalidData);
                    }
                    state = ACL_GROUP;
                }
                ACL_GROUP => {
                    if state != ACL_GROUP {
                        return Err(FsError::InvalidData);
                    }
                    needs_mask = true;
                }
                ACL_MASK => {
                    if state != ACL_GROUP {
                        return Err(FsError::InvalidData);
                    }
                    state = ACL_OTHER;
                }
                ACL_OTHER => {
                    if state == ACL_OTHER || (state == ACL_GROUP && !needs_mask) {
                        state = 0;
                    } else {
                        return Err(FsError::InvalidData);
                    }
                }
                _ => return Err(FsError::InvalidData),
            }
        }
        if state == 0 {
            Ok(())
        } else {
            Err(FsError::InvalidData)
        }
    }

    /// `posix_acl_equiv_mode()`.
    ///
    /// Folds the ACL back onto `mode`'s low 9 bits (leaving the
    /// setuid/setgid/sticky bits alone, as Linux's
    /// `*mode_p = (*mode_p & ~S_IRWXUGO) | mode` does) and reports whether
    /// the ACL says MORE than the mode can: `Ok(true)` = not equivalent,
    /// so the ACL must be stored; `Ok(false)` = the mode alone carries it.
    ///
    /// Note that `ACL_MASK` — not `ACL_GROUP_OBJ` — supplies the group
    /// triplet when a mask is present. That is the whole reason
    /// `chmod g+w` on an ACL'd file adjusts the mask rather than the
    /// owning group's entry.
    pub fn equiv_mode(&self, mode_p: &mut u16) -> Result<bool, FsError> {
        let mut mode: u16 = 0;
        let mut not_equiv = false;
        for pa in &self.entries {
            match pa.tag {
                ACL_USER_OBJ => mode |= (pa.perm & 0o7) << 6,
                ACL_GROUP_OBJ => mode |= (pa.perm & 0o7) << 3,
                ACL_OTHER => mode |= pa.perm & 0o7,
                ACL_MASK => {
                    mode = (mode & !0o070) | ((pa.perm & 0o7) << 3);
                    not_equiv = true;
                }
                ACL_USER | ACL_GROUP => not_equiv = true,
                _ => return Err(FsError::InvalidData),
            }
        }
        *mode_p = (*mode_p & !0o777) | mode;
        Ok(not_equiv)
    }

    /// `posix_acl_create_masq()` — intersect a *cloned default* ACL with
    /// the mode the caller asked `open`/`mkdir` for, and narrow the mode
    /// to what the ACL actually grants.
    ///
    /// `mode` carries the low 12 bits in and out; only the low 9 are
    /// rewritten. Returns `Ok(true)` when the result still needs to be
    /// stored as an ACL (it has named entries or a mask), `Ok(false)`
    /// when the mode bits now say everything the ACL does.
    pub fn create_masq(&mut self, mode: &mut u16) -> Result<bool, FsError> {
        let mut m = *mode;
        let mut not_equiv = false;
        let mut group_obj: Option<usize> = None;
        let mut mask_obj: Option<usize> = None;
        for (i, pa) in self.entries.iter_mut().enumerate() {
            match pa.tag {
                ACL_USER_OBJ => {
                    pa.perm &= (m >> 6) | !0o7;
                    m &= (pa.perm << 6) | !0o700;
                }
                ACL_USER | ACL_GROUP => not_equiv = true,
                ACL_GROUP_OBJ => group_obj = Some(i),
                ACL_OTHER => {
                    pa.perm &= m | !0o7;
                    m &= pa.perm | !0o7;
                }
                ACL_MASK => {
                    mask_obj = Some(i);
                    not_equiv = true;
                }
                // Linux returns -EIO here: an ACL carrying an unknown tag
                // is corruption of a stored structure, not a bad request.
                _ => return Err(FsError::Io(BlockError::IOError)),
            }
        }
        // The mask, when present, IS the group triplet — so it, not
        // ACL_GROUP_OBJ, is what the requested group bits clamp.
        // No mask and no ACL_GROUP_OBJ is Linux's `return -EIO`.
        let idx = match mask_obj.or(group_obj) {
            Some(i) => i,
            None => return Err(FsError::Io(BlockError::IOError)),
        };
        let pa = &mut self.entries[idx];
        pa.perm &= (m >> 3) | !0o7;
        m &= (pa.perm << 3) | !0o070;
        *mode = (*mode & !0o777) | (m & 0o777);
        Ok(not_equiv)
    }

    /// `__posix_acl_chmod_masq()` — push a new mode INTO an existing ACL.
    ///
    /// The owner and other entries take the mode's outer triplets
    /// verbatim; the middle triplet lands on `ACL_MASK` if there is one
    /// and on `ACL_GROUP_OBJ` otherwise. Named `ACL_USER`/`ACL_GROUP`
    /// entries are left untouched — `chmod` cannot delete a grant, it can
    /// only re-cap it through the mask.
    pub fn chmod_masq(&mut self, mode: u16) -> Result<(), FsError> {
        let mut group_obj: Option<usize> = None;
        let mut mask_obj: Option<usize> = None;
        for (i, pa) in self.entries.iter_mut().enumerate() {
            match pa.tag {
                ACL_USER_OBJ => pa.perm = (mode & 0o700) >> 6,
                ACL_USER | ACL_GROUP => {}
                ACL_GROUP_OBJ => group_obj = Some(i),
                ACL_MASK => mask_obj = Some(i),
                ACL_OTHER => pa.perm = mode & 0o007,
                _ => return Err(FsError::Io(BlockError::IOError)),
            }
        }
        match mask_obj.or(group_obj) {
            Some(i) => {
                self.entries[i].perm = (mode & 0o070) >> 3;
                Ok(())
            }
            None => Err(FsError::Io(BlockError::IOError)),
        }
    }
}

/// The three outcomes of an ACL check.
///
/// Linux returns `0` / `-EACCES` / `-EIO` from
/// `fs/posix_acl.c::posix_acl_permission`, and the distinction between
/// the last two survives all the way out: `fs/namei.c::generic_permission`
/// does `if (ret != -EACCES) return ret;`, so a MALFORMED ACL denies the
/// access without ever consulting `CAP_DAC_OVERRIDE`. Collapsing
/// `Malformed` onto `Denied` would let a privileged process walk through
/// a corrupt ACL.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AclDecision {
    /// `0` — the ACL grants everything in `want`.
    Granted,
    /// `-EACCES` — the ACL denies; capability overrides may still apply.
    Denied,
    /// `-EIO` — the ACL is corrupt (unknown tag, or no `ACL_OTHER`).
    Malformed,
}

/// `fs/posix_acl.c::posix_acl_permission` — "is `accessor` granted `want`
/// by `acl` on a file owned by `file.uid`:`file.gid`?"
///
/// `want` is the `MAY_READ | MAY_WRITE | MAY_EXEC` triple (4/2/1); Linux
/// masks it down to those three bits first, so `MAY_APPEND` and friends
/// never reach the ACL.
///
/// The walk is a single forward pass with two escapes:
///
///   * `ACL_USER_OBJ` and `ACL_OTHER` go to `check_perm` — their entry is
///     compared with `want` DIRECTLY, unlimited by `ACL_MASK`.
///   * `ACL_USER`, `ACL_GROUP_OBJ` and `ACL_GROUP` go to `mask` — they
///     are ANDed with the first `ACL_MASK` found AFTER them before the
///     comparison. Skipping that AND is the classic silent over-grant:
///     `setfacl -m u:bob:rwx,m::r--` must leave bob with `r--`.
///
/// The `found` flag is what makes a group match final: once any group
/// entry matched the accessor, reaching `ACL_OTHER` is `-EACCES` rather
/// than a fallback to the other bits. A user in a listed group is never
/// demoted to "other".
pub fn posix_acl_permission(
    acl: &PosixAcl,
    file: FileOwner,
    accessor: &Accessor,
    want: u32,
) -> AclDecision {
    let want = (want & 7) as u16;
    let mut found = false;
    for (i, pa) in acl.entries.iter().enumerate() {
        match pa.tag {
            ACL_USER_OBJ => {
                // "(May have been checked already)" — acl_permission_check
                // short-circuits the owner before ever calling check_acl.
                if accessor.uid == file.uid {
                    return check_perm(pa, want);
                }
            }
            ACL_USER => {
                if pa.id == accessor.uid {
                    return apply_mask(acl, i, pa, want);
                }
            }
            ACL_GROUP_OBJ => {
                if accessor.in_group(file.gid) {
                    found = true;
                    if pa.perm & want == want {
                        return apply_mask(acl, i, pa, want);
                    }
                }
            }
            ACL_GROUP => {
                if accessor.in_group(pa.id) {
                    found = true;
                    if pa.perm & want == want {
                        return apply_mask(acl, i, pa, want);
                    }
                }
            }
            ACL_MASK => {}
            ACL_OTHER => {
                if found {
                    return AclDecision::Denied;
                }
                return check_perm(pa, want);
            }
            _ => return AclDecision::Malformed,
        }
    }
    // Falling off the end means the ACL had no ACL_OTHER: Linux's
    // `return -EIO` after the loop.
    AclDecision::Malformed
}

/// Linux's `check_perm:` label.
fn check_perm(pa: &AclEntry, want: u16) -> AclDecision {
    if pa.perm & want == want {
        AclDecision::Granted
    } else {
        AclDecision::Denied
    }
}

/// Linux's `mask:` label — scan FORWARD from the matched entry for
/// `ACL_MASK`. If none follows, control falls into `check_perm`.
fn apply_mask(acl: &PosixAcl, matched_idx: usize, pa: &AclEntry, want: u16) -> AclDecision {
    for mask_obj in &acl.entries[matched_idx + 1..] {
        if mask_obj.tag == ACL_MASK {
            if pa.perm & mask_obj.perm & want == want {
                return AclDecision::Granted;
            }
            return AclDecision::Denied;
        }
    }
    check_perm(pa, want)
}

/// What a create inherits from its parent directory, per
/// `fs/posix_acl.c::posix_acl_create`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AclCreate {
    /// The `system.posix_acl_default` to install on the NEW inode — only
    /// ever `Some` for a directory, so the default propagates down a
    /// subtree but stops at the first file.
    pub default_acl: Option<PosixAcl>,
    /// The `system.posix_acl_access` to install, or `None` when the mode
    /// bits alone express the result.
    pub access_acl: Option<PosixAcl>,
}

/// `fs/posix_acl.c::posix_acl_create` — default-ACL inheritance.
///
/// `mode` is the creation mode (low 12 bits) and is narrowed in place.
/// Three behaviours here are easy to lose and all are Linux's:
///
///   * A symlink inherits nothing AND is not umasked — Linux returns
///     before touching `*mode` on `S_ISLNK`.
///   * The umask applies ONLY when the parent has no default ACL. Where
///     there is one, the default ACL replaces the umask entirely; that is
///     the point of `setfacl -d`.
///   * The parent's default ACL is copied verbatim onto a new DIRECTORY
///     (so it keeps propagating) and dropped for anything else, while the
///     *access* ACL is the masqueraded clone in both cases.
pub fn posix_acl_create(
    dir_default: Option<&PosixAcl>,
    new_is_dir: bool,
    new_is_symlink: bool,
    mode: &mut u16,
    umask: u16,
) -> Result<AclCreate, FsError> {
    if new_is_symlink {
        return Ok(AclCreate::default());
    }
    let p = match dir_default {
        Some(p) => p,
        None => {
            *mode &= !(umask & 0o777);
            return Ok(AclCreate::default());
        }
    };
    let mut clone = p.clone();
    let not_equiv = clone.create_masq(mode)?;
    Ok(AclCreate {
        default_acl: if new_is_dir { Some(p.clone()) } else { None },
        access_acl: if not_equiv { Some(clone) } else { None },
    })
}

/// `fs/posix_acl.c::posix_acl_update_mode` — the other half of the
/// coherence rule: SETTING an access ACL rewrites the file mode.
///
/// Returns the new mode and the ACL that should actually be stored —
/// `None` when the ACL turned out to be exactly expressible as mode bits,
/// in which case Linux stores no ACL at all (`*acl = NULL`).
///
/// `in_group_or_capable` is `fs/inode.c::in_group_or_capable`: true when
/// the caller is in the file's group or holds `CAP_FSETID` over it. When
/// false the setgid bit is dropped, exactly as `chmod` would.
///
/// LINUX-GAP: [`Accessor`] carries `CAP_DAC_OVERRIDE` and
/// `CAP_DAC_READ_SEARCH` but not `CAP_FSETID`, so callers inside
/// `filesystem/` cannot compute that predicate and must pass it in.
pub fn posix_acl_update_mode(
    inode_mode: u16,
    acl: PosixAcl,
    in_group_or_capable: bool,
) -> Result<(u16, Option<PosixAcl>), FsError> {
    let mut mode = inode_mode;
    let not_equiv = acl.equiv_mode(&mut mode)?;
    if !in_group_or_capable {
        mode &= !0o2000; // S_ISGID
    }
    Ok((mode, if not_equiv { Some(acl) } else { None }))
}
