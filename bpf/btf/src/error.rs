//! Rejection reasons, and the errno each maps to.
//!
//! Every rejection is a distinct [`Reason`] rather than a bare "invalid",
//! because the tests assert on the reason. A test that only asserts "some
//! error" passes when the parser rejects for the *wrong* reason, which is how
//! a bounds check silently degrades into a length check somewhere else.
//!
//! The errno mapping lives here rather than in the syscall handler so that the
//! crate stays the single place that knows what BTF considers fatal, but it is
//! expressed as [`Errno`] — a three-variant enum — rather than a number, so the
//! crate needs no kernel dependency.

/// The errno class a rejection maps to.
///
/// Deliberately not a raw integer: this crate is host-testable and has no
/// business knowing NARF's or Linux's errno numbering. The syscall handler
/// translates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    /// `EINVAL` — the blob is malformed.
    Invalid,
    /// `E2BIG` — the blob, or something it declares, exceeds a hard limit.
    TooBig,
    /// `EOPNOTSUPP` — well-formed, but names a BTF feature NARF does not do.
    NotSupported,
}

/// Why a blob was rejected.
///
/// One variant per check. Ordering and numbering are not ABI — only the
/// [`Errno`] a variant maps to is visible to userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    // ── blob and header ──────────────────────────────────────────────
    /// The blob is empty.
    BlobEmpty,
    /// The blob is larger than [`crate::MAX_BTF_SIZE`].
    BlobTooLarge,
    /// Fewer bytes than the fixed part of `struct btf_header`, or fewer than
    /// the `hdr_len` the header itself declares.
    HeaderTruncated,
    /// `magic != 0xeB9F`. Also what a big-endian blob looks like from here.
    BadMagic,
    /// `version != 1`.
    UnsupportedVersion,
    /// `flags != 0`. Reserved for split BTF, which NARF does not implement.
    UnsupportedFlags,
    /// `hdr_len` extends past the fields this parser knows, and the extra
    /// bytes are not all zero — so the producer meant something by them.
    UnsupportedHeader,
    /// Header only, no sections.
    NoData,
    /// A section offset lies past the end of the blob.
    SectionOffsetOutOfRange,
    /// Bytes between the header and a section, or between two sections, that
    /// belong to neither.
    SectionGap,
    /// Two sections claim the same bytes.
    SectionOverlap,
    /// A section's length runs past the end of the blob.
    SectionTooLong,
    /// The sections do not account for every byte after the header.
    TrailingData,
    /// The string section must be last and must end at the end of the blob.
    StringSectionNotAtEnd,
    /// The string section is empty, over-long, or not NUL-delimited at both
    /// ends. Both terminators matter: the leading one makes `name_off == 0`
    /// mean "anonymous", the trailing one makes every name NUL-terminated
    /// without a bounds check at every read.
    StringSectionInvalid,
    /// `type_off` is not 4-byte aligned.
    UnalignedTypeSection,
    /// The type section is empty.
    NoTypes,
    /// More types than a `type_id` can name.
    TooManyTypes,

    // ── per-type metadata ────────────────────────────────────────────
    /// The type section ends inside a type record or its trailing payload.
    TypeTruncated,
    /// Reserved bits set in `btf_type::info`.
    InvalidInfo,
    /// `kind` is 0 (`UNKN`) or above `BTF_KIND_MAX`.
    InvalidKind,
    /// A `name_off` lies outside the string section.
    InvalidNameOffset,
    /// A name is empty where one is required, or is not a valid identifier.
    InvalidName,
    /// `vlen != 0` on a kind that has no members.
    VlenNotZero,
    /// `kind_flag` set on a kind that does not define one.
    KindFlagNotZero,
    /// `size != 0` on a kind that carries a `type` instead.
    SizeNotZero,
    /// `type != 0` on a kind that carries a `size` instead.
    TypeNotZero,
    /// A `type_id` is 0 where void is not allowed, or names a type that does
    /// not exist.
    InvalidTypeId,

    /// Reserved bits set in an `INT`'s trailing word.
    IntDataInvalid,
    /// `INT` bit offset + bit width exceeds 128.
    IntBitsExceedU128,
    /// `INT` bit offset + bit width does not fit in the declared size.
    IntBitsExceedSize,
    /// `INT` encoding names more than one of SIGNED/CHAR/BOOL, or an unknown
    /// bit.
    IntEncodingUnsupported,

    /// An `ARRAY` element type is void, or has no size.
    InvalidElem,
    /// An `ARRAY` index type is not a plain, byte-aligned, power-of-two `INT`.
    InvalidIndex,
    /// An `ARRAY` of a bitfield-shaped `INT`.
    InvalidArrayOfInt,
    /// `elem_size * nelems` overflows 32 bits.
    ArraySizeOverflow,

    /// Struct member bit offsets must be non-decreasing.
    MemberBitOffsetNotMonotonic,
    /// A union member at a nonzero bit offset.
    UnionMemberBitOffsetNotZero,
    /// A member starts past the end of its struct.
    MemberOffsetExceedsStructSize,
    /// A member ends past the end of its struct.
    MemberExceedsStructSize,
    /// A non-bitfield member at a bit offset that is not a whole byte.
    MemberNotByteAligned,

    /// `ENUM`/`ENUM64` size is not 1, 2, 4, or 8.
    EnumUnexpectedSize,

    /// `FUNC` linkage above `BTF_FUNC_GLOBAL`.
    FuncLinkageInvalid,
    /// `FUNC::type` does not name a `FUNC_PROTO`.
    FuncTypeNotProto,
    /// A `FUNC_PROTO` return or parameter type has no size.
    FuncProtoTypeNoSize,
    /// A named vararg parameter, which is a contradiction.
    FuncProtoNamedVararg,

    /// `VAR` linkage is neither static nor global-allocated.
    VarLinkageUnsupported,

    /// `DATASEC` with `size == 0`.
    DatasecSizeZero,
    /// `DATASEC` with no members.
    DatasecVlenZero,
    /// A `DATASEC` member offset overlaps the previous one or starts past the
    /// section.
    DatasecOffsetInvalid,
    /// A `DATASEC` member size is 0 or exceeds the section.
    DatasecSizeInvalid,
    /// A `DATASEC` member's offset+size runs past the section.
    DatasecOffsetSizeInvalid,
    /// The `DATASEC` members' sizes sum to more than the section size.
    DatasecSumExceedsSize,
    /// A `DATASEC` member is not a `VAR`.
    DatasecMemberNotVar,
    /// A `DATASEC` member is smaller than the variable it describes.
    DatasecVarTooSmall,

    /// `FLOAT` size is not 2, 4, 8, 12, or 16.
    FloatSizeInvalid,

    /// `DECL_TAG` `component_idx < -1`, or out of range for its target.
    DeclTagComponentIdxInvalid,
    /// `DECL_TAG` applied to something that cannot carry one.
    DeclTagTargetInvalid,

    // ── whole-graph ──────────────────────────────────────────────────
    /// A type reaches itself without going through a pointer, so walking it
    /// would not terminate.
    TypeCycle,
    /// A type is used where a size is required but has none — a forward
    /// declaration as a struct member, say.
    TypeHasNoSize,
}

impl Reason {
    /// A short, stable, allocation-free description, for the `btf_log_buf`.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::BlobEmpty => "empty blob",
            Self::BlobTooLarge => "blob exceeds the maximum BTF size",
            Self::HeaderTruncated => "btf_header not found",
            Self::BadMagic => "invalid magic",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnsupportedFlags => "unsupported flags",
            Self::UnsupportedHeader => "unsupported btf_header",
            Self::NoData => "no data",
            Self::SectionOffsetOutOfRange => "invalid section offset",
            Self::SectionGap => "unsupported section found",
            Self::SectionOverlap => "section overlap found",
            Self::SectionTooLong => "total section length too long",
            Self::TrailingData => "data outside the known sections",
            Self::StringSectionNotAtEnd => "string section is not at the end",
            Self::StringSectionInvalid => "invalid string section",
            Self::UnalignedTypeSection => "unaligned type_off",
            Self::NoTypes => "no type found",
            Self::TooManyTypes => "too many types",
            Self::TypeTruncated => "type record runs past the type section",
            Self::InvalidInfo => "invalid btf_info",
            Self::InvalidKind => "invalid kind",
            Self::InvalidNameOffset => "invalid name_offset",
            Self::InvalidName => "invalid name",
            Self::VlenNotZero => "vlen != 0",
            Self::KindFlagNotZero => "invalid btf_info kind_flag",
            Self::SizeNotZero => "size != 0",
            Self::TypeNotZero => "type != 0",
            Self::InvalidTypeId => "invalid type_id",
            Self::IntDataInvalid => "invalid int_data",
            Self::IntBitsExceedU128 => "nr_bits exceeds 128",
            Self::IntBitsExceedSize => "nr_bits exceeds type_size",
            Self::IntEncodingUnsupported => "unsupported encoding",
            Self::InvalidElem => "invalid elem",
            Self::InvalidIndex => "invalid index",
            Self::InvalidArrayOfInt => "invalid array of int",
            Self::ArraySizeOverflow => "array size overflows u32",
            Self::MemberBitOffsetNotMonotonic => "invalid member bits_offset",
            Self::UnionMemberBitOffsetNotZero => "invalid member bits_offset",
            Self::MemberOffsetExceedsStructSize => "member bits_offset exceeds its struct size",
            Self::MemberExceedsStructSize => "member exceeds struct size",
            Self::MemberNotByteAligned => "member is not byte aligned",
            Self::EnumUnexpectedSize => "unexpected enum size",
            Self::FuncLinkageInvalid => "invalid func linkage",
            Self::FuncTypeNotProto => "invalid type_id",
            Self::FuncProtoTypeNoSize => "invalid func_proto type",
            Self::FuncProtoNamedVararg => "invalid vararg",
            Self::VarLinkageUnsupported => "linkage not supported",
            Self::DatasecSizeZero => "size == 0",
            Self::DatasecVlenZero => "vlen == 0",
            Self::DatasecOffsetInvalid => "invalid offset",
            Self::DatasecSizeInvalid => "invalid size",
            Self::DatasecOffsetSizeInvalid => "invalid offset+size",
            Self::DatasecSumExceedsSize => "invalid btf_info size",
            Self::DatasecMemberNotVar => "not a VAR kind member",
            Self::DatasecVarTooSmall => "invalid size",
            Self::FloatSizeInvalid => "invalid type_size",
            Self::DeclTagComponentIdxInvalid => "invalid component_idx",
            Self::DeclTagTargetInvalid => "invalid type_id",
            Self::TypeCycle => "type cycle",
            Self::TypeHasNoSize => "type has no size",
        }
    }

    /// The errno class this rejection maps to.
    #[must_use]
    pub const fn errno(self) -> Errno {
        match self {
            Self::BlobTooLarge | Self::UnsupportedHeader | Self::TooManyTypes => Errno::TooBig,
            // LINUX-GAP: Linux reports these three as its *internal* `ENOTSUPP`
            // (524), which `bpf(2)` leaks to userspace verbatim — an errno with
            // no `strerror` entry. NARF returns the userspace-visible
            // `EOPNOTSUPP` (95) instead. A loader that only tests `err != 0`
            // (libbpf does) cannot tell the difference; one that tests for 524
            // was reading a kernel-internal number it was never promised.
            Self::UnsupportedVersion | Self::UnsupportedFlags | Self::IntEncodingUnsupported => {
                Errno::NotSupported
            }
            _ => Errno::Invalid,
        }
    }
}

/// A rejection: what went wrong, and which type it went wrong in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfError {
    reason: Reason,
    type_id: u32,
}

impl BtfError {
    /// A rejection not attributable to one type — anything in the header or
    /// the section layout.
    #[must_use]
    pub const fn global(reason: Reason) -> Self {
        Self { reason, type_id: 0 }
    }

    /// A rejection in type `type_id` (1-based, as BTF numbers them).
    #[must_use]
    pub const fn at(type_id: u32, reason: Reason) -> Self {
        Self { reason, type_id }
    }

    /// Why.
    #[must_use]
    pub const fn reason(self) -> Reason {
        self.reason
    }

    /// The 1-based `type_id` this was found in, or 0 for a header-level
    /// rejection.
    #[must_use]
    pub const fn type_id(self) -> u32 {
        self.type_id
    }

    /// The errno class this maps to.
    #[must_use]
    pub const fn errno(self) -> Errno {
        self.reason.errno()
    }

    /// A short description, without the type id.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.reason.message()
    }
}
