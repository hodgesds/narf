//! The decoded type graph.
//!
//! One Rust enum variant per BTF kind, with the trailing payload each kind
//! carries decoded into owned `Vec`s. Names stay as `u32` offsets into the
//! string section rather than `String`s: a `vmlinux`-sized blob has hundreds of
//! thousands of names, and the string section is retained anyway, so copying
//! each one would double the footprint to save an indirection.
//!
//! This is deliberately **not** `narf_bpf_verifier::kfunc::TypeKind`, and this
//! crate deliberately does not depend on the verifier. NARF's kfunc semantics
//! come from Rust types through the `kfunc!` macro and a link-section registry
//! (`bpf/specification/spec.md` §1.3), so BTF is a compatibility surface for
//! loaders, not the type system the verifier consumes. Mapping this graph onto
//! the verifier's descriptors would create exactly the drift the Rust-derived
//! descriptors exist to prevent.

use alloc::vec::Vec;

/// `BTF_KIND_*`, from `include/uapi/linux/btf.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Kind {
    /// `BTF_KIND_INT`
    Int = 1,
    /// `BTF_KIND_PTR`
    Ptr = 2,
    /// `BTF_KIND_ARRAY`
    Array = 3,
    /// `BTF_KIND_STRUCT`
    Struct = 4,
    /// `BTF_KIND_UNION`
    Union = 5,
    /// `BTF_KIND_ENUM` — values are 32 bits.
    Enum = 6,
    /// `BTF_KIND_FWD`
    Fwd = 7,
    /// `BTF_KIND_TYPEDEF`
    Typedef = 8,
    /// `BTF_KIND_VOLATILE`
    Volatile = 9,
    /// `BTF_KIND_CONST`
    Const = 10,
    /// `BTF_KIND_RESTRICT`
    Restrict = 11,
    /// `BTF_KIND_FUNC`
    Func = 12,
    /// `BTF_KIND_FUNC_PROTO`
    FuncProto = 13,
    /// `BTF_KIND_VAR`
    Var = 14,
    /// `BTF_KIND_DATASEC`
    DataSec = 15,
    /// `BTF_KIND_FLOAT`
    Float = 16,
    /// `BTF_KIND_DECL_TAG`
    DeclTag = 17,
    /// `BTF_KIND_TYPE_TAG`
    TypeTag = 18,
    /// `BTF_KIND_ENUM64` — values are 64 bits.
    Enum64 = 19,
}

impl Kind {
    /// The highest kind this parser knows. `BTF_KIND_MAX`.
    pub const MAX: u8 = Self::Enum64 as u8;

    /// Decode a raw kind field. `None` for `BTF_KIND_UNKN` (0) and anything
    /// above [`Kind::MAX`].
    #[must_use]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Int,
            2 => Self::Ptr,
            3 => Self::Array,
            4 => Self::Struct,
            5 => Self::Union,
            6 => Self::Enum,
            7 => Self::Fwd,
            8 => Self::Typedef,
            9 => Self::Volatile,
            10 => Self::Const,
            11 => Self::Restrict,
            12 => Self::Func,
            13 => Self::FuncProto,
            14 => Self::Var,
            15 => Self::DataSec,
            16 => Self::Float,
            17 => Self::DeclTag,
            18 => Self::TypeTag,
            19 => Self::Enum64,
            _ => return None,
        })
    }

    /// Whether this kind is a qualifier or alias that a type walk sees
    /// through: `typedef`, `const`, `volatile`, `restrict`, `type_tag`.
    #[must_use]
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::Typedef | Self::Volatile | Self::Const | Self::Restrict | Self::TypeTag
        )
    }
}

/// The `BTF_INT_ENCODING` attribute. At most one bit may be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntEncoding {
    /// No attribute — an unsigned integer.
    #[default]
    None,
    /// `BTF_INT_SIGNED`
    Signed,
    /// `BTF_INT_CHAR`
    Char,
    /// `BTF_INT_BOOL`
    Bool,
}

/// `enum btf_func_linkage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncLinkage {
    /// `BTF_FUNC_STATIC`
    Static,
    /// `BTF_FUNC_GLOBAL`
    Global,
}

/// `BTF_VAR_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarLinkage {
    /// `BTF_VAR_STATIC`
    Static,
    /// `BTF_VAR_GLOBAL_ALLOCATED`
    GlobalAllocated,
}

/// One `struct btf_member`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// Offset into the string section. 0 means anonymous.
    pub name_off: u32,
    /// The member's type.
    pub type_id: u32,
    /// Bit offset of the member within the struct.
    pub bit_offset: u32,
    /// Width in bits for a bitfield member, 0 otherwise. Only a `kind_flag`
    /// struct can carry this; without `kind_flag` the bitfield width lives in
    /// the member's `INT` type instead.
    pub bitfield_size: u8,
}

/// One `struct btf_enum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumValue {
    /// Offset into the string section. Never 0 — an enumerator must be named.
    pub name_off: u32,
    /// The value. Interpret as signed when the enum's `kind_flag` is set.
    pub val: i32,
}

/// One `struct btf_enum64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enum64Value {
    /// Offset into the string section. Never 0.
    pub name_off: u32,
    /// The value, reassembled from its two 32-bit halves.
    pub val: u64,
}

/// One `struct btf_param`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    /// Offset into the string section. 0 means unnamed.
    pub name_off: u32,
    /// The parameter's type. 0 on the final parameter marks a vararg.
    pub type_id: u32,
}

/// One `struct btf_var_secinfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecInfo {
    /// The `VAR` this describes.
    pub type_id: u32,
    /// Byte offset within the section.
    pub offset: u32,
    /// Byte size within the section.
    pub size: u32,
}

/// A decoded BTF type.
///
/// Type ids are 1-based; id 0 is void and has no entry. Every `type_id` in
/// here has been bounds-checked against the type count, so a consumer may
/// index with it — but through [`crate::Btf::type_by_id`], which is still
/// `Option`-returning, because "checked once at parse" is not a property the
/// type system carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BtfType {
    /// `BTF_KIND_INT`.
    Int {
        /// Name offset.
        name_off: u32,
        /// Declared size in bytes.
        size: u32,
        /// Signed / char / bool attribute.
        encoding: IntEncoding,
        /// Bit offset of the value within `size` bytes.
        bit_offset: u8,
        /// Value width in bits.
        nr_bits: u8,
    },
    /// `BTF_KIND_PTR`. Always anonymous. `type_id` 0 is `void *`.
    Ptr {
        /// The pointee.
        type_id: u32,
    },
    /// `BTF_KIND_ARRAY`. Always anonymous, always `size == 0`.
    Array {
        /// Element type. Never 0.
        elem_type: u32,
        /// Index type — must resolve to a plain `INT`. Never 0.
        index_type: u32,
        /// Element count. May be 0 (a flexible array member).
        nelems: u32,
    },
    /// `BTF_KIND_STRUCT` or `BTF_KIND_UNION`.
    Composite {
        /// Name offset. 0 for an anonymous struct/union.
        name_off: u32,
        /// Whether this is a union.
        is_union: bool,
        /// Declared size in bytes.
        size: u32,
        /// Whether member offsets carry bitfield widths.
        kind_flag: bool,
        /// The members, in declaration order.
        members: Vec<Member>,
    },
    /// `BTF_KIND_ENUM`.
    Enum {
        /// Name offset. 0 for an anonymous enum.
        name_off: u32,
        /// Size in bytes: 1, 2, 4, or 8.
        size: u32,
        /// Whether the values are signed.
        signed: bool,
        /// The enumerators.
        values: Vec<EnumValue>,
    },
    /// `BTF_KIND_ENUM64`.
    Enum64 {
        /// Name offset. 0 for an anonymous enum.
        name_off: u32,
        /// Size in bytes: 1, 2, 4, or 8.
        size: u32,
        /// Whether the values are signed.
        signed: bool,
        /// The enumerators.
        values: Vec<Enum64Value>,
    },
    /// `BTF_KIND_FWD` — an incomplete struct or union declaration.
    Fwd {
        /// Name offset. Never 0.
        name_off: u32,
        /// Whether the forward declaration is of a union.
        is_union: bool,
    },
    /// `BTF_KIND_TYPEDEF`.
    Typedef {
        /// Name offset. Never 0.
        name_off: u32,
        /// The aliased type.
        type_id: u32,
    },
    /// `BTF_KIND_CONST`, `BTF_KIND_VOLATILE`, or `BTF_KIND_RESTRICT`.
    /// Always anonymous.
    Qualifier {
        /// Which qualifier.
        kind: Kind,
        /// The qualified type.
        type_id: u32,
    },
    /// `BTF_KIND_TYPE_TAG`.
    TypeTag {
        /// Name offset. Never 0.
        name_off: u32,
        /// The tagged type.
        type_id: u32,
    },
    /// `BTF_KIND_FUNC`.
    Func {
        /// Name offset. Never 0.
        name_off: u32,
        /// Static or global.
        linkage: FuncLinkage,
        /// The `FUNC_PROTO` this function has.
        proto: u32,
    },
    /// `BTF_KIND_FUNC_PROTO`. Always anonymous.
    FuncProto {
        /// Return type. 0 means `void`.
        ret_type: u32,
        /// The parameters. A final entry with both fields 0 is a vararg.
        params: Vec<Param>,
    },
    /// `BTF_KIND_VAR`.
    Var {
        /// Name offset. Never 0.
        name_off: u32,
        /// The variable's type.
        type_id: u32,
        /// Static or global-allocated.
        linkage: VarLinkage,
    },
    /// `BTF_KIND_DATASEC`.
    DataSec {
        /// Name offset. Never 0.
        name_off: u32,
        /// Section size in bytes. Never 0.
        size: u32,
        /// The variables in the section, in ascending offset order.
        vars: Vec<SecInfo>,
    },
    /// `BTF_KIND_FLOAT`.
    Float {
        /// Name offset.
        name_off: u32,
        /// Size in bytes: 2, 4, 8, 12, or 16.
        size: u32,
    },
    /// `BTF_KIND_DECL_TAG`.
    DeclTag {
        /// Name offset — the tag's value. Never 0.
        name_off: u32,
        /// What is being tagged.
        type_id: u32,
        /// Which member or parameter, or -1 for the whole thing.
        component_idx: i32,
    },
}

impl BtfType {
    /// The kind this type is.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Int { .. } => Kind::Int,
            Self::Ptr { .. } => Kind::Ptr,
            Self::Array { .. } => Kind::Array,
            Self::Composite {
                is_union: false, ..
            } => Kind::Struct,
            Self::Composite { is_union: true, .. } => Kind::Union,
            Self::Enum { .. } => Kind::Enum,
            Self::Enum64 { .. } => Kind::Enum64,
            Self::Fwd { .. } => Kind::Fwd,
            Self::Typedef { .. } => Kind::Typedef,
            Self::Qualifier { kind, .. } => *kind,
            Self::TypeTag { .. } => Kind::TypeTag,
            Self::Func { .. } => Kind::Func,
            Self::FuncProto { .. } => Kind::FuncProto,
            Self::Var { .. } => Kind::Var,
            Self::DataSec { .. } => Kind::DataSec,
            Self::Float { .. } => Kind::Float,
            Self::DeclTag { .. } => Kind::DeclTag,
        }
    }

    /// This type's name offset, or 0 if it is anonymous or cannot be named.
    #[must_use]
    pub const fn name_off(&self) -> u32 {
        match self {
            Self::Int { name_off, .. }
            | Self::Composite { name_off, .. }
            | Self::Enum { name_off, .. }
            | Self::Enum64 { name_off, .. }
            | Self::Fwd { name_off, .. }
            | Self::Typedef { name_off, .. }
            | Self::TypeTag { name_off, .. }
            | Self::Func { name_off, .. }
            | Self::Var { name_off, .. }
            | Self::DataSec { name_off, .. }
            | Self::Float { name_off, .. }
            | Self::DeclTag { name_off, .. } => *name_off,
            Self::Ptr { .. }
            | Self::Array { .. }
            | Self::Qualifier { .. }
            | Self::FuncProto { .. } => 0,
        }
    }

    /// The type this one aliases or qualifies, if it is a modifier.
    #[must_use]
    pub const fn modifier_target(&self) -> Option<u32> {
        match self {
            Self::Typedef { type_id, .. }
            | Self::Qualifier { type_id, .. }
            | Self::TypeTag { type_id, .. } => Some(*type_id),
            _ => None,
        }
    }
}
