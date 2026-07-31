//! Whole-graph validation: id bounds, cycle rejection, size computation, and
//! the cross-type checks that need a resolved size to state.
//!
//! ## Why a graph pass at all
//!
//! The per-record pass in `lib.rs` can only check a `type_id` against
//! `BTF_MAX_TYPE`, because BTF permits forward references and the type count
//! is not known until the section has been walked. So "does this id exist" is
//! a post-pass, and so is everything that needs another type's *size*.
//!
//! ## The cycle rule
//!
//! A type walk must terminate. The edges that can make it not terminate are
//! the ones a walk follows to compute a size or to strip a modifier:
//!
//! | from | to |
//! |---|---|
//! | `typedef`/`const`/`volatile`/`restrict`/`type_tag` | the type it wraps |
//! | `array` | element type, index type |
//! | `struct`/`union` | every member's type |
//! | `var` | its type |
//! | `func` | its `func_proto` |
//! | `func_proto` | return type, every parameter type |
//! | `datasec` | every member's type |
//! | `decl_tag` | its target |
//!
//! **`ptr` is deliberately not an edge.** `struct list { struct list *next; }`
//! is the single most common shape in any real BTF blob, and it is a cycle
//! through a pointer. A pointer has a size without knowing its pointee, so the
//! walk stops there — which is exactly why the cycle is harmless.
//!
//! Including `func_proto`'s parameter and return edges is stricter than
//! strictly necessary (C cannot express a function type reachable from its own
//! parameter list except through a pointer, which breaks the cycle anyway),
//! but it costs nothing and keeps the rule "every non-pointer edge is
//! acyclic" instead of a longer rule with an exception nobody can check.
//!
//! ## Why an explicit stack
//!
//! Depth is `O(nr_types)` in the worst case — a chain of a million typedefs is
//! a 16 MiB blob away — and recursion at that depth is a kernel stack
//! overflow, i.e. a syscall argument that reboots the machine. The DFS below
//! keeps its stack on the heap, bounded by `MAX_TYPE_ID` entries.

use alloc::vec;
use alloc::vec::Vec;

use crate::types::BtfType;
use crate::{Btf, BtfError, Reason, PTR_SIZE};

/// White: not yet visited. Gray: on the current DFS path — reaching one is a
/// cycle. Black: finished, `sizes` and `resolved` are valid for it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Color {
    White,
    Gray,
    Black,
}

pub(crate) fn resolve(btf: &mut Btf) -> Result<(), BtfError> {
    check_id_bounds(btf.types())?;
    let (sizes, resolved) = walk(btf.types())?;
    btf.set_resolution(sizes, resolved);
    Ok(())
}

/// Every `type_id` a record names must exist.
///
/// Separate from the walk so that "id 7000 in a 3-type blob" is rejected as
/// `InvalidTypeId` no matter which edge reached it, rather than as whatever
/// the walk happened to be doing at the time.
fn check_id_bounds(types: &[BtfType]) -> Result<(), BtfError> {
    let n = types.len() as u32;
    for (i, t) in types.iter().enumerate() {
        let id = (i as u32) + 1;
        let check = |referenced: u32| -> Result<(), BtfError> {
            if referenced > n {
                Err(BtfError::at(id, Reason::InvalidTypeId))
            } else {
                Ok(())
            }
        };
        match t {
            BtfType::Int { .. } | BtfType::Fwd { .. } | BtfType::Float { .. } => {}
            BtfType::Ptr { type_id }
            | BtfType::Typedef { type_id, .. }
            | BtfType::Qualifier { type_id, .. }
            | BtfType::TypeTag { type_id, .. }
            | BtfType::Var { type_id, .. }
            | BtfType::DeclTag { type_id, .. } => check(*type_id)?,
            BtfType::Func { proto, .. } => check(*proto)?,
            BtfType::Array {
                elem_type,
                index_type,
                ..
            } => {
                check(*elem_type)?;
                check(*index_type)?;
            }
            BtfType::Composite { members, .. } => {
                for m in members {
                    check(m.type_id)?;
                }
            }
            BtfType::FuncProto { ret_type, params } => {
                check(*ret_type)?;
                for p in params {
                    check(p.type_id)?;
                }
            }
            BtfType::DataSec { vars, .. } => {
                for v in vars {
                    check(v.type_id)?;
                }
            }
            BtfType::Enum { .. } | BtfType::Enum64 { .. } => {}
        }
    }
    Ok(())
}

/// The `i`th cycle-graph successor of `t`, or `None` once they are exhausted.
///
/// `Some(0)` is a void reference: a real slot whose target is void, which the
/// walk skips. Distinguishing it from "exhausted" is what lets `func_proto`
/// put its return type in slot 0 and its parameters after it.
fn child(t: &BtfType, i: usize) -> Option<u32> {
    match t {
        // A pointer's size does not depend on its pointee, so the walk stops
        // here. See the module docs — this is the whole reason self-referential
        // structs are legal.
        BtfType::Int { .. }
        | BtfType::Ptr { .. }
        | BtfType::Fwd { .. }
        | BtfType::Float { .. }
        | BtfType::Enum { .. }
        | BtfType::Enum64 { .. } => None,

        BtfType::Typedef { type_id, .. }
        | BtfType::Qualifier { type_id, .. }
        | BtfType::TypeTag { type_id, .. }
        | BtfType::Var { type_id, .. }
        | BtfType::DeclTag { type_id, .. } => (i == 0).then_some(*type_id),

        BtfType::Func { proto, .. } => (i == 0).then_some(*proto),

        BtfType::Array {
            elem_type,
            index_type,
            ..
        } => match i {
            0 => Some(*elem_type),
            1 => Some(*index_type),
            _ => None,
        },

        BtfType::Composite { members, .. } => members.get(i).map(|m| m.type_id),

        BtfType::FuncProto { ret_type, params } => match i.checked_sub(1) {
            None => Some(*ret_type),
            Some(pi) => params.get(pi).map(|p| p.type_id),
        },

        BtfType::DataSec { vars, .. } => vars.get(i).map(|v| v.type_id),
    }
}

/// Depth-first walk over the cycle graph.
///
/// Returns `(sizes, resolved)`, both indexed from 0 for `type_id` 1. Every
/// cross-type check runs in the post-order step, which is what guarantees that
/// the sizes it reads are already computed — there is no second pass that
/// could be reordered into reading an uninitialised entry.
fn walk(types: &[BtfType]) -> Result<(Vec<Option<u32>>, Vec<u32>), BtfError> {
    let n = types.len();
    let mut color = vec![Color::White; n];
    let mut sizes: Vec<Option<u32>> = vec![None; n];
    let mut resolved: Vec<u32> = vec![0; n];
    // `(type_id, next child index)`.
    let mut stack: Vec<(u32, usize)> = Vec::new();

    // Every id below is in `1..=n`: the roots by construction, the children
    // because `check_id_bounds` ran first. The lookups still go through
    // `get`/`get_mut` — an out-of-range id becomes `InvalidTypeId` rather than
    // a panic, so a future edit to `check_id_bounds` cannot turn a malformed
    // blob into a kernel fault.
    let oob = |id: u32| BtfError::at(id, Reason::InvalidTypeId);

    for root in 1..=n as u32 {
        if *color.get(root as usize - 1).ok_or_else(|| oob(root))? != Color::White {
            continue;
        }
        color[root as usize - 1] = Color::Gray;
        stack.push((root, 0));

        while let Some(&(id, next)) = stack.last() {
            let t = types.get(id as usize - 1).ok_or_else(|| oob(id))?;
            match child(t, next) {
                Some(c) => {
                    if let Some(top) = stack.last_mut() {
                        top.1 += 1;
                    }
                    // A void reference: a real edge slot whose target is void.
                    if c == 0 {
                        continue;
                    }
                    let slot = color.get_mut(c as usize - 1).ok_or_else(|| oob(id))?;
                    match *slot {
                        Color::White => {
                            *slot = Color::Gray;
                            stack.push((c, 0));
                        }
                        // A back edge: this type reaches itself without going
                        // through a pointer, so a size or modifier walk would
                        // not terminate.
                        Color::Gray => return Err(BtfError::at(id, Reason::TypeCycle)),
                        Color::Black => {}
                    }
                }
                None => {
                    finish(types, id, &mut sizes, &mut resolved)?;
                    *color.get_mut(id as usize - 1).ok_or_else(|| oob(id))? = Color::Black;
                    stack.pop();
                }
            }
        }
    }

    Ok((sizes, resolved))
}

/// Size of `id`, or `None` for void and the sizeless kinds.
fn size_of(sizes: &[Option<u32>], id: u32) -> Option<u32> {
    *sizes.get(id.checked_sub(1)? as usize)?
}

/// `id` with modifiers stripped; 0 stays 0.
fn resolved_id(resolved: &[u32], id: u32) -> u32 {
    resolved
        .get(id.wrapping_sub(1) as usize)
        .copied()
        .unwrap_or(0)
}

fn type_of(types: &[BtfType], id: u32) -> Option<&BtfType> {
    types.get(id.checked_sub(1)? as usize)
}

/// `btf_type_int_is_regular`: a whole, byte-aligned, power-of-two-sized
/// integer — no bit offset, no odd width. What an array index must be, and
/// what an array element must be if it is an integer at all.
fn int_is_regular(t: &BtfType) -> bool {
    let BtfType::Int {
        size,
        bit_offset,
        nr_bits,
        ..
    } = t
    else {
        return false;
    };
    if *bit_offset != 0 || nr_bits % 8 != 0 {
        return false;
    }
    let nr_bytes = u32::from(*nr_bits) / 8;
    nr_bytes == *size && nr_bytes.is_power_of_two()
}

#[allow(clippy::too_many_lines)]
fn finish(
    types: &[BtfType],
    id: u32,
    sizes: &mut [Option<u32>],
    resolved: &mut [u32],
) -> Result<(), BtfError> {
    let idx = id as usize - 1;
    let err = |reason: Reason| BtfError::at(id, reason);
    let t = types.get(idx).ok_or_else(|| err(Reason::InvalidTypeId))?;

    let (size, res) = match t {
        BtfType::Int { size, .. }
        | BtfType::Composite { size, .. }
        | BtfType::Enum { size, .. }
        | BtfType::Enum64 { size, .. }
        | BtfType::Float { size, .. } => (Some(*size), id),

        BtfType::Ptr { .. } => (Some(PTR_SIZE), id),

        // Sizeless by definition: an incomplete declaration, a function, or a
        // description of something rather than a value.
        BtfType::Fwd { .. }
        | BtfType::Func { .. }
        | BtfType::FuncProto { .. }
        | BtfType::Var { .. }
        | BtfType::DataSec { .. }
        | BtfType::DeclTag { .. } => (None, id),

        // A modifier is transparent to both queries: it has the size of what
        // it wraps, and it resolves to what it wraps resolves to. `void` stays
        // 0, so `const void` resolves to void and has no size.
        BtfType::Typedef { type_id, .. }
        | BtfType::Qualifier { type_id, .. }
        | BtfType::TypeTag { type_id, .. } => {
            (size_of(sizes, *type_id), resolved_id(resolved, *type_id))
        }

        BtfType::Array {
            elem_type,
            index_type,
            nelems,
        } => {
            let index = type_of(types, resolved_id(resolved, *index_type))
                .ok_or_else(|| err(Reason::InvalidIndex))?;
            if !int_is_regular(index) {
                return Err(err(Reason::InvalidIndex));
            }
            let elem_size = size_of(sizes, *elem_type).ok_or_else(|| err(Reason::InvalidElem))?;
            let elem = type_of(types, resolved_id(resolved, *elem_type))
                .ok_or_else(|| err(Reason::InvalidElem))?;
            // An array of a bitfield-shaped int has no coherent element
            // stride, so Linux refuses it and so do we.
            if matches!(elem, BtfType::Int { .. }) && !int_is_regular(elem) {
                return Err(err(Reason::InvalidArrayOfInt));
            }
            // `checked_mul` rather than Linux's `elem_size > U32_MAX / nelems`
            // — same predicate, one fewer chance to get the division wrong.
            let total = elem_size
                .checked_mul(*nelems)
                .ok_or_else(|| err(Reason::ArraySizeOverflow))?;
            (Some(total), id)
        }
    };

    // Per-kind cross-checks that need the sizes computed above. Split out of
    // the match so the `(size, res)` assignment above stays readable.
    match t {
        BtfType::Composite {
            size,
            members,
            kind_flag,
            ..
        } => {
            for m in members {
                let msize = size_of(sizes, m.type_id).ok_or_else(|| err(Reason::TypeHasNoSize))?;
                let struct_bytes = u64::from(*size);
                if *kind_flag && m.bitfield_size != 0 {
                    // A `kind_flag` bitfield: the width is in the member, not
                    // in the member's `INT` type.
                    //
                    // LINUX-GAP: Linux additionally requires the member type
                    // to be an int or an enum (its `check_kflag_member` exists
                    // only for those two). NARF accepts the bit-range check on
                    // any member kind, because nothing here decodes values —
                    // the field is carried, not interpreted — and rejecting it
                    // would only reject blobs, never protect anything.
                    let bytes_off = u64::from(m.bit_offset) / 8;
                    let copy_bits = u64::from(m.bitfield_size) + u64::from(m.bit_offset % 8);
                    if copy_bits > 128 {
                        return Err(err(Reason::MemberExceedsStructSize));
                    }
                    if bytes_off + copy_bits.div_ceil(8) > struct_bytes {
                        return Err(err(Reason::MemberExceedsStructSize));
                    }
                } else if let Some(BtfType::Int {
                    bit_offset,
                    nr_bits,
                    ..
                }) = type_of(types, resolved_id(resolved, m.type_id))
                {
                    // A plain int member, possibly a non-`kind_flag` bitfield
                    // whose width lives in the int itself. `u64` throughout:
                    // both offsets are attacker-chosen and their sum overflows
                    // `u32` for ordinary hostile values.
                    let bits_off = u64::from(m.bit_offset) + u64::from(*bit_offset);
                    let bytes_off = bits_off / 8;
                    let copy_bits = u64::from(*nr_bits) + bits_off % 8;
                    if copy_bits > 128 {
                        return Err(err(Reason::MemberExceedsStructSize));
                    }
                    if bytes_off + copy_bits.div_ceil(8) > struct_bytes {
                        return Err(err(Reason::MemberExceedsStructSize));
                    }
                } else {
                    if m.bit_offset % 8 != 0 {
                        return Err(err(Reason::MemberNotByteAligned));
                    }
                    if u64::from(m.bit_offset) / 8 + u64::from(msize) > struct_bytes {
                        return Err(err(Reason::MemberExceedsStructSize));
                    }
                }
            }
        }

        BtfType::Func { proto, .. } => {
            // Not modifier-stripped: a `FUNC` names a `FUNC_PROTO` directly,
            // and a typedef in between would be a different thing entirely.
            if !matches!(type_of(types, *proto), Some(BtfType::FuncProto { .. })) {
                return Err(err(Reason::FuncTypeNotProto));
            }
        }

        BtfType::FuncProto { ret_type, params } => {
            // A void return is `ret_type == 0`; anything else must have a size,
            // so a `FWD` or another `FUNC_PROTO` cannot be returned.
            if *ret_type != 0 && size_of(sizes, *ret_type).is_none() {
                return Err(err(Reason::FuncProtoTypeNoSize));
            }
            let mut effective = params.len();
            if let Some(last) = params.last() {
                if last.type_id == 0 {
                    // The vararg marker. It must be unnamed — a named one is a
                    // parameter the producer forgot to give a type.
                    if last.name_off != 0 {
                        return Err(err(Reason::FuncProtoNamedVararg));
                    }
                    effective -= 1;
                }
            }
            for p in params.iter().take(effective) {
                if size_of(sizes, p.type_id).is_none() {
                    return Err(err(Reason::FuncProtoTypeNoSize));
                }
            }
        }

        BtfType::Var { type_id, .. } => {
            if size_of(sizes, *type_id).is_none() {
                return Err(err(Reason::TypeHasNoSize));
            }
        }

        BtfType::DataSec { vars, .. } => {
            for v in vars {
                let Some(BtfType::Var {
                    type_id: var_type, ..
                }) = type_of(types, v.type_id)
                else {
                    return Err(err(Reason::DatasecMemberNotVar));
                };
                let var_size =
                    size_of(sizes, *var_type).ok_or_else(|| err(Reason::TypeHasNoSize))?;
                if v.size < var_size {
                    return Err(err(Reason::DatasecVarTooSmall));
                }
            }
        }

        BtfType::DeclTag {
            type_id,
            component_idx,
            ..
        } => {
            let target = type_of(types, *type_id).ok_or_else(|| err(Reason::InvalidTypeId))?;
            let vlen = match target {
                BtfType::Composite { members, .. } => Some(members.len()),
                BtfType::Func { proto, .. } => match type_of(types, *proto) {
                    Some(BtfType::FuncProto { params, .. }) => Some(params.len()),
                    // `Func::proto` is validated when the `FUNC` itself is
                    // finished, and the walk finishes it first — but this is
                    // still a rejection rather than an `expect`.
                    _ => return Err(err(Reason::DeclTagTargetInvalid)),
                },
                // Tagging a variable or a typedef is legal, but there is no
                // component to index into.
                BtfType::Var { .. } | BtfType::Typedef { .. } => None,
                _ => return Err(err(Reason::DeclTagTargetInvalid)),
            };
            if *component_idx != -1 {
                let Some(vlen) = vlen else {
                    return Err(err(Reason::DeclTagComponentIdxInvalid));
                };
                // `component_idx >= -1` was checked at parse, so the cast is
                // of a non-negative value.
                if (*component_idx as u32 as usize) >= vlen {
                    return Err(err(Reason::DeclTagComponentIdxInvalid));
                }
            }
        }

        _ => {}
    }

    *sizes
        .get_mut(idx)
        .ok_or_else(|| err(Reason::InvalidTypeId))? = size;
    *resolved
        .get_mut(idx)
        .ok_or_else(|| err(Reason::InvalidTypeId))? = res;
    Ok(())
}
