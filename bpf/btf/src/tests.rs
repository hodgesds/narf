//! Host tests for the BTF parser.
//!
//! The parser is the attacker-facing surface of `BPF_BTF_LOAD`, so the tests
//! are mostly negative: a well-formed blob with exactly one field broken, and
//! an assertion on the *specific* [`Reason`]. Asserting only "is an error"
//! would pass when the parser rejects for the wrong reason, which is how a
//! bounds check silently becomes a length check somewhere else.
//!
//! There is one positive round-trip that hand-builds a blob covering every
//! kind and asserts the decoded graph equals what was encoded, plus a fuzz-ish
//! sweep that mutates every byte of a valid blob and only asserts that nothing
//! panics.

use alloc::vec;
use alloc::vec::Vec;

use crate::builder::{
    info, int_data, poke, Builder, K_ARRAY, K_CONST, K_DATASEC, K_DECL_TAG, K_ENUM, K_ENUM64,
    K_FLOAT, K_FUNC, K_FUNC_PROTO, K_FWD, K_INT, K_PTR, K_RESTRICT, K_STRUCT, K_TYPEDEF,
    K_TYPE_TAG, K_UNION, K_VAR, K_VOLATILE,
};
use crate::types::{
    BtfType, Enum64Value, EnumValue, FuncLinkage, IntEncoding, Kind, Member, Param, SecInfo,
    VarLinkage,
};
use crate::{Btf, Errno, Reason};

/// Parse and expect success.
#[track_caller]
fn ok(blob: Vec<u8>) -> Btf {
    match Btf::parse(blob) {
        Ok(b) => b,
        Err(e) => panic!(
            "expected success, got {:?} at type {}",
            e.reason(),
            e.type_id()
        ),
    }
}

/// Parse and expect this exact rejection.
#[track_caller]
fn rejects(blob: Vec<u8>, reason: Reason) {
    match Btf::parse(blob) {
        Ok(_) => panic!("expected {reason:?}, blob was accepted"),
        Err(e) => assert_eq!(e.reason(), reason, "wrong rejection reason"),
    }
}

/// The smallest well-formed blob: one `int`.
fn minimal() -> Builder {
    let mut b = Builder::new();
    b.int("int", 4);
    b
}

// ── header ──────────────────────────────────────────────────────────

#[test]
fn empty_blob() {
    rejects(Vec::new(), Reason::BlobEmpty);
}

#[test]
fn truncated_header() {
    let full = minimal().build();
    // Anything shorter than `offsetofend(hdr_len)` cannot even be read.
    for n in 1..8 {
        rejects(full[..n].to_vec(), Reason::HeaderTruncated);
    }
    // Long enough to read `hdr_len`, shorter than `hdr_len` declares.
    for n in 8..24 {
        rejects(full[..n].to_vec(), Reason::HeaderTruncated);
    }
}

#[test]
fn bad_magic() {
    let mut b = minimal();
    b.magic = Some(0x9feb); // the same blob byte-swapped
    rejects(b.build(), Reason::BadMagic);
    b.magic = Some(0);
    rejects(b.build(), Reason::BadMagic);
}

#[test]
fn wrong_version() {
    let mut b = minimal();
    for v in [0u8, 2, 255] {
        b.version = Some(v);
        rejects(b.build(), Reason::UnsupportedVersion);
    }
    // …and it is EOPNOTSUPP, not EINVAL, so a probing loader can tell
    // "wrong shape" from "newer than me".
    assert_eq!(Reason::UnsupportedVersion.errno(), Errno::NotSupported);
}

#[test]
fn nonzero_flags() {
    let mut b = minimal();
    b.flags = Some(1); // split BTF
    rejects(b.build(), Reason::UnsupportedFlags);
    assert_eq!(Reason::UnsupportedFlags.errno(), Errno::NotSupported);
}

#[test]
fn header_only() {
    let b = Builder::new();
    let mut blob = b.build();
    blob.truncate(24);
    poke(&mut blob, 8, 0); // type_off
    poke(&mut blob, 12, 0); // type_len
    poke(&mut blob, 16, 0); // str_off
    poke(&mut blob, 20, 0); // str_len
    rejects(blob, Reason::NoData);
}

#[test]
fn extended_header_must_be_zero() {
    let mut b = minimal();
    b.hdr_len = Some(32);
    // A longer header whose extra bytes are zero is fine; the sections just
    // start later.
    ok(b.build());

    let mut blob = b.build();
    blob[28] = 1;
    rejects(blob, Reason::UnsupportedHeader);
    assert_eq!(Reason::UnsupportedHeader.errno(), Errno::TooBig);
}

#[test]
fn short_header_declares_no_sections() {
    // `hdr_len` below the known header means every section field reads as
    // zero, so the bytes after the header belong to nothing.
    let mut b = minimal();
    b.hdr_len = Some(12);
    rejects(b.build(), Reason::TrailingData);
}

// ── section layout ──────────────────────────────────────────────────

#[test]
fn section_offset_past_end() {
    // The string section first (so the tiling walk consumes it), the type
    // section at an offset far past the end of the blob.
    let mut b = minimal();
    let types_len = b.build().len() as u32 - 24 - 5;
    b.str_off = Some(0);
    b.type_off = Some(0x1000_0000);
    b.type_len = Some(types_len);
    rejects(b.build(), Reason::SectionOffsetOutOfRange);
}

#[test]
fn section_offset_only_reachable_as_a_gap() {
    // With the type section first, an offset past the end is a gap before it
    // is anything else — the tiling walk finds the hole first.
    let mut b = minimal();
    b.type_off = Some(0x1000_0000);
    rejects(b.build(), Reason::SectionGap);
}

#[test]
fn section_gap() {
    let mut b = minimal();
    // Push the type section one word later, leaving four unclaimed bytes.
    b.type_off = Some(4);
    rejects(b.build(), Reason::SectionGap);
}

#[test]
fn str_section_overlaps_type_section() {
    let mut b = minimal();
    // The string section starts inside the type section.
    b.str_off = Some(4);
    rejects(b.build(), Reason::SectionOverlap);
}

#[test]
fn section_length_too_long() {
    let mut b = minimal();
    b.type_len = Some(0x1000);
    rejects(b.build(), Reason::SectionTooLong);
}

#[test]
fn section_offset_len_overflow_u32() {
    // `str_off + str_len` wraps u32. Computed in u64 it is enormous and the
    // tiling check refuses it; computed in u32 it would wrap to a small
    // number that looks like it fits.
    let mut b = minimal();
    b.str_off = Some(0xffff_ff00);
    rejects(b.build(), Reason::SectionOffsetOutOfRange);
}

#[test]
fn trailing_data_after_sections() {
    let mut b = minimal();
    b.trailer = vec![0xaa, 0xbb, 0xcc, 0xdd];
    rejects(b.build(), Reason::TrailingData);
}

#[test]
fn string_section_must_be_last() {
    // Put the strings first and the types after. The tiling rule can be
    // satisfied that way, but "the string section ends at the end of the
    // blob" cannot be, and that is what makes every name NUL-terminated.
    // A layout that tiles perfectly — 8 bytes of "strings" then 16 bytes of
    // types — but puts the string section first. The three trailing bytes
    // pad the blob to the 24 the two sections claim.
    let mut b = minimal();
    b.trailer = vec![0, 0, 0];
    b.str_off = Some(0);
    b.str_len = Some(8);
    b.type_off = Some(8);
    b.type_len = Some(16);
    rejects(b.build(), Reason::StringSectionNotAtEnd);
}

#[test]
fn string_section_not_nul_delimited() {
    let mut blob = minimal().build();
    let len = blob.len();

    // First byte of the string section must be NUL — that is what makes
    // `name_off == 0` mean "anonymous".
    let mut blob2 = blob.clone();
    blob2[len - 5] = b'x';
    rejects(blob2, Reason::StringSectionInvalid);

    // Last byte must be NUL — that is what makes every name terminated.
    blob[len - 1] = b'x';
    rejects(blob, Reason::StringSectionInvalid);
}

#[test]
fn empty_string_section() {
    // A blob with no string section at all: the tiling holds and the section
    // ends where the blob ends, so only the "must not be empty" rule catches
    // it. Hand-built, because the builder always emits the leading NUL.
    let mut b = Builder::new();
    let n = b.name("int");
    b.ty(n, info(K_INT, 0, false), 4);
    b.word(int_data(0, 0, 32));
    let with_strings = b.build();
    let type_len = 16u32;

    let mut blob = with_strings[..24 + type_len as usize].to_vec();
    poke(&mut blob, 8, 0); // type_off
    poke(&mut blob, 12, type_len);
    poke(&mut blob, 16, type_len); // str_off
    poke(&mut blob, 20, 0); // str_len
    rejects(blob, Reason::StringSectionInvalid);
}

#[test]
fn unaligned_type_section() {
    // A misaligned `type_off` would make every field read straddle a word.
    // Checked before the tiling rule, because the tiling rule forces
    // `type_off == 0` for anything it accepts and would leave this
    // unreachable.
    let mut b = minimal();
    b.type_off = Some(2);
    rejects(b.build(), Reason::UnalignedTypeSection);
    b.type_off = Some(1);
    rejects(b.build(), Reason::UnalignedTypeSection);
}

#[test]
fn no_types() {
    let mut b = Builder::new();
    b.name("x");
    b.type_len = Some(0);
    b.str_off = Some(0);
    rejects(b.build(), Reason::NoTypes);
}

// ── per-type metadata ───────────────────────────────────────────────

#[test]
fn truncated_type_record() {
    let full = minimal().build();
    // Chop bytes off the type section by shrinking type_len and str_off in
    // lockstep. A record that runs past the section end must be rejected, not
    // read past.
    for chop in 1..12 {
        let mut b = minimal();
        let types_len = 16u32; // btf_type + int_data
        b.type_len = Some(types_len - chop);
        b.str_off = Some(types_len - chop);
        b.str_len = Some((full.len() - 24 - types_len as usize + chop as usize) as u32);
        // The blob bytes are unchanged; only the declared split moves, so the
        // last record is truncated and the leftovers land in the strings.
        let blob = b.build();
        let r = Btf::parse(blob);
        assert!(r.is_err(), "chop {chop} was accepted");
    }
}

#[test]
fn reserved_info_bits() {
    let mut b = Builder::new();
    let n = b.name("int");
    b.ty(n, info(K_INT, 0, false) | (1 << 20), 4);
    b.word(int_data(0, 0, 32));
    rejects(b.build(), Reason::InvalidInfo);
}

#[test]
fn invalid_kind() {
    for kind in [0u32, 20, 31] {
        let mut b = Builder::new();
        let n = b.name("x");
        b.ty(n, info(kind, 0, false), 4);
        b.word(0);
        rejects(b.build(), Reason::InvalidKind);
    }
}

#[test]
fn name_offset_past_string_section() {
    let mut b = Builder::new();
    b.ty(9999, info(K_INT, 0, false), 4);
    b.word(int_data(0, 0, 32));
    rejects(b.build(), Reason::InvalidNameOffset);
}

#[test]
fn typedef_needs_a_valid_identifier() {
    // Empty name.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    b.ty(0, info(K_TYPEDEF, 0, false), i);
    rejects(b.build(), Reason::InvalidName);

    // Leading digit.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("1bad");
    b.ty(n, info(K_TYPEDEF, 0, false), i);
    rejects(b.build(), Reason::InvalidName);

    // A space is not in the identifier character set.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("has space");
    b.ty(n, info(K_TYPEDEF, 0, false), i);
    rejects(b.build(), Reason::InvalidName);

    // Over-long.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let long = "a".repeat(513);
    let n = b.name(&long);
    b.ty(n, info(K_TYPEDEF, 0, false), i);
    rejects(b.build(), Reason::InvalidName);
}

#[test]
fn int_and_float_names_are_not_identifier_checked() {
    // `long long unsigned int` and `long double` are what clang emits, and
    // neither is an identifier. Rejecting them would reject every real blob.
    let mut b = Builder::new();
    let n = b.name("long long unsigned int");
    b.ty(n, info(K_INT, 0, false), 8);
    b.word(int_data(0, 0, 64));
    let n2 = b.name("long double");
    b.ty(n2, info(K_FLOAT, 0, false), 16);
    ok(b.build());
}

#[test]
fn qualifiers_must_be_anonymous() {
    for kind in [
        K_PTR,
        K_CONST,
        K_VOLATILE,
        K_RESTRICT,
        K_ARRAY,
        K_FUNC_PROTO,
    ] {
        let mut b = Builder::new();
        let i = b.int("int", 4);
        let n = b.name("nope");
        b.ty(n, info(kind, 0, false), if kind == K_ARRAY { 0 } else { i });
        if kind == K_ARRAY {
            b.word(i).word(i).word(1);
        }
        rejects(b.build(), Reason::InvalidName);
    }
}

#[test]
fn int_bit_arithmetic() {
    // offset + bits > 128.
    let mut b = Builder::new();
    let n = b.name("i");
    b.ty(n, info(K_INT, 0, false), 32);
    b.word(int_data(0, 200, 100));
    rejects(b.build(), Reason::IntBitsExceedU128);

    // Fits in 128 bits but not in the declared size.
    let mut b = Builder::new();
    let n = b.name("i");
    b.ty(n, info(K_INT, 0, false), 4);
    b.word(int_data(0, 0, 64));
    rejects(b.build(), Reason::IntBitsExceedSize);

    // Reserved bits in int_data.
    let mut b = Builder::new();
    let n = b.name("i");
    b.ty(n, info(K_INT, 0, false), 4);
    b.word(0xf000_0000);
    rejects(b.build(), Reason::IntDataInvalid);

    // Two encoding attributes at once.
    let mut b = Builder::new();
    let n = b.name("i");
    b.ty(n, info(K_INT, 0, false), 4);
    b.word(int_data(0b011, 0, 32));
    rejects(b.build(), Reason::IntEncodingUnsupported);
    assert_eq!(Reason::IntEncodingUnsupported.errno(), Errno::NotSupported);
}

#[test]
fn int_vlen_and_kflag_must_be_zero() {
    let mut b = Builder::new();
    let n = b.name("i");
    b.ty(n, info(K_INT, 3, false), 4);
    b.word(int_data(0, 0, 32));
    rejects(b.build(), Reason::VlenNotZero);

    let mut b = Builder::new();
    let n = b.name("i");
    b.ty(n, info(K_INT, 0, true), 4);
    b.word(int_data(0, 0, 32));
    rejects(b.build(), Reason::KindFlagNotZero);
}

#[test]
fn array_rules() {
    let mut base = Builder::new();
    let i = base.int("int", 4);
    base.ty(0, info(K_ARRAY, 0, false), 0);
    base.word(i).word(i).word(8);
    let arr_id = 2;
    ok(base.build());

    // size != 0.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(arr_id) + 8, 4);
    rejects(blob, Reason::SizeNotZero);

    // Element type 0 (void).
    let mut blob = base.build();
    poke(&mut blob, base.record_off(arr_id) + 12, 0);
    rejects(blob, Reason::InvalidElem);

    // Index type 0.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(arr_id) + 16, 0);
    rejects(blob, Reason::InvalidIndex);

    // Element type out of range.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(arr_id) + 12, 9999);
    rejects(blob, Reason::InvalidTypeId);

    // nelems * elem_size overflows u32.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(arr_id) + 20, 0x4000_0000);
    rejects(blob, Reason::ArraySizeOverflow);
}

#[test]
fn array_index_must_be_a_plain_int() {
    // A bitfield-shaped int cannot be an array index.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("odd");
    b.ty(n, info(K_INT, 0, false), 4);
    b.word(int_data(0, 0, 12));
    let odd = 2;
    b.ty(0, info(K_ARRAY, 0, false), 0);
    b.word(i).word(odd).word(4);
    rejects(b.build(), Reason::InvalidIndex);

    // A struct cannot be an index either.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("s");
    b.ty(n, info(K_STRUCT, 0, false), 4);
    let s = 2;
    b.ty(0, info(K_ARRAY, 0, false), 0);
    b.word(i).word(s).word(4);
    rejects(b.build(), Reason::InvalidIndex);
}

#[test]
fn array_of_bitfield_int() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("odd");
    b.ty(n, info(K_INT, 0, false), 4);
    b.word(int_data(0, 0, 12));
    let odd = 2;
    b.ty(0, info(K_ARRAY, 0, false), 0);
    b.word(odd).word(i).word(4);
    rejects(b.build(), Reason::InvalidArrayOfInt);
}

#[test]
fn struct_member_rules() {
    // A member that starts past the end of the struct. `> struct_size` and
    // not `>=`, because a trailing `char a[0]` legitimately starts exactly at
    // the end — so bit offset 32 in a 4-byte struct is allowed here and only
    // caught by the size check below.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 4);
    b.word(mn).word(i).word(40); // rounds up to byte 5 in a 4-byte struct
    rejects(b.build(), Reason::MemberOffsetExceedsStructSize);

    // Bit offset exactly at the end of the struct: past the *start* check,
    // caught by the size check.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 4);
    b.word(mn).word(i).word(32);
    rejects(b.build(), Reason::MemberExceedsStructSize);

    // Starts inside but ends outside.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 6);
    b.word(mn).word(i).word(24); // byte 3 + 4 bytes > 6
    rejects(b.build(), Reason::MemberExceedsStructSize);

    // Members must be in ascending bit-offset order.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("s");
    let a = b.name("a");
    let c = b.name("b");
    b.ty(sn, info(K_STRUCT, 2, false), 8);
    b.word(a).word(i).word(32);
    b.word(c).word(i).word(0);
    rejects(b.build(), Reason::MemberBitOffsetNotMonotonic);

    // Member type 0.
    let mut b = Builder::new();
    b.int("int", 4);
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 4);
    b.word(mn).word(0).word(0);
    rejects(b.build(), Reason::InvalidTypeId);

    // A forward declaration has no size, so it cannot be a member by value.
    let mut b = Builder::new();
    let fn_ = b.name("incomplete");
    b.ty(fn_, info(K_FWD, 0, false), 0);
    let fwd = 1;
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 8);
    b.word(mn).word(fwd).word(0);
    rejects(b.build(), Reason::TypeHasNoSize);
}

#[test]
fn union_members_start_at_zero() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let un = b.name("u");
    let a = b.name("a");
    let c = b.name("b");
    b.ty(un, info(K_UNION, 2, false), 8);
    b.word(a).word(i).word(0);
    b.word(c).word(i).word(32);
    rejects(b.build(), Reason::UnionMemberBitOffsetNotZero);
}

#[test]
fn member_bit_offset_rounds_up_in_u64() {
    // `bit_offset + 7` overflows u32 for this value; in u32 the round-up
    // wraps to 0 and the member looks like it starts at byte 0.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 4);
    b.word(mn).word(i).word(0xffff_fffb);
    rejects(b.build(), Reason::MemberOffsetExceedsStructSize);
}

#[test]
fn non_bitfield_member_must_be_byte_aligned() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let pn = b.name("p");
    b.ty(0, info(K_PTR, 0, false), i);
    let p = 2;
    let _ = pn;
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 16);
    b.word(mn).word(p).word(3); // bit 3 of a pointer member
    rejects(b.build(), Reason::MemberNotByteAligned);
}

#[test]
fn enum_rules() {
    for size in [0u32, 3, 16] {
        let mut b = Builder::new();
        let n = b.name("e");
        let vn = b.name("A");
        b.ty(n, info(K_ENUM, 1, false), size);
        b.word(vn).word(0);
        rejects(b.build(), Reason::EnumUnexpectedSize);
    }

    // An enumerator must be named.
    let mut b = Builder::new();
    let n = b.name("e");
    b.ty(n, info(K_ENUM, 1, false), 4);
    b.word(0).word(0);
    rejects(b.build(), Reason::InvalidName);

    // An absurd vlen runs past the type section rather than allocating for it.
    let mut b = Builder::new();
    let n = b.name("e");
    let vn = b.name("A");
    b.ty(n, info(K_ENUM, 0xffff, false), 4);
    b.word(vn).word(0);
    rejects(b.build(), Reason::TypeTruncated);
}

#[test]
fn enum64_rules() {
    let mut b = Builder::new();
    let n = b.name("e");
    let vn = b.name("A");
    b.ty(n, info(K_ENUM64, 0xffff, false), 8);
    b.word(vn).word(0).word(0);
    rejects(b.build(), Reason::TypeTruncated);
}

#[test]
fn fwd_rules() {
    // A forward declaration carries no type.
    let mut b = Builder::new();
    let n = b.name("f");
    b.ty(n, info(K_FWD, 0, false), 7);
    rejects(b.build(), Reason::TypeNotZero);

    // …and must be named.
    let mut b = Builder::new();
    b.ty(0, info(K_FWD, 0, false), 0);
    rejects(b.build(), Reason::InvalidName);
}

#[test]
fn func_rules() {
    // Linkage above BTF_FUNC_GLOBAL.
    let mut b = Builder::new();
    b.ty(0, info(K_FUNC_PROTO, 0, false), 0);
    let proto = 1;
    let n = b.name("f");
    b.ty(n, info(K_FUNC, 2, false), proto);
    rejects(b.build(), Reason::FuncLinkageInvalid);

    // `type` must name a FUNC_PROTO.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("f");
    b.ty(n, info(K_FUNC, 0, false), i);
    rejects(b.build(), Reason::FuncTypeNotProto);

    // …and must be named.
    let mut b = Builder::new();
    b.ty(0, info(K_FUNC_PROTO, 0, false), 0);
    b.ty(0, info(K_FUNC, 0, false), 1);
    rejects(b.build(), Reason::InvalidName);
}

#[test]
fn func_proto_rules() {
    // A return type with no size.
    let mut b = Builder::new();
    let fwn = b.name("incomplete");
    b.ty(fwn, info(K_FWD, 0, false), 0);
    b.ty(0, info(K_FUNC_PROTO, 0, false), 1);
    rejects(b.build(), Reason::FuncProtoTypeNoSize);

    // A named vararg is a contradiction.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let pn = b.name("x");
    b.ty(0, info(K_FUNC_PROTO, 1, false), i);
    b.word(pn).word(0);
    rejects(b.build(), Reason::FuncProtoNamedVararg);

    // A void parameter that is not the last one.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    b.ty(0, info(K_FUNC_PROTO, 2, false), i);
    b.word(0).word(0);
    b.word(0).word(i);
    rejects(b.build(), Reason::FuncProtoTypeNoSize);

    // An unnamed trailing vararg is fine.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let pn = b.name("x");
    b.ty(0, info(K_FUNC_PROTO, 2, false), i);
    b.word(pn).word(i);
    b.word(0).word(0);
    ok(b.build());
}

#[test]
fn var_rules() {
    // Unsupported linkage (BTF_VAR_GLOBAL_EXTERN).
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("v");
    b.ty(n, info(K_VAR, 0, false), i);
    b.word(2);
    rejects(b.build(), Reason::VarLinkageUnsupported);

    // A variable of a sizeless type.
    let mut b = Builder::new();
    let fwn = b.name("incomplete");
    b.ty(fwn, info(K_FWD, 0, false), 0);
    let n = b.name("v");
    b.ty(n, info(K_VAR, 0, false), 1);
    b.word(1);
    rejects(b.build(), Reason::TypeHasNoSize);
}

#[test]
fn datasec_rules() {
    let mut base = Builder::new();
    let i = base.int("int", 4);
    let vn = base.name("v");
    base.ty(vn, info(K_VAR, 0, false), i);
    base.word(1);
    let var = 2;
    let dn = base.name(".data");
    base.ty(dn, info(K_DATASEC, 1, false), 4);
    base.word(var).word(0).word(4);
    let ds = 3;
    ok(base.build());

    // size == 0.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(ds) + 8, 0);
    rejects(blob, Reason::DatasecSizeZero);

    // A member size of 0.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(ds) + 20, 0);
    rejects(blob, Reason::DatasecSizeInvalid);

    // offset + size past the section.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(ds) + 16, 2);
    rejects(blob, Reason::DatasecOffsetSizeInvalid);

    // offset + size overflowing u32 must not wrap into range.
    let mut blob = base.build();
    poke(&mut blob, base.record_off(ds) + 8, 0xffff_ffff);
    poke(&mut blob, base.record_off(ds) + 16, 0xffff_fffe);
    poke(&mut blob, base.record_off(ds) + 20, 4);
    rejects(blob, Reason::DatasecOffsetSizeInvalid);

    // vlen == 0.
    let mut b = Builder::new();
    let dn = b.name(".data");
    b.ty(dn, info(K_DATASEC, 0, false), 4);
    rejects(b.build(), Reason::DatasecVlenZero);

    // A member that is not a VAR.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let dn = b.name(".data");
    b.ty(dn, info(K_DATASEC, 1, false), 4);
    b.word(i).word(0).word(4);
    rejects(b.build(), Reason::DatasecMemberNotVar);

    // A member smaller than the variable it describes.
    let mut b = Builder::new();
    let i = b.int("int", 8);
    let vn = b.name("v");
    b.ty(vn, info(K_VAR, 0, false), i);
    b.word(1);
    let dn = b.name(".data");
    b.ty(dn, info(K_DATASEC, 1, false), 8);
    b.word(2).word(0).word(4);
    rejects(b.build(), Reason::DatasecVarTooSmall);
}

#[test]
fn datasec_members_must_not_overlap() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let vn = b.name("v");
    b.ty(vn, info(K_VAR, 0, false), i);
    b.word(1);
    let dn = b.name(".data");
    b.ty(dn, info(K_DATASEC, 2, false), 8);
    b.word(2).word(0).word(4);
    b.word(2).word(2).word(4); // starts inside the previous member
    rejects(b.build(), Reason::DatasecOffsetInvalid);
}

#[test]
fn float_rules() {
    for size in [0u32, 1, 3, 5, 32] {
        let mut b = Builder::new();
        let n = b.name("f");
        b.ty(n, info(K_FLOAT, 0, false), size);
        rejects(b.build(), Reason::FloatSizeInvalid);
    }
}

#[test]
fn decl_tag_rules() {
    // component_idx < -1.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let vn = b.name("v");
    b.ty(vn, info(K_VAR, 0, false), i);
    b.word(1);
    let tn = b.name("tag");
    b.ty(tn, info(K_DECL_TAG, 0, false), 2);
    b.word((-2i32) as u32);
    rejects(b.build(), Reason::DeclTagComponentIdxInvalid);

    // component_idx on a variable.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let vn = b.name("v");
    b.ty(vn, info(K_VAR, 0, false), i);
    b.word(1);
    let tn = b.name("tag");
    b.ty(tn, info(K_DECL_TAG, 0, false), 2);
    b.word(0);
    rejects(b.build(), Reason::DeclTagComponentIdxInvalid);

    // component_idx past the struct's member count.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 4);
    b.word(mn).word(i).word(0);
    let tn = b.name("tag");
    b.ty(tn, info(K_DECL_TAG, 0, false), 2);
    b.word(1);
    rejects(b.build(), Reason::DeclTagComponentIdxInvalid);

    // A target that cannot carry a tag.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let tn = b.name("tag");
    b.ty(tn, info(K_DECL_TAG, 0, false), i);
    b.word((-1i32) as u32);
    rejects(b.build(), Reason::DeclTagTargetInvalid);

    // An empty tag value.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let vn = b.name("v");
    b.ty(vn, info(K_VAR, 0, false), i);
    b.word(1);
    b.ty(0, info(K_DECL_TAG, 0, false), 2);
    b.word((-1i32) as u32);
    rejects(b.build(), Reason::InvalidName);
}

// ── the graph ───────────────────────────────────────────────────────

#[test]
fn type_id_out_of_range() {
    let mut b = Builder::new();
    let _ = b.int("int", 4);
    let n = b.name("t");
    b.ty(n, info(K_TYPEDEF, 0, false), 9999);
    rejects(b.build(), Reason::InvalidTypeId);
}

#[test]
fn pointer_to_out_of_range_type_id() {
    // A pointer is not an edge in the cycle graph, so the DFS never looks at
    // its target — `check_id_bounds` is the only thing standing between a
    // dangling `type_id` and a consumer that trusts it. Removing that pass
    // makes exactly this test go red and nothing else.
    let mut b = Builder::new();
    b.int("int", 4);
    b.ty(0, info(K_PTR, 0, false), 9999);
    rejects(b.build(), Reason::InvalidTypeId);
}

#[test]
fn type_id_above_btf_max_type() {
    let mut b = Builder::new();
    let _ = b.int("int", 4);
    let n = b.name("t");
    b.ty(n, info(K_TYPEDEF, 0, false), 0x0010_0000);
    rejects(b.build(), Reason::InvalidTypeId);
}

#[test]
fn typedef_self_cycle() {
    let mut b = Builder::new();
    let n = b.name("t");
    b.ty(n, info(K_TYPEDEF, 0, false), 1);
    rejects(b.build(), Reason::TypeCycle);
}

#[test]
fn modifier_cycle() {
    // const → volatile → typedef → const.
    let mut b = Builder::new();
    b.ty(0, info(K_CONST, 0, false), 2);
    b.ty(0, info(K_VOLATILE, 0, false), 3);
    let n = b.name("t");
    b.ty(n, info(K_TYPEDEF, 0, false), 1);
    rejects(b.build(), Reason::TypeCycle);
}

#[test]
fn struct_contains_itself_by_value() {
    let mut b = Builder::new();
    let sn = b.name("s");
    let mn = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, false), 8);
    b.word(mn).word(1).word(0);
    rejects(b.build(), Reason::TypeCycle);
}

#[test]
fn array_of_itself() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    b.ty(0, info(K_ARRAY, 0, false), 0);
    b.word(2).word(i).word(4);
    rejects(b.build(), Reason::TypeCycle);
}

#[test]
fn self_referential_struct_through_a_pointer_is_fine() {
    // `struct list { struct list *next; }` — the shape the cycle rule must
    // *not* reject, and the reason PTR is not an edge in the cycle graph.
    let mut b = Builder::new();
    let sn = b.name("list");
    let mn = b.name("next");
    b.ty(sn, info(K_STRUCT, 1, false), 8);
    b.word(mn).word(2).word(0);
    b.ty(0, info(K_PTR, 0, false), 1);
    let btf = ok(b.build());
    assert_eq!(btf.size_of(1), Some(8));
    assert_eq!(btf.size_of(2), Some(8));
}

#[test]
fn mutually_recursive_structs_through_pointers() {
    let mut b = Builder::new();
    let an = b.name("a");
    let bn = b.name("b");
    let m = b.name("p");
    b.ty(an, info(K_STRUCT, 1, false), 8);
    b.word(m).word(4).word(0); // struct a { struct b *p; }
    b.ty(bn, info(K_STRUCT, 1, false), 8);
    b.word(m).word(3).word(0); // struct b { struct a *p; }
    b.ty(0, info(K_PTR, 0, false), 1);
    b.ty(0, info(K_PTR, 0, false), 2);
    ok(b.build());
}

#[test]
fn deep_typedef_chain_does_not_overflow_the_stack() {
    // The DFS is explicit-stack precisely so this is a parse, not a crash.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let n = b.name("t");
    for k in 0..20_000u32 {
        b.ty(n, info(K_TYPEDEF, 0, false), if k == 0 { i } else { k + 1 });
    }
    let btf = ok(b.build());
    assert_eq!(btf.size_of(btf.nr_types()), Some(4));
    assert_eq!(btf.skip_modifiers(btf.nr_types()), i);
}

#[test]
fn skip_modifiers_and_sizes() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    b.ty(0, info(K_CONST, 0, false), i);
    let c = 2;
    let tn = b.name("my_int");
    b.ty(tn, info(K_TYPEDEF, 0, false), c);
    let td = 3;
    b.ty(0, info(K_ARRAY, 0, false), 0);
    b.word(td).word(i).word(10);
    let arr = 4;
    let btf = ok(b.build());

    assert_eq!(btf.skip_modifiers(c), i);
    assert_eq!(btf.skip_modifiers(td), i);
    assert_eq!(btf.size_of(td), Some(4));
    assert_eq!(btf.size_of(arr), Some(40));
    // void resolves to void and has no size.
    assert_eq!(btf.skip_modifiers(0), 0);
    assert_eq!(btf.size_of(0), None);
    // Out of range is None, not a panic.
    assert_eq!(btf.size_of(99), None);
    assert!(btf.type_by_id(0).is_none());
    assert!(btf.type_by_id(99).is_none());
}

#[test]
fn const_void_has_no_size() {
    let mut b = Builder::new();
    b.int("int", 4);
    b.ty(0, info(K_CONST, 0, false), 0);
    let btf = ok(b.build());
    assert_eq!(btf.size_of(2), None);
    assert_eq!(btf.skip_modifiers(2), 0);
}

// ── round trip ──────────────────────────────────────────────────────

/// Hand-build a blob covering every kind and assert the decoded graph is
/// exactly what was encoded.
#[test]
#[allow(clippy::too_many_lines)]
fn round_trip_every_kind() {
    let mut b = Builder::new();

    let n_int = b.name("int");
    let int_id = b.ty(n_int, info(K_INT, 0, false), 4);
    b.word(int_data(1 /* SIGNED */, 0, 32));

    let ptr_id = b.ty(0, info(K_PTR, 0, false), int_id);

    let arr_id = b.ty(0, info(K_ARRAY, 0, false), 0);
    b.word(int_id).word(int_id).word(6);

    let n_s = b.name("s");
    let n_a = b.name("a");
    let n_b = b.name("b");
    let struct_id = b.ty(n_s, info(K_STRUCT, 2, false), 12);
    b.word(n_a).word(int_id).word(0);
    b.word(n_b).word(ptr_id).word(32);

    let n_u = b.name("u");
    let union_id = b.ty(n_u, info(K_UNION, 1, false), 8);
    b.word(n_a).word(ptr_id).word(0);

    let n_e = b.name("e");
    let n_e0 = b.name("E0");
    let enum_id = b.ty(n_e, info(K_ENUM, 1, false), 4);
    b.word(n_e0).word((-3i32) as u32);

    let n_e64 = b.name("e64");
    let enum64_id = b.ty(n_e64, info(K_ENUM64, 1, true), 8);
    b.word(n_e0).word(0xdead_beef).word(0x0000_00ff);

    let n_fwd = b.name("fwd_union");
    let fwd_id = b.ty(n_fwd, info(K_FWD, 0, true), 0);

    let n_td = b.name("my_int");
    let td_id = b.ty(n_td, info(K_TYPEDEF, 0, false), int_id);

    let const_id = b.ty(0, info(K_CONST, 0, false), td_id);
    let vol_id = b.ty(0, info(K_VOLATILE, 0, false), const_id);
    let restrict_id = b.ty(0, info(K_RESTRICT, 0, false), ptr_id);

    let n_tag = b.name("rcu");
    let type_tag_id = b.ty(n_tag, info(K_TYPE_TAG, 0, false), ptr_id);

    let n_p = b.name("x");
    let proto_id = b.ty(0, info(K_FUNC_PROTO, 2, false), int_id);
    b.word(n_p).word(int_id);
    b.word(0).word(0); // vararg

    let n_f = b.name("f");
    let func_id = b.ty(n_f, info(K_FUNC, 1, false), proto_id);

    let n_v = b.name("v");
    let var_id = b.ty(n_v, info(K_VAR, 0, false), struct_id);
    b.word(1); // BTF_VAR_GLOBAL_ALLOCATED

    let n_ds = b.name(".data");
    let ds_id = b.ty(n_ds, info(K_DATASEC, 1, false), 16);
    b.word(var_id).word(0).word(12);

    let n_fl = b.name("float");
    let float_id = b.ty(n_fl, info(K_FLOAT, 0, false), 4);

    let n_dt = b.name("user");
    let dt_id = b.ty(n_dt, info(K_DECL_TAG, 0, false), struct_id);
    b.word(1u32); // component_idx = 1 → member `b`

    let btf = ok(b.build());
    assert_eq!(btf.nr_types(), dt_id);

    assert_eq!(
        btf.type_by_id(int_id),
        Some(&BtfType::Int {
            name_off: n_int,
            size: 4,
            encoding: IntEncoding::Signed,
            bit_offset: 0,
            nr_bits: 32,
        })
    );
    assert_eq!(btf.name(n_int), Some("int"));

    assert_eq!(
        btf.type_by_id(ptr_id),
        Some(&BtfType::Ptr { type_id: int_id })
    );

    assert_eq!(
        btf.type_by_id(arr_id),
        Some(&BtfType::Array {
            elem_type: int_id,
            index_type: int_id,
            nelems: 6,
        })
    );
    assert_eq!(btf.size_of(arr_id), Some(24));

    assert_eq!(
        btf.type_by_id(struct_id),
        Some(&BtfType::Composite {
            name_off: n_s,
            is_union: false,
            size: 12,
            kind_flag: false,
            members: vec![
                Member {
                    name_off: n_a,
                    type_id: int_id,
                    bit_offset: 0,
                    bitfield_size: 0
                },
                Member {
                    name_off: n_b,
                    type_id: ptr_id,
                    bit_offset: 32,
                    bitfield_size: 0
                },
            ],
        })
    );

    assert_eq!(
        btf.type_by_id(union_id),
        Some(&BtfType::Composite {
            name_off: n_u,
            is_union: true,
            size: 8,
            kind_flag: false,
            members: vec![Member {
                name_off: n_a,
                type_id: ptr_id,
                bit_offset: 0,
                bitfield_size: 0
            }],
        })
    );

    assert_eq!(
        btf.type_by_id(enum_id),
        Some(&BtfType::Enum {
            name_off: n_e,
            size: 4,
            signed: false,
            values: vec![EnumValue {
                name_off: n_e0,
                val: -3
            }],
        })
    );

    assert_eq!(
        btf.type_by_id(enum64_id),
        Some(&BtfType::Enum64 {
            name_off: n_e64,
            size: 8,
            signed: true,
            values: vec![Enum64Value {
                name_off: n_e0,
                val: 0x0000_00ff_dead_beef
            }],
        })
    );

    assert_eq!(
        btf.type_by_id(fwd_id),
        Some(&BtfType::Fwd {
            name_off: n_fwd,
            is_union: true
        })
    );
    assert_eq!(btf.size_of(fwd_id), None);

    assert_eq!(
        btf.type_by_id(td_id),
        Some(&BtfType::Typedef {
            name_off: n_td,
            type_id: int_id
        })
    );
    assert_eq!(
        btf.type_by_id(const_id),
        Some(&BtfType::Qualifier {
            kind: Kind::Const,
            type_id: td_id
        })
    );
    assert_eq!(
        btf.type_by_id(vol_id),
        Some(&BtfType::Qualifier {
            kind: Kind::Volatile,
            type_id: const_id
        })
    );
    assert_eq!(
        btf.type_by_id(restrict_id),
        Some(&BtfType::Qualifier {
            kind: Kind::Restrict,
            type_id: ptr_id
        })
    );
    assert_eq!(btf.skip_modifiers(vol_id), int_id);

    assert_eq!(
        btf.type_by_id(type_tag_id),
        Some(&BtfType::TypeTag {
            name_off: n_tag,
            type_id: ptr_id
        })
    );

    assert_eq!(
        btf.type_by_id(proto_id),
        Some(&BtfType::FuncProto {
            ret_type: int_id,
            params: vec![
                Param {
                    name_off: n_p,
                    type_id: int_id
                },
                Param {
                    name_off: 0,
                    type_id: 0
                },
            ],
        })
    );
    assert_eq!(
        btf.type_by_id(func_id),
        Some(&BtfType::Func {
            name_off: n_f,
            linkage: FuncLinkage::Global,
            proto: proto_id,
        })
    );

    assert_eq!(
        btf.type_by_id(var_id),
        Some(&BtfType::Var {
            name_off: n_v,
            type_id: struct_id,
            linkage: VarLinkage::GlobalAllocated,
        })
    );

    assert_eq!(
        btf.type_by_id(ds_id),
        Some(&BtfType::DataSec {
            name_off: n_ds,
            size: 16,
            vars: vec![SecInfo {
                type_id: var_id,
                offset: 0,
                size: 12
            }],
        })
    );

    assert_eq!(
        btf.type_by_id(float_id),
        Some(&BtfType::Float {
            name_off: n_fl,
            size: 4
        })
    );

    assert_eq!(
        btf.type_by_id(dt_id),
        Some(&BtfType::DeclTag {
            name_off: n_dt,
            type_id: struct_id,
            component_idx: 1,
        })
    );

    // The raw bytes survive for `BPF_OBJ_GET_INFO_BY_FD`.
    assert_eq!(
        btf.raw().len(),
        btf.header().hdr_len as usize
            + btf.header().type_len as usize
            + btf.header().str_len as usize
    );

    // Iteration order is declaration order.
    let ids: Vec<u32> = btf.iter().map(|(id, _)| id).collect();
    assert_eq!(ids, (1..=dt_id).collect::<Vec<_>>());
}

#[test]
fn kind_flag_bitfields_round_trip() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("bits");
    let a = b.name("a");
    let c = b.name("b");
    b.ty(sn, info(K_STRUCT, 2, true), 4);
    // bitfield_size in the top byte, bit offset in the low 24.
    b.word(a).word(i).word(3u32 << 24);
    b.word(c).word(i).word((5u32 << 24) | 3);
    let btf = ok(b.build());
    let Some(BtfType::Composite {
        members, kind_flag, ..
    }) = btf.type_by_id(2)
    else {
        panic!("not a struct");
    };
    assert!(*kind_flag);
    assert_eq!(members[0].bitfield_size, 3);
    assert_eq!(members[0].bit_offset, 0);
    assert_eq!(members[1].bitfield_size, 5);
    assert_eq!(members[1].bit_offset, 3);
}

#[test]
fn kind_flag_bitfield_past_the_struct() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    let sn = b.name("bits");
    let a = b.name("a");
    b.ty(sn, info(K_STRUCT, 1, true), 4);
    b.word(a).word(i).word((8u32 << 24) | 30); // bits 30..38 of a 32-bit struct
    rejects(b.build(), Reason::MemberExceedsStructSize);
}

#[test]
fn non_kflag_bitfield_uses_the_ints_own_width() {
    // `struct { char c; int a:1; }` — the member sits at bit 8 and its int
    // type is 4 bytes wide, which a naive `offset/8 + size <= struct_size`
    // check would reject.
    let mut b = Builder::new();
    let c = b.int("char", 1);
    let n = b.name("int");
    b.ty(n, info(K_INT, 0, false), 4);
    b.word(int_data(0, 0, 1));
    let bitint = 2;
    let sn = b.name("s");
    let mc = b.name("c");
    let ma = b.name("a");
    b.ty(sn, info(K_STRUCT, 2, false), 4);
    b.word(mc).word(c).word(0);
    b.word(ma).word(bitint).word(8);
    ok(b.build());
}

// ── nothing panics ──────────────────────────────────────────────────

#[test]
fn single_byte_mutations_never_panic() {
    // A valid blob with every byte set to each of a handful of hostile
    // values, one at a time. The assertion is only that `parse` returns —
    // this is the property that matters, because a panic here is a kernel
    // panic driven by a syscall argument.
    let mut b = Builder::new();
    let i = b.int("int", 4);
    b.ty(0, info(K_PTR, 0, false), i);
    b.ty(0, info(K_ARRAY, 0, false), 0);
    b.word(i).word(i).word(4);
    let sn = b.name("s");
    let mn = b.name("m");
    b.ty(sn, info(K_STRUCT, 1, false), 8);
    b.word(mn).word(2).word(0);
    let base = b.build();
    ok(base.clone());

    for pos in 0..base.len() {
        for v in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
            let mut blob = base.clone();
            blob[pos] = v;
            // Result ignored on purpose: the test is that this returns.
            let _ = Btf::parse(blob);
        }
    }
}

#[test]
fn truncation_at_every_length_never_panics() {
    let mut b = Builder::new();
    let i = b.int("int", 4);
    b.ty(0, info(K_PTR, 0, false), i);
    let base = b.build();
    for n in 0..=base.len() {
        let _ = Btf::parse(base[..n].to_vec());
    }
}

#[test]
fn oversized_blob() {
    // One byte over the limit, without actually building 16 MiB of BTF.
    let blob = vec![0u8; crate::MAX_BTF_SIZE + 1];
    rejects(blob, Reason::BlobTooLarge);
    assert_eq!(Reason::BlobTooLarge.errno(), Errno::TooBig);
}

#[test]
fn errno_classes_are_stable() {
    // The three errno classes are the syscall's contract; a rejection that
    // silently changed class would change what a loader does about it.
    assert_eq!(Reason::TypeCycle.errno(), Errno::Invalid);
    assert_eq!(Reason::InvalidTypeId.errno(), Errno::Invalid);
    assert_eq!(Reason::TooManyTypes.errno(), Errno::TooBig);
    assert_eq!(Reason::BadMagic.errno(), Errno::Invalid);
    // Every reason has a non-empty message for the log buffer.
    for r in [
        Reason::BlobEmpty,
        Reason::TypeCycle,
        Reason::MemberNotByteAligned,
        Reason::DatasecVarTooSmall,
    ] {
        assert!(!r.message().is_empty());
    }
}
