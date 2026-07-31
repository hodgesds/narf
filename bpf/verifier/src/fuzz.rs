//! Differential fuzzing of the abstract domain against concrete semantics.
//!
//! Every test here checks the one property that matters for a verifier:
//! **soundness**, `f(γ(A)) ⊆ γ(f#(A))`. If a concrete result ever escapes the
//! abstract result, the verifier can prove a false bound and the JIT will emit
//! an unchecked access from it. Precision loss is a rejected program; soundness
//! loss is a kernel compromise, so only soundness is asserted — never that the
//! abstract result is *tight*.
//!
//! Seeds are fixed. A verifier test that fails one run in fifty is a test that
//! gets marked flaky and then ignored, and the one thing worse than no
//! differential fuzzing is differential fuzzing nobody reads the output of.

use alloc::vec::Vec;

use narf_bpf_isa::{AluOp, ByteOrder, CondOp};

use narf_bpf_isa::Size;

use crate::domain::{Scalar, Tnum};
use crate::interp;
use crate::state::{AbsValue, Stack};

/// xorshift64*, so the corpus is reproducible without a dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Values chosen to sit on every boundary the domain reasons about.
const INTERESTING: &[u64] = &[
    0,
    1,
    2,
    7,
    8,
    63,
    64,
    255,
    256,
    0xffff,
    0x1_0000,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff_ffff_ffff,
    0xdead_beef_cafe_babe,
];

fn sample_value(rng: &mut Rng) -> u64 {
    match rng.below(4) {
        0 => INTERESTING[rng.below(INTERESTING.len() as u64) as usize],
        1 => rng.below(1024),
        2 => INTERESTING[rng.below(INTERESTING.len() as u64) as usize]
            .wrapping_add(rng.below(5))
            .wrapping_sub(2),
        _ => rng.next(),
    }
}

/// Build an abstract value together with concrete members of it.
///
/// Constructed as the join of a handful of constants, so membership of the
/// generators is guaranteed by the lattice rather than by a filter — which
/// means a bug in `join` shows up as a *failure* here rather than as a silently
/// empty corpus.
fn sample_abstract(rng: &mut Rng) -> (Scalar, Vec<u64>) {
    let k = 1 + rng.below(4) as usize;
    let mut members = Vec::with_capacity(k);
    let mut abs = None;
    for _ in 0..k {
        let v = sample_value(rng);
        members.push(v);
        let c = Scalar::constant(v as i64);
        abs = Some(match abs {
            None => c,
            Some(a) => Scalar::join(&a, &c),
        });
    }
    let mut abs = abs.expect("k >= 1");

    // Half the time, loosen it further so widened and top-ish states are
    // exercised too, not just tight joins of constants.
    if rng.below(2) == 0 {
        let extra_mask = rng.next();
        abs = Scalar {
            tnum: Tnum {
                value: abs.tnum.value & !extra_mask,
                mask: abs.tnum.mask | extra_mask,
            },
            min: abs.min.saturating_sub(rng.below(1 << 20) as i64),
            max: abs.max.saturating_add(rng.below(1 << 20) as i64),
        }
        .normalized();
    }

    for &m in &members {
        assert!(
            abs.contains(m),
            "generator {m:#x} escaped its own abstraction {abs:?}"
        );
    }
    (abs, members)
}

fn check<F, G>(seed: u64, name: &str, concrete: F, abstract_: G)
where
    F: Fn(u64, u64) -> u64,
    G: Fn(&Scalar, &Scalar) -> Scalar,
{
    let mut rng = Rng::new(seed);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let (b, bvs) = sample_abstract(&mut rng);
        let r = abstract_(&a, &b);
        for &x in &avs {
            for &y in &bvs {
                let c = concrete(x, y);
                assert!(
                    r.contains(c),
                    "{name}: {x:#x} op {y:#x} = {c:#x} escaped {r:?}\n  lhs {a:?}\n  rhs {b:?}"
                );
            }
        }
    }
}

// ─── Instruction-level transfers, both widths ───────────────────────
//
// These drive the abstract side through the *same* dispatch the verifier's
// transfer function uses (`Scalar::alu`, `div_op`, `mod_op`, …), against the
// reference interpreter's dispatch. Fuzzing only the 64-bit primitives would
// leave the 32-bit forms — where the zero-extension and the arithmetic-shift
// sign handling live, and where the subtle bugs are — covered by nothing.

const ALU_OPS: &[AluOp] = &[
    AluOp::Add,
    AluOp::Sub,
    AluOp::Mul,
    AluOp::Or,
    AluOp::And,
    AluOp::Xor,
    AluOp::Lsh,
    AluOp::Rsh,
    AluOp::Arsh,
];

#[test]
fn every_alu_op_is_sound_in_both_widths() {
    let mut rng = Rng::new(30);
    for _ in 0..8_000 {
        let (a, avs) = sample_abstract(&mut rng);
        // Shifts only say anything about a constant amount, so half the
        // right-hand sides are drawn as constants.
        let (b, bvs) = if rng.below(2) == 0 {
            let n = rng.below(70);
            (Scalar::constant(n as i64), alloc::vec![n])
        } else {
            sample_abstract(&mut rng)
        };
        for &op in ALU_OPS {
            for wide in [true, false] {
                let r = a.alu(op, wide, &b);
                for &x in &avs {
                    for &y in &bvs {
                        let c = interp::alu(op, wide, x, y);
                        assert!(
                            r.contains(c),
                            "{op:?} wide={wide}: {x:#x} op {y:#x} = {c:#x} escaped {r:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn division_and_modulo_are_sound_in_both_widths_and_signednesses() {
    let mut rng = Rng::new(31);
    for _ in 0..8_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let (b, bvs) = sample_abstract(&mut rng);
        for wide in [true, false] {
            for signed in [true, false] {
                let d = a.div_op(wide, signed, &b);
                let m = a.mod_op(wide, signed, &b);
                for &x in &avs {
                    for &y in &bvs {
                        assert!(
                            d.contains(interp::div(wide, signed, x, y)),
                            "div wide={wide} signed={signed}: {x:#x}/{y:#x} escaped {d:?}"
                        );
                        assert!(
                            m.contains(interp::rem(wide, signed, x, y)),
                            "mod wide={wide} signed={signed}: {x:#x}%{y:#x} escaped {m:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn moves_negations_and_byte_swaps_are_sound() {
    let mut rng = Rng::new(32);
    for _ in 0..10_000 {
        let (a, avs) = sample_abstract(&mut rng);
        for wide in [true, false] {
            let n = a.neg_op(wide);
            for &x in &avs {
                let c = if wide {
                    (x as i64).wrapping_neg() as u64
                } else {
                    u64::from((x as u32).wrapping_neg())
                };
                assert!(
                    n.contains(c),
                    "neg wide={wide}: {x:#x} → {c:#x} escaped {n:?}"
                );
            }
            for sx in [None, Some(8u8), Some(16), Some(32)] {
                let m = a.mov_op(wide, sx);
                for &x in &avs {
                    let c = match (sx, wide) {
                        (Some(bits), true) => interp::sext(x, u32::from(bits)),
                        (Some(bits), false) => u64::from(interp::sext(x, u32::from(bits)) as u32),
                        (None, true) => x,
                        (None, false) => u64::from(x as u32),
                    };
                    assert!(m.contains(c), "mov wide={wide} sx={sx:?}: {x:#x} → {c:#x}");
                }
            }
        }
        for order in [ByteOrder::Little, ByteOrder::Big, ByteOrder::Swap] {
            for width in [16u8, 32, 64] {
                let e = a.end_op(order, width);
                for &x in &avs {
                    let c = interp::end(order, width, x);
                    assert!(
                        e.contains(c),
                        "end {order:?}/{width}: {x:#x} → {c:#x} escaped {e:?}"
                    );
                }
            }
        }
    }
}

// ─── Transfer functions, per instruction class ──────────────────────

#[test]
fn add_is_sound() {
    check(1, "add", |a, b| a.wrapping_add(b), Scalar::add);
}

#[test]
fn sub_is_sound() {
    check(2, "sub", |a, b| a.wrapping_sub(b), Scalar::sub);
}

#[test]
fn mul_is_sound() {
    check(3, "mul", |a, b| a.wrapping_mul(b), Scalar::mul);
}

#[test]
fn and_is_sound() {
    check(4, "and", |a, b| a & b, Scalar::and);
}

#[test]
fn or_is_sound() {
    check(5, "or", |a, b| a | b, Scalar::or);
}

#[test]
fn xor_is_sound() {
    check(6, "xor", |a, b| a ^ b, Scalar::xor);
}

#[test]
fn shifts_are_sound() {
    // Shift amounts must be constants for the abstract form to say anything,
    // so they are drawn separately rather than through `sample_abstract`.
    let mut rng = Rng::new(7);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let n = rng.below(70); // deliberately past 63, to exercise masking
        let sn = Scalar::constant(n as i64);
        let (shl, shr, sar) = (a.shl(&sn), a.shr(&sn), a.sar(&sn));
        for &x in &avs {
            assert!(
                shl.contains(interp::alu(AluOp::Lsh, true, x, n)),
                "shl {x:#x} << {n}"
            );
            assert!(
                shr.contains(interp::alu(AluOp::Rsh, true, x, n)),
                "shr {x:#x} >> {n}"
            );
            assert!(
                sar.contains(interp::alu(AluOp::Arsh, true, x, n)),
                "sar {x:#x} >> {n}"
            );
        }
    }
}

#[test]
fn unsigned_div_and_mod_are_sound() {
    check(8, "udiv", crate::domain::concrete_udiv, Scalar::udiv);
    check(9, "umod", crate::domain::concrete_umod, Scalar::umod);
}

#[test]
fn signed_div_and_mod_are_sound() {
    check(
        10,
        "sdiv",
        |a, b| crate::domain::concrete_sdiv(a as i64, b as i64) as u64,
        Scalar::sdiv,
    );
    check(
        11,
        "smod",
        |a, b| crate::domain::concrete_smod(a as i64, b as i64) as u64,
        Scalar::smod,
    );
}

#[test]
fn neg_is_sound() {
    let mut rng = Rng::new(12);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let r = a.neg();
        for &x in &avs {
            assert!(
                r.contains((x as i64).wrapping_neg() as u64),
                "neg {x:#x} in {r:?}"
            );
        }
    }
}

#[test]
fn subregister_views_are_sound() {
    let mut rng = Rng::new(13);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let z = a.zext32();
        let s = a.sext32();
        for &x in &avs {
            assert!(
                z.contains(u64::from(x as u32)),
                "zext32 {x:#x} in {z:?} from {a:?}"
            );
            assert!(
                s.contains(interp::sext(x, 32)),
                "sext32 {x:#x} in {s:?} from {a:?}"
            );
        }
        for bits in [8u32, 16, 32] {
            let e = a.sign_extend(bits);
            for &x in &avs {
                assert!(
                    e.contains(interp::sext(x, bits)),
                    "sext{bits} {x:#x} in {e:?} from {a:?}"
                );
            }
        }
    }
}

#[test]
fn bswap_is_sound() {
    let mut rng = Rng::new(14);
    for _ in 0..10_000 {
        let (a, avs) = sample_abstract(&mut rng);
        for width in [16u8, 32, 64] {
            let r = a.bswap(width);
            for &x in &avs {
                assert!(
                    r.contains(interp::end(ByteOrder::Swap, width, x)),
                    "bswap{width} {x:#x} in {r:?}"
                );
            }
        }
    }
}

// ─── Lattice laws ───────────────────────────────────────────────────

#[test]
fn normalize_never_drops_a_member() {
    // The property that makes `normalize` safe to call after every transfer
    // function: it may tighten the representation, never the set.
    let mut rng = Rng::new(20);
    for _ in 0..50_000 {
        let mask = rng.next();
        let raw = Scalar {
            tnum: Tnum {
                value: rng.next() & !mask,
                mask,
            },
            min: rng.next() as i64,
            max: rng.next() as i64,
        };
        let normalized = raw.normalize();
        // Sample candidate members of the *unnormalized* value.
        for _ in 0..8 {
            let v = raw.tnum.value | (rng.next() & raw.tnum.mask);
            if !raw.contains(v) {
                continue;
            }
            match normalized {
                None => panic!("normalize called {raw:?} empty, but {v:#x} is a member"),
                Some(n) => assert!(
                    n.contains(v),
                    "normalize dropped {v:#x} from {raw:?} → {n:?}"
                ),
            }
        }
    }
}

#[test]
fn join_is_an_upper_bound() {
    let mut rng = Rng::new(21);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let (b, bvs) = sample_abstract(&mut rng);
        let j = a.join(&b);
        for &v in avs.iter().chain(bvs.iter()) {
            assert!(j.contains(v), "join lost {v:#x}: {a:?} ⊔ {b:?} = {j:?}");
        }
        assert!(a.is_subset_of(&j), "{a:?} ⊄ {j:?}");
        assert!(b.is_subset_of(&j), "{b:?} ⊄ {j:?}");
    }
}

#[test]
fn meet_is_exactly_intersection() {
    let mut rng = Rng::new(22);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let (b, bvs) = sample_abstract(&mut rng);
        let m = a.meet(&b);
        for &v in avs.iter().chain(bvs.iter()) {
            if a.contains(v) && b.contains(v) {
                match m {
                    None => panic!("meet claimed empty but {v:#x} is in both {a:?} and {b:?}"),
                    Some(m) => assert!(m.contains(v), "meet lost {v:#x}"),
                }
            }
        }
        // The other direction: nothing outside both may appear.
        if let Some(m) = m {
            for _ in 0..8 {
                let v = m.tnum.value | (rng.next() & m.tnum.mask);
                if m.contains(v) {
                    assert!(a.contains(v) && b.contains(v), "meet invented {v:#x}");
                }
            }
        }
    }
}

#[test]
fn is_subset_of_never_claims_a_containment_that_is_false() {
    // The fixpoint stops when a block's input `is_subset_of` the previous one.
    // A false positive here terminates the analysis on a state that has not
    // converged — the abstract state would then be missing values the program
    // can actually reach, and a bounds check derived from it would be a lie.
    // This is the single most dangerous predicate in the crate.
    let mut rng = Rng::new(26);
    for _ in 0..50_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let (b, _) = sample_abstract(&mut rng);
        if !a.is_subset_of(&b) {
            continue;
        }
        for &v in &avs {
            assert!(b.contains(v), "{a:?} ⊑ {b:?} but {v:#x} escapes b");
        }
        // Sample beyond the generators too: anything in `a` must be in `b`.
        for _ in 0..8 {
            let v = a.tnum.value | (rng.next() & a.tnum.mask);
            if a.contains(v) {
                assert!(b.contains(v), "{a:?} ⊑ {b:?} but {v:#x} escapes b");
            }
        }
    }
}

#[test]
fn widening_is_extensive() {
    // A widening must be an upper bound of *both* sides, or the fixpoint's
    // ascending chain is not ascending and the convergence argument collapses.
    let mut rng = Rng::new(27);
    let thresholds = [-1i64, 0, 1, 8, 64, 4096];
    for _ in 0..20_000 {
        let (old, oldvs) = sample_abstract(&mut rng);
        let (new, newvs) = sample_abstract(&mut rng);
        let w = old.widen(&new, &thresholds);
        for &v in oldvs.iter().chain(newvs.iter()) {
            assert!(w.contains(v), "{old:?} ∇ {new:?} = {w:?} lost {v:#x}");
        }
        // Widening the same value twice must be stable, or a loop header would
        // keep reporting "changed" forever.
        assert!(
            w.widen(&w, &thresholds).is_subset_of(&w),
            "widening is not idempotent at {w:?}"
        );
    }
}

#[test]
fn widening_covers_the_new_value() {
    let mut rng = Rng::new(23);
    let thresholds = [-1i64, 0, 1, 8, 64, 4096, i64::from(i32::MAX)];
    for _ in 0..20_000 {
        let (old, _) = sample_abstract(&mut rng);
        let (new, newvs) = sample_abstract(&mut rng);
        let w = old.widen(&new, &thresholds);
        for &v in &newvs {
            assert!(
                w.contains(v),
                "widen lost {v:#x}: {old:?} ∇ {new:?} = {w:?}"
            );
        }
    }
}

#[test]
fn widening_terminates_on_a_climbing_loop() {
    // The property the whole design rests on: no instruction budget, no state
    // limit, so the fixpoint has to converge on its own. A counter that grows
    // without bound must reach a stable abstract value in a small number of
    // steps.
    let thresholds = [0i64, 1, 100, 1000];
    let mut cur = Scalar::constant(0);
    let mut steps = 0;
    loop {
        let next = cur.add(&Scalar::constant(1)).join(&Scalar::constant(0));
        let widened = cur.widen(&next, &thresholds);
        if widened == cur {
            break;
        }
        cur = widened;
        steps += 1;
        assert!(steps < 32, "widening did not converge: {cur:?}");
    }
    assert!(
        cur.contains(5),
        "converged value lost a reachable state: {cur:?}"
    );
    assert!(cur.contains(0));
}

// ─── Branch refinement ──────────────────────────────────────────────

#[test]
fn refinement_keeps_every_satisfying_value() {
    let mut rng = Rng::new(24);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let c = sample_value(&mut rng);

        /// A refined value, the predicate it was refined by, and a label.
        type Case<'a> = (Option<Scalar>, &'a dyn Fn(u64) -> bool, &'static str);

        let cases: [Case<'_>; 4] = [
            (a.refine_unsigned_max(c), &|v: u64| v <= c, "u<="),
            (a.refine_unsigned_min(c), &|v: u64| v >= c, "u>="),
            (
                a.refine_signed_max(c as i64),
                &|v: u64| (v as i64) <= (c as i64),
                "s<=",
            ),
            (
                a.refine_signed_min(c as i64),
                &|v: u64| (v as i64) >= (c as i64),
                "s>=",
            ),
        ];
        for (refined, holds, name) in cases {
            for &v in &avs {
                if !holds(v) {
                    continue;
                }
                match refined {
                    None => panic!("{name} {c:#x}: dropped satisfying {v:#x} from {a:?}"),
                    Some(r) => assert!(
                        r.contains(v),
                        "{name} {c:#x}: lost {v:#x} from {a:?} → {r:?}"
                    ),
                }
            }
        }
    }
}

#[test]
fn jset_refinement_is_sound() {
    let mut rng = Rng::new(25);
    for _ in 0..20_000 {
        let (a, avs) = sample_abstract(&mut rng);
        let c = sample_value(&mut rng);
        let cs = Scalar::constant(c as i64);
        let set = a.refine_bits_set(&cs);
        let clear = a.refine_bits_clear(&cs);
        for &v in &avs {
            if interp::cond(CondOp::Set, true, v, c) {
                match set {
                    None => panic!("jset taken-branch dropped {v:#x}"),
                    Some(r) => assert!(r.contains(v)),
                }
            } else {
                match clear {
                    None => panic!("jset fallthrough dropped {v:#x}"),
                    Some(r) => assert!(r.contains(v)),
                }
            }
        }
    }
}

// ─── Targeted cases the random corpus would only reach by luck ──────

#[test]
fn a_masked_value_gets_an_exact_bound() {
    // `r0 &= 0xff` is the single most common way a BPF program establishes a
    // bound, and it must come out exact — this is what the tnum component buys
    // that an interval alone cannot.
    let masked = Scalar::UNKNOWN.and(&Scalar::constant(0xff));
    assert_eq!(masked.min, 0);
    assert_eq!(masked.max, 0xff);
    assert_eq!(masked.unsigned_bounds(), (0, 0xff));
}

#[test]
fn a_32_bit_load_is_known_non_negative() {
    // The load transfer produces `unsigned_bits(32)`; the point of the test is
    // that `normalize` turns "high 32 bits known zero" into a *signed* lower
    // bound of zero, without which the following unsigned comparison could not
    // refine anything.
    let loaded = Scalar::unsigned_bits(32);
    assert_eq!(loaded.min, 0);
    assert_eq!(loaded.max, 0xffff_ffff);
    let bounded = loaded.refine_unsigned_max(63).expect("satisfiable");
    assert_eq!((bounded.min, bounded.max), (0, 63));
    // …and scaling it stays exact, which is what makes `ptr + (idx << 3)`
    // provable.
    let scaled = bounded.shl(&Scalar::constant(3));
    assert_eq!((scaled.min, scaled.max), (0, 504));
}

#[test]
fn an_impossible_comparison_is_detected() {
    // `if r0 > 10 goto` where r0 is already known ≤ 5: the taken branch is
    // unreachable, and saying so is how the fixpoint avoids analysing dead
    // code with a bottom state.
    let bounded = Scalar::UNKNOWN.and(&Scalar::constant(5));
    assert_eq!(bounded.refine_unsigned_min(6), None);
}

#[test]
fn division_by_zero_yields_zero_not_top() {
    // `instruction-set.rst:351`. A verifier that modelled this as "unknown"
    // would be sound but would reject the idiom of dividing by a value that
    // has not been proved non-zero, which LLVM emits freely.
    let d = Scalar::constant(100).udiv(&Scalar::constant(0));
    assert_eq!(d.as_const(), Some(0));
    // Modulo by zero leaves the dividend.
    let m = Scalar::constant(100).umod(&Scalar::constant(0));
    assert!(m.contains(100));
}

#[test]
fn llong_min_divided_by_minus_one_does_not_trap() {
    // `instruction-set.rst:352`. On x86 the hardware would #DE; the ISA
    // defines the result instead, so the JIT must guard and the verifier must
    // agree with the guard's value.
    assert_eq!(
        Scalar::constant(i64::MIN)
            .sdiv(&Scalar::constant(-1))
            .as_const(),
        Some(i64::MIN)
    );
    assert_eq!(
        Scalar::constant(i64::MIN)
            .smod(&Scalar::constant(-1))
            .as_const(),
        Some(0)
    );
}

#[test]
fn tnum_intersection_detects_contradictions() {
    let even = Tnum { value: 0, mask: !1 };
    let odd = Tnum { value: 1, mask: !1 };
    assert_eq!(even.meet(odd), None);
    assert!(even.meet(even).is_some());
}

#[test]
fn reference_interpreter_agrees_with_the_isa_on_32_bit_zero_extension() {
    // Every 32-bit ALU result is zero-extended into the 64-bit register. This
    // is easy to get wrong in one place and not the other, and getting it
    // wrong in the *verifier* means believing a register's high bits are set
    // when the hardware cleared them.
    let r = interp::alu(AluOp::Add, false, 0xffff_ffff_ffff_ffff, 1);
    assert_eq!(r, 0);
    let a = Scalar::constant(-1);
    let out = a.add(&Scalar::constant(1)).zext32();
    assert!(out.contains(0));
}

// ── the stack's per-byte initialisation model ───────────────────────

/// The obvious, slow definition of "every byte in the range was written".
///
/// [`Stack::is_initialized`] walks slots rather than bytes, because a
/// variable-offset access asks about a range that can be the whole frame and
/// the walk happens once per access per fixpoint round. This is what it is
/// supposed to compute, written the way nobody would get wrong — mask
/// arithmetic over a partially-covered slot at each end of the range is
/// exactly the kind of thing that is right for every case anyone thinks to
/// write a unit test for.
fn is_initialized_bytewise(s: &Stack, off: i64, len: u64) -> bool {
    (off..off + len as i64).all(|b| {
        let slot = s.slot(Stack::slot_index(b));
        (slot.init & (1u8 << Stack::byte_in_slot(b))) != 0
    })
}

#[test]
fn the_slotwise_initialisation_check_agrees_with_the_bytewise_one() {
    let mut rng = Rng::new(0x1517_C0DE_5EED_0001);
    let mut any_true = 0usize;
    let mut any_false = 0usize;
    for _ in 0..20_000 {
        // A frame with a handful of partially-written regions, so the boundary
        // cases — a range starting or ending mid-slot, a hole in the middle,
        // a slot that exists but is only half written — all occur.
        let mut s = Stack::default();
        for _ in 0..rng.below(6) {
            let off = -(rng.below(160) as i64) - 1;
            let size = match rng.below(4) {
                0 => Size::B,
                1 => Size::H,
                2 => Size::W,
                _ => Size::Dw,
            };
            if off + size.bytes() as i64 <= 0 {
                s.write(off, size, AbsValue::UNKNOWN_SCALAR);
            }
        }
        let off = -(rng.below(200) as i64) - 1;
        let len = rng.below(40);
        if off + len as i64 > 0 {
            continue;
        }
        let fast = s.is_initialized(off, len);
        let slow = is_initialized_bytewise(&s, off, len);
        assert_eq!(
            fast, slow,
            "is_initialized({off}, {len}) disagreed with the byte-wise oracle"
        );
        if fast {
            any_true += 1;
        } else {
            any_false += 1;
        }
    }
    // Agreement is trivial if one answer never occurs.
    assert!(
        any_true > 100 && any_false > 100,
        "corpus was one-sided: {any_true} true, {any_false} false"
    );
}

#[test]
fn an_empty_range_is_initialised_and_a_whole_frame_range_is_not() {
    let s = Stack::default();
    assert!(s.is_initialized(-8, 0), "an empty range asks nothing");
    assert!(
        !s.is_initialized(
            -(crate::MAX_STACK_BYTES as i64),
            crate::MAX_STACK_BYTES as u64
        ),
        "an untouched frame has nothing initialised"
    );
}

#[test]
fn a_range_that_is_not_a_frame_range_answers_false() {
    // Fail-closed on nonsense, because the natural implementation fails *open*
    // on it: the byte-wise form this replaced computed `off + len as i64`,
    // which for a `len` near `u64::MAX` is negative, giving an empty iterator
    // and a vacuous `true` — "every byte in this range is initialised" for a
    // range that does not exist.
    //
    // A fully written frame is used so the answer cannot come from the bytes
    // being uninitialised; only the range check can produce it.
    let mut s = Stack::default();
    for i in 0..8 {
        s.write(-8 * (i + 1), Size::Dw, AbsValue::UNKNOWN_SCALAR);
    }
    assert!(s.is_initialized(-64, 64), "the frame really is written");
    assert!(!s.is_initialized(-8, u64::MAX), "a wrapping length");
    assert!(!s.is_initialized(-8, i64::MAX as u64 + 1), "past i64");
    assert!(!s.is_initialized(i64::MIN, 8), "an offset that cannot add");
    assert!(!s.is_initialized(8, 8), "above the frame pointer");
    assert!(!s.is_initialized(-8, 16), "running past the frame pointer");
}
