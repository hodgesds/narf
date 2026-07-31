//! Disassembly.
//!
//! Renders a [`Decoded`] in the syntax `llvm-objdump -d` uses for BPF, so
//! verifier logs and `bpftool prog dump`-alike output are diffable against
//! LLVM's. No allocation — everything goes through [`core::fmt`], so this is
//! usable from a trap handler.

use core::fmt;

use crate::insn::{CallTarget, Decoded, Imm64};
use crate::opcode::{AluOp, AtomicOp, ByteOrder, CondOp, Size, Source};

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(r) => write!(f, "{r}"),
            Self::Imm(i) => write!(f, "{i}"),
        }
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::B => "u8",
            Self::H => "u16",
            Self::W => "u32",
            Self::Dw => "u64",
        })
    }
}

impl AluOp {
    /// The infix operator LLVM prints for this operation.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+=",
            Self::Sub => "-=",
            Self::Mul => "*=",
            Self::Or => "|=",
            Self::And => "&=",
            Self::Lsh => "<<=",
            Self::Rsh => ">>=",
            Self::Xor => "^=",
            Self::Arsh => "s>>=",
        }
    }
}

impl CondOp {
    /// The comparison operator LLVM prints for this predicate.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Sgt => "s>",
            Self::Sge => "s>=",
            Self::Slt => "s<",
            Self::Sle => "s<=",
            Self::Set => "&",
        }
    }
}

/// Suffix distinguishing a 32-bit operation from a 64-bit one, matching
/// LLVM's `w`-register convention.
const fn wsuffix(wide: bool) -> &'static str {
    if wide {
        ""
    } else {
        "32"
    }
}

impl fmt::Display for Decoded {
    #[allow(clippy::too_many_lines)] // one arm per instruction shape; splitting hurts readability
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Alu { wide, op, dst, src } => {
                write!(f, "{dst} {}{} {src}", op.symbol(), wsuffix(wide))
            }

            Self::Neg { wide, dst } => write!(f, "{dst} = -{dst}{}", wsuffix(wide)),

            Self::Mov {
                wide,
                dst,
                src,
                sign_extend,
            } => match sign_extend {
                None => write!(f, "{dst} ={} {src}", wsuffix(wide)),
                Some(b) => write!(f, "{dst} = (s{b}){src}"),
            },

            Self::Div {
                wide,
                signed,
                dst,
                src,
            } => write!(
                f,
                "{dst} {}/={} {src}",
                if signed { "s" } else { "" },
                wsuffix(wide)
            ),

            Self::Mod {
                wide,
                signed,
                dst,
                src,
            } => write!(
                f,
                "{dst} {}%={} {src}",
                if signed { "s" } else { "" },
                wsuffix(wide)
            ),

            Self::End { dst, order, width } => match order {
                ByteOrder::Little => write!(f, "{dst} = le{width} {dst}"),
                ByteOrder::Big => write!(f, "{dst} = be{width} {dst}"),
                ByteOrder::Swap => write!(f, "{dst} = bswap{width} {dst}"),
            },

            Self::AddrSpaceCast {
                dst,
                src,
                dst_as,
                src_as,
            } => write!(f, "{dst} = addr_space_cast({src}, {dst_as}, {src_as})"),

            Self::Load {
                size,
                sign_extend,
                dst,
                src,
                off,
            } => write!(
                f,
                "{dst} = *({}{} *)({src} {})",
                if sign_extend { "s" } else { "" },
                size,
                Offset(off)
            ),

            Self::Store {
                size,
                dst,
                off,
                src,
            } => write!(f, "*({size} *)({dst} {}) = {src}", Offset(off)),

            Self::Atomic {
                size,
                op,
                dst,
                src,
                off,
            } => fmt_atomic(f, size, op, dst, src, off),

            Self::LoadImm64 { dst, value } => match value {
                Imm64::Value(v) => write!(f, "{dst} = 0x{v:x} ll"),
                Imm64::MapFd(fd) => write!(f, "{dst} = map_by_fd({fd}) ll"),
                Imm64::MapValue { fd, value_offset } => {
                    write!(f, "{dst} = map_val(map_by_fd({fd})) + {value_offset} ll")
                }
                Imm64::BtfId(id) => write!(f, "{dst} = btf_var({id}) ll"),
                Imm64::SubprogAddr(o) => write!(f, "{dst} = subprog(+{o}) ll"),
                Imm64::MapIdx(i) => write!(f, "{dst} = map_by_idx({i}) ll"),
                Imm64::MapIdxValue { idx, value_offset } => {
                    write!(f, "{dst} = map_val(map_by_idx({idx})) + {value_offset} ll")
                }
            },

            Self::Jump { off } => write!(f, "goto {}", Signed(off)),

            Self::JumpCond {
                wide,
                op,
                dst,
                src,
                off,
            } => write!(
                f,
                "if {dst} {}{} {src} goto {}",
                op.symbol(),
                wsuffix(wide),
                Signed(i32::from(off))
            ),

            Self::MayGoto { off } => write!(f, "may_goto {}", Signed(i32::from(off))),

            Self::Call(CallTarget::Subprog(o)) => write!(f, "call pc{}", Signed(o)),
            Self::Call(CallTarget::Kfunc(id)) => write!(f, "call kfunc#{id}"),

            Self::Exit => f.write_str("exit"),
        }
    }
}

fn fmt_atomic(
    f: &mut fmt::Formatter<'_>,
    size: Size,
    op: AtomicOp,
    dst: crate::opcode::Reg,
    src: crate::opcode::Reg,
    off: i16,
) -> fmt::Result {
    let at = Offset(off);
    match op {
        AtomicOp::Cmpxchg => write!(f, "r0 = cmpxchg_{size}(({dst} {at}), r0, {src})"),
        AtomicOp::Xchg => write!(f, "{src} = xchg_{size}(({dst} {at}), {src})"),
        AtomicOp::LoadAcquire => write!(f, "{src} = load_acquire(({dst} {at}))"),
        AtomicOp::StoreRelease => write!(f, "store_release(({dst} {at}), {src})"),
        AtomicOp::Add { fetch }
        | AtomicOp::Or { fetch }
        | AtomicOp::And { fetch }
        | AtomicOp::Xor { fetch } => {
            let name = match op {
                AtomicOp::Add { .. } => "add",
                AtomicOp::Or { .. } => "or",
                AtomicOp::And { .. } => "and",
                _ => "xor",
            };
            if fetch {
                write!(f, "{src} = atomic_fetch_{name}(({dst} {at}), {src})")
            } else {
                write!(f, "lock *({size} *)({dst} {at}) {name}= {src}")
            }
        }
    }
}

/// Renders a memory displacement as `+ N` / `- N`, the way LLVM prints it.
struct Offset(i16);

impl fmt::Display for Offset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            // Negate through i32 so i16::MIN doesn't overflow.
            write!(f, "- {}", -i32::from(self.0))
        } else {
            write!(f, "+ {}", self.0)
        }
    }
}

/// Renders a jump displacement with an explicit sign, as `+N` / `-N`.
struct Signed(i32);

impl fmt::Display for Signed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            write!(f, "{}", self.0)
        } else {
            write!(f, "+{}", self.0)
        }
    }
}
