//! The program object and its lifecycle.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_bpf_isa::Insn;
use narf_bpf_verifier::kfunc::Context;
use narf_bpf_verifier::SubprogInfo;
use narf_bpf_verifier::{VerifyError, DEFAULT_FUEL, MAX_STACK_BYTES};
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_crypto::sha256::Sha256;
use narf_lib::sync::IrqSafeSpinLock;

use crate::interp::{Outcome, Vm, MAX_CTX_WORDS};
use crate::mem::{
    BpfStack, HeapStack, PerCpuRegion, PerCpuStackStub, StackFrame, STUB_STACK_BYTES,
};
use crate::xdp_stage::{XDP_HEADROOM, XDP_STAGE_LEN, XDP_STAGE_PACKET_MAX};

/// Authority to load and verify a BPF program.
///
/// `bpf/specification/spec.md` §4.10: there is no unprivileged mode and no
/// second set of limits. Linux forks its whole verifier on `allow_ptr_leaks`,
/// `allow_uninit_stack`, `bpf_capable`, and `bypass_spec_v1/v4` — and then
/// every distribution disables unprivileged BPF anyway.
#[derive(Copy, Clone, Debug)]
pub struct BpfProgLoad;
impl CapType for BpfProgLoad {
    const KIND: CapKind = CapKind::BpfProgLoad;
}

/// Authority to attach a verified program to a hook.
#[derive(Copy, Clone, Debug)]
pub struct BpfAttach;
impl CapType for BpfAttach {
    const KIND: CapKind = CapKind::BpfAttach;
}

/// Largest program the loader accepts, in instruction slots.
///
/// Not a verification limit — fuel handles termination, so there is no
/// `BPF_COMPLEXITY_LIMIT_INSNS` here. This is a memory bound on the copy from
/// userspace, nothing more.
pub const MAX_INSNS: usize = 1 << 16;

/// Bytes Linux exposes as a program tag.
pub const PROG_TAG_SIZE: usize = 8;

/// Linux `BPF_PROG_TYPE_XDP`.
pub const BPF_PROG_TYPE_XDP: u32 = 6;

const XDP_PACKET_KEY: narf_bpf_verifier::TypeKey = narf_bpf_verifier::TypeKey(
    narf_bpf_verifier::kfunc::fnv1a32_nonzero("narf_bpf::xdp_packet"),
);

const XDP_CTX: [narf_bpf_verifier::ArgDesc; 2] = [
    // `data` — the packet's writable base. No `READONLY`: a store through a
    // derived data pointer is admitted, and the verifier bounds it against
    // `data_end` exactly as it does a load (`fixpoint::access` checks the same
    // `p.size` interval for a write as for a read; only `p.readonly` would
    // reject the write). An in-place header rewrite is therefore verifier-legal,
    // while an out-of-bounds store is still `OutOfBounds`. See
    // `crate::attach_xdp` for the runtime that makes the frame a real `&mut`.
    narf_bpf_verifier::ArgDesc {
        kind: narf_bpf_verifier::TypeKind::Ptr {
            kind: narf_bpf_verifier::PtrKind::Mem,
            key: XDP_PACKET_KEY,
        },
        domain: narf_bpf_verifier::ValidityDomain::NonPreemptible,
        flags: narf_bpf_verifier::ArgFlags::NONE,
    },
    // `data_end` — the exclusive end marker. `READONLY` and never
    // dereferenceable: it exists only to bound the region, so a load or store
    // through it is rejected (the read test `dynamic_region_end_is_not_
    // dereferenceable` is joined by the write case in `verify_tests`).
    narf_bpf_verifier::ArgDesc {
        kind: narf_bpf_verifier::TypeKind::Ptr {
            kind: narf_bpf_verifier::PtrKind::MemEnd,
            key: XDP_PACKET_KEY,
        },
        domain: narf_bpf_verifier::ValidityDomain::NonPreemptible,
        flags: narf_bpf_verifier::ArgFlags::READONLY,
    },
];

/// Why loading failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The `Cap<BpfProgLoad, Grant>` was revoked.
    AuthorityRevoked,
    /// The kfunc registry has not been built yet — `register_initcalls()` has
    /// not run.
    NoRegistry,
    /// Empty program, or more than [`MAX_INSNS`] slots.
    BadSize(usize),
    /// The verifier rejected it.
    Rejected(VerifyError),
    /// The program needs more stack than the current provider offers.
    StackTooDeep { needed: u32, limit: u32 },
    /// Typed probe objects are borrowed only for an atomic fire callback.
    TypedProbeRequiresAtomic,
    /// The Rust probe object cannot be represented by the verifier schema.
    TypedProbeTooLarge,
    /// XDP frames are borrowed only for an atomic classifier callback.
    XdpRequiresAtomic,
}

impl From<CapError> for LoadError {
    fn from(_: CapError) -> Self {
        LoadError::AuthorityRevoked
    }
}

/// Why an explicit map lifetime binding failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BindError {
    /// Growing the program's bound-map set could not be allocated. `ENOMEM`.
    NoMemory,
}

/// A type-erased object whose lifetime is bound to a loaded program.
///
/// Linux permits BTF descriptors in `bpf_attr.prog_load.fd_array` alongside
/// maps. `narf-bpf` deliberately does not depend on the BTF parser crate, so
/// the syscall layer hands the program an opaque strong reference instead of
/// teaching the runtime about a compatibility-only type graph.
pub trait LoadReference: core::fmt::Debug + Send + Sync {}

impl<T: core::fmt::Debug + Send + Sync> LoadReference for T {}

/// One sparse `fd_array` position resolved to a map.
///
/// Positions are explicit rather than implied by vector order because Linux's
/// array may contain duplicate maps, BTF descriptors, and unused slots.
#[derive(Clone, Debug)]
pub struct IndexedMap {
    /// The index carried by `BPF_PSEUDO_MAP_IDX`.
    pub index: i32,
    /// The descriptor read from the caller's fd array.
    pub fd: i32,
    /// The map held alive for verification and execution.
    pub map: Arc<crate::map::BpfMap>,
}

/// A loaded, verified program.
///
/// Reference-counted (`Arc`) rather than owned by its fd, because a program
/// outlives the fd once it is attached — the same lifetime shape as
/// `Arc<Task>` elsewhere in the tree.
#[derive(Debug)]
pub struct BpfProg {
    /// Program name, as supplied at load.
    pub name: String,
    /// Kernel-wide id.
    pub id: u32,
    /// Stable Linux-compatible identity of the submitted instruction image.
    tag: [u8; PROG_TAG_SIZE],
    /// Whether the load-time license matched Linux's GPL-compatible set.
    gpl_compatible: bool,
    /// Monotonic nanoseconds since boot when the program finished loading.
    load_time_ns: u64,
    /// Effective uid of the task that loaded the program.
    created_by_uid: u32,
    /// Linux `enum bpf_prog_type` supplied by a syscall-shaped loader.
    ///
    /// Separate from `context`: several Linux program types execute in the
    /// same atomic context but are not interchangeable at attach time.
    linux_prog_type: Option<u32>,
    /// The validated instruction image. Verification does not rewrite
    /// instructions — lowering happens once, in the JIT (spec §1.7).
    insns: Vec<Insn>,
    /// The execution context this program was verified for.
    context: Context,
    /// Whether the program calls `bpf_xdp_adjust_head`/`_tail`.
    ///
    /// Set at load from the verifier's resolved kfunc-call sites. When true the
    /// XDP run path stages the frame into a per-CPU buffer with head/tailroom so
    /// a grow has somewhere to go, and delivers the resulting `[data, data_end)`
    /// window rather than the original frame — see [`Self::run_xdp`]. False for
    /// every program that does not resize, so the common RX path is unchanged and
    /// pays no staging copy.
    uses_xdp_adjust: bool,
    /// Rust-native typed-probe schema, for runtime attach validation.
    typed_probe: Option<TypedProbeLayout>,
    /// Loads the verifier certified as exact typed-field reads through the
    /// tracing wrapper. The interpreter services these through the live
    /// [`narf_tracing::TypedProbeRef`] rather than as bare dereferences; empty
    /// for every non-typed program.
    typed_load_sites: Vec<narf_bpf_verifier::TypedLoadSite>,
    /// Starting fuel for each invocation.
    initial_fuel: u64,
    /// Bytes of BPF stack the program may use.
    stack_bytes: u32,
    /// Per-subprogram frame sizes, as the verifier modelled them.
    ///
    /// Kept, not discarded: `Ok` from the verifier is conditional on the
    /// frames being laid out this way. Handing every frame a fixed width
    /// instead disagreed in both directions — eight tiny subprograms verified
    /// with a 64-byte budget and then exhausted the region on the first call,
    /// and a single 1 KiB callee verified and then wrote below it.
    subprogs: Vec<SubprogInfo>,
    /// Invocations.
    runs: AtomicU64,
    /// Invocations observed while `BPF_ENABLE_STATS` had a live lease.
    stats_runs: AtomicU64,
    /// Nanoseconds spent executing invocations admitted to runtime stats.
    run_time_ns: AtomicU64,
    /// Atomic invocations refused because this CPU's nesting budget was full.
    recursion_misses: AtomicU64,
    /// Sum of return values. One of three ways an attached program's effect is
    /// observed, alongside the scratch counters in `crate::kfuncs` and — now
    /// that they exist — the maps in `crate::map`.
    accumulated: AtomicU64,
    /// Invocations that ended in a [`crate::interp::Trap`].
    traps: AtomicU64,
    /// Native code, when the program passed every gate in
    /// [`crate::jit_glue`]. `None` means it runs interpreted, which is a
    /// complete implementation and not a degraded one.
    jit: Option<crate::jit_glue::JitImage>,
    /// The arenas this program may address, if any.
    ///
    /// Held as an `Arc` because the same arenas are reachable through an
    /// [`crate::arena::ArenaFile`] fd that userspace mapped, and the frames must
    /// outlive whichever of the two goes away first.
    ///
    /// Bound at load time and never after: the interpreter reads this slice on
    /// the run path with no lock, which is only sound because it cannot change
    /// under it.
    arenas: Option<Arc<crate::arena::ArenaGroup>>,
    /// The maps this program may reference, paired with the file descriptors
    /// its `LD_IMM64` immediates name.
    ///
    /// Held for the program's life, which is the point: the `Arc` is what keeps
    /// a map alive after the fd that created it is closed. Linux does the same
    /// through `prog->aux->used_maps`.
    maps: Vec<(i32, Arc<crate::map::BpfMap>)>,
    /// Sparse positions used by `BPF_PSEUDO_MAP_IDX` instructions.
    map_indices: Vec<IndexedMap>,
    /// Non-map objects from the program-load fd array, currently BTF blobs.
    /// Their only NARF semantic is the Linux-compatible lifetime reference.
    _load_references: Vec<Arc<dyn LoadReference>>,
    /// Maps attached after load solely to share the program's lifetime.
    ///
    /// `BPF_PROG_BIND_MAP` does not make these maps addressable by program
    /// instructions. Keeping them separate preserves the verifier/runtime
    /// agreement that `maps` above is immutable, while this set may grow under
    /// concurrent syscalls. Object identity, not the fd used for the binding,
    /// makes repeated binds idempotent.
    bound_maps: IrqSafeSpinLock<Vec<Arc<crate::map::BpfMap>>>,
}

/// Owned copy of one typed-probe schema used during verification and dispatch.
#[derive(Clone, Debug)]
struct TypedProbeLayout {
    type_key: u32,
    size: u32,
    fields: Vec<narf_bpf_verifier::ObjectField>,
}

/// Linux-visible metadata supplied by a userspace program loader.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LoadMetadata {
    /// Whether the copied license matched Linux's GPL-compatible set.
    pub gpl_compatible: bool,
    /// Effective uid of the task issuing `BPF_PROG_LOAD`.
    pub created_by_uid: u32,
    /// Declared Linux program type, absent for direct in-kernel loaders.
    pub linux_prog_type: Option<u32>,
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// Match Linux's `bpf_prog_calc_tag`: hash the submitted slots, except that
/// the two immediate halves of map-fd and map-value pseudo loads are zero.
/// File descriptors are process-local allocation results and therefore cannot
/// be part of a stable program identity. Map-index pseudo loads remain intact
/// because their indices are stable inputs from the loader's fd array.
fn calculate_tag(insns: &[Insn]) -> [u8; PROG_TAG_SIZE] {
    use narf_bpf_isa::opcode::{PSEUDO_MAP_FD, PSEUDO_MAP_VALUE};

    let mut sha = Sha256::new();
    let mut map_imm_tail = false;
    for &original in insns {
        let mut insn = original;
        if !map_imm_tail
            && insn.is_wide_imm()
            && matches!(insn.src_raw(), PSEUDO_MAP_FD | PSEUDO_MAP_VALUE)
        {
            insn.imm = 0;
            map_imm_tail = true;
        } else if map_imm_tail
            && insn.code == 0
            && insn.dst_raw() == 0
            && insn.src_raw() == 0
            && insn.off == 0
        {
            insn.imm = 0;
            map_imm_tail = false;
        } else {
            map_imm_tail = false;
        }
        sha.update(&insn.to_bytes());
    }
    let digest = sha.finalize();
    let mut tag = [0u8; PROG_TAG_SIZE];
    tag.copy_from_slice(&digest[..PROG_TAG_SIZE]);
    tag
}

/// A load request.
#[derive(Debug)]
pub struct LoadRequest {
    /// Program name (Linux caps this at 16 bytes; so do we, at the syscall
    /// boundary).
    pub name: String,
    /// The instruction image.
    pub insns: Vec<Insn>,
    /// The execution context the target hook provides. Declared by the hook,
    /// never by a program flag — spec §4.5.
    pub context: Context,
    /// Every map the program may reference, in the order the loader supplied
    /// them, each paired with the file descriptor its `LD_IMM64` immediates
    /// name.
    ///
    /// Resolved by the caller, not here: `narf-bpf` cannot depend on
    /// `narf-userspace` (that is the cycle spec §3.1 forbids), so it has no way
    /// to turn an fd into a map. The `bpf(2)` handler does the lookup and hands
    /// over the `Arc`s, which is also what makes the program hold a reference
    /// for its whole life — a map cannot be freed out from under a program that
    /// names it.
    pub maps: Vec<(i32, Arc<crate::map::BpfMap>)>,
    /// Map positions resolved from `bpf_attr.prog_load.fd_array`.
    pub map_indices: Vec<IndexedMap>,
    /// Compatibility objects whose lifetime is bound to this program.
    pub load_references: Vec<Arc<dyn LoadReference>>,
}

impl BpfProg {
    /// Verify and load.
    ///
    /// # Errors
    ///
    /// See [`LoadError`].
    pub fn load(cap: &Cap<BpfProgLoad, Grant>, req: LoadRequest) -> Result<Arc<Self>, LoadError> {
        Self::load_with_options(cap, req, None, LoadMetadata::default(), None)
    }

    /// Verify and load with the compatibility classification of the license
    /// supplied through Linux's `BPF_PROG_LOAD` ABI.
    ///
    /// Direct in-kernel loaders use [`Self::load`] and are conservatively
    /// non-GPL unless they opt into this metadata explicitly.
    ///
    /// # Errors
    ///
    /// See [`LoadError`].
    pub fn load_with_license(
        cap: &Cap<BpfProgLoad, Grant>,
        req: LoadRequest,
        gpl_compatible: bool,
    ) -> Result<Arc<Self>, LoadError> {
        Self::load_with_metadata(
            cap,
            req,
            LoadMetadata {
                gpl_compatible,
                created_by_uid: 0,
                linux_prog_type: None,
            },
        )
    }

    /// Verify and load with metadata captured by a userspace loader.
    ///
    /// In-kernel loaders use [`Self::load`]; syscall-shaped loaders use this
    /// entry point so credential metadata is copied once and remains stable if
    /// either the loader or a later querying task changes credentials.
    ///
    /// # Errors
    ///
    /// See [`LoadError`].
    pub fn load_with_metadata(
        cap: &Cap<BpfProgLoad, Grant>,
        req: LoadRequest,
        metadata: LoadMetadata,
    ) -> Result<Arc<Self>, LoadError> {
        Self::load_with_options(cap, req, None, metadata, None)
    }

    /// Verify and load against the XDP `data` / `data_end` context.
    ///
    /// The program may read frame bytes only after the verifier proves a
    /// dominating comparison against the paired exclusive end pointer.
    pub fn load_for_xdp(
        cap: &Cap<BpfProgLoad, Grant>,
        req: LoadRequest,
    ) -> Result<Arc<Self>, LoadError> {
        if req.context != Context::Atomic {
            return Err(LoadError::XdpRequiresAtomic);
        }
        Self::load_with_options(
            cap,
            req,
            None,
            LoadMetadata {
                linux_prog_type: Some(BPF_PROG_TYPE_XDP),
                ..LoadMetadata::default()
            },
            None,
        )
    }

    /// Verify and load, binding an arena group the program may address.
    ///
    /// A separate entry point rather than a field on [`LoadRequest`]: that struct
    /// is built by literal in `narf-userspace`'s `bpf(2)` handler and in
    /// `crate::bench`, so a new field would be a breaking change across crates
    /// for the benefit of one caller.
    ///
    /// The group is *not* something the verifier is told about, and that is worth
    /// stating precisely. `narf-bpf-verifier` bounds an arena displacement
    /// against a fixed `ARENA_WINDOW_BYTES`, not against this group's extent, so
    /// it will accept a program that walks past the end of its own arenas. What
    /// makes that safe is the runtime: the interpreter resolves every handle
    /// against exactly this slice and traps
    /// [`crate::interp::Trap::ArenaOutOfBounds`] otherwise, and the slot's tail
    /// guard means even an unchecked access could not reach another program's
    /// arenas.
    ///
    /// Native code performs neither check and reaches the same verdict a
    /// different way: the access is lowered slot-relative, the unmapped pages
    /// the guards and the arena's own extent leave behind make a wild handle
    /// *fault*, and the exception table turns that fault into the same trap.
    /// The group's **length** is what makes the two agree, which is why it is
    /// passed to `crate::jit_glue::try_compile` — see gate 2 there.
    ///
    /// # Errors
    ///
    /// See [`LoadError`].
    pub fn load_with_arena(
        cap: &Cap<BpfProgLoad, Grant>,
        req: LoadRequest,
        arenas: Option<Arc<crate::arena::ArenaGroup>>,
    ) -> Result<Arc<Self>, LoadError> {
        Self::load_with_options(cap, req, arenas, LoadMetadata::default(), None)
    }

    /// Verify and load for one Rust-described typed tracing object.
    ///
    /// The object is borrowed by `tracing::fire_typed` only for the synchronous
    /// atomic callback. Its fields remain opaque to ordinary loads; programs
    /// reach them through `narf_probe_read`, whose verifier descriptor and
    /// runtime wrapper both require an exact declared field.
    pub fn load_for_typed_probe<T: narf_tracing::TypedProbe>(
        cap: &Cap<BpfProgLoad, Grant>,
        req: LoadRequest,
    ) -> Result<Arc<Self>, LoadError> {
        if req.context != Context::Atomic {
            return Err(LoadError::TypedProbeRequiresAtomic);
        }
        let size =
            u32::try_from(core::mem::size_of::<T>()).map_err(|_| LoadError::TypedProbeTooLarge)?;
        let fields = T::FIELDS
            .iter()
            .map(|field| narf_bpf_verifier::ObjectField {
                offset: field.offset,
                size: field.size,
            })
            .collect();
        Self::load_with_options(
            cap,
            req,
            None,
            LoadMetadata::default(),
            Some(TypedProbeLayout {
                type_key: T::TYPE_KEY,
                size,
                fields,
            }),
        )
    }

    fn load_with_options(
        cap: &Cap<BpfProgLoad, Grant>,
        req: LoadRequest,
        arenas: Option<Arc<crate::arena::ArenaGroup>>,
        metadata: LoadMetadata,
        typed_probe: Option<TypedProbeLayout>,
    ) -> Result<Arc<Self>, LoadError> {
        cap.check_live()?;
        let xdp = metadata.linux_prog_type == Some(BPF_PROG_TYPE_XDP);
        if xdp && req.context != Context::Atomic {
            return Err(LoadError::XdpRequiresAtomic);
        }
        if req.insns.is_empty() || req.insns.len() > MAX_INSNS {
            return Err(LoadError::BadSize(req.insns.len()));
        }
        let registry = crate::kfunc::registry().ok_or(LoadError::NoRegistry)?;
        reject_unrunnable(&req.insns)?;
        let tag = calculate_tag(&req.insns);

        // Descriptors for every kfunc the program may call. The whole
        // registry, because NARF has one call ABI and one closed kfunc set —
        // there is no per-program-type helper allowlist to intersect with.
        let descs: Vec<_> = registry.all().iter().map(|e| e.desc()).collect();
        // The verifier's view of the map set: an fd, and the three widths that
        // bound an access. Built here rather than by the caller so the
        // descriptor cannot disagree with the map it describes.
        let map_descs: Vec<narf_bpf_verifier::MapDesc> = req
            .maps
            .iter()
            .map(|(fd, m)| {
                let a = m.attr();
                narf_bpf_verifier::MapDesc {
                    fd: *fd,
                    fd_array_idx: None,
                    key_size: a.key_size,
                    value_size: a.value_size,
                    max_entries: a.max_entries,
                }
            })
            .chain(req.map_indices.iter().map(|indexed| {
                let a = indexed.map.attr();
                narf_bpf_verifier::MapDesc {
                    fd: indexed.fd,
                    fd_array_idx: Some(indexed.index),
                    key_size: a.key_size,
                    value_size: a.value_size,
                    max_entries: a.max_entries,
                }
            }))
            .collect();
        let typed_ctx = typed_probe
            .as_ref()
            .map(|typed| narf_bpf_verifier::ArgDesc {
                kind: narf_bpf_verifier::TypeKind::Ptr {
                    kind: narf_bpf_verifier::PtrKind::TraceObject,
                    key: narf_bpf_verifier::TypeKey(typed.type_key),
                },
                domain: narf_bpf_verifier::ValidityDomain::NonPreemptible,
                flags: narf_bpf_verifier::ArgFlags::READONLY,
            });
        let typed_objects = typed_probe
            .as_ref()
            .map(|typed| narf_bpf_verifier::ObjectDesc {
                key: narf_bpf_verifier::TypeKey(typed.type_key),
                size: typed.size,
                fields: typed.fields.as_slice(),
            });
        let typed_ctx_storage = typed_ctx.into_iter().collect::<Vec<_>>();
        let typed_object_storage = typed_objects.into_iter().collect::<Vec<_>>();
        let prog = narf_bpf_verifier::Program {
            insns: &req.insns,
            context: req.context,
            // The probe ABI's `[u64; 4]` is already the ctx tuple, so there is
            // no ctx-rewriting layer and nothing to describe beyond four
            // scalars.
            ctx_fields: if typed_probe.is_some() {
                &typed_ctx_storage
            } else if xdp {
                &XDP_CTX
            } else {
                &CTX_SCALARS
            },
            kfuncs: &descs,
            maps: &map_descs,
            objects: &typed_object_storage,
        };

        let mut subprogs: Vec<SubprogInfo> = Vec::new();
        // Certified typed-field loads, empty unless a clean `verify()` produced
        // them. A `provisional` program never reaches a typed load — typed
        // programs are always fully verified — so leaving this empty on that
        // path is correct rather than merely conservative.
        let mut typed_load_sites: Vec<narf_bpf_verifier::TypedLoadSite> = Vec::new();
        // `None` unless a clean `verify()` produced a program that passed every
        // gate. Deliberately not set on the `provisional` path below: that
        // acceptance is *defined* as leaning on the interpreter's runtime
        // bounds checks, which native code does not perform.
        let mut jit = None;
        // Whether the program resizes the frame. Read from the verifier's
        // resolved call sites so it cannot disagree with what the interpreter
        // will intercept; the `provisional` path below leaves it false, which is
        // correct — that path accepts only non-`Value` `LD_IMM64` forms, none of
        // which is a kfunc call.
        let mut uses_xdp_adjust = false;
        let stack_bytes = match narf_bpf_verifier::verify(&prog) {
            Ok(v) => {
                if v.max_stack_bytes > MAX_STACK_BYTES {
                    return Err(LoadError::StackTooDeep {
                        needed: v.max_stack_bytes,
                        limit: MAX_STACK_BYTES,
                    });
                }
                // The arena count is gate 2's input and the verifier does not
                // have it — it bounds a displacement against a fixed window,
                // never against this program's extent. Taken from the very
                // group the program will run against, so the number cannot
                // describe a different one.
                let arena_count = arenas.as_ref().map_or(0, |g| g.arenas().len());
                jit = crate::jit_glue::try_compile(
                    &v,
                    true,
                    arena_count,
                    &req.maps,
                    &req.map_indices,
                )
                .ok();
                uses_xdp_adjust = v
                    .kfunc_calls
                    .iter()
                    .any(|c| crate::kfuncs::is_xdp_adjust(c.id));
                subprogs = v.subprogs;
                typed_load_sites = v.typed_load_sites;
                v.max_stack_bytes.max(1)
            }
            // The abstract interpreter is live, so this arm no longer catches
            // "everything" — it catches the two constructs `narf-bpf-verifier`
            // still declines to reason about, both `LD_IMM64` pseudo-forms: a
            // BTF-id kernel-variable address, and a subprogram address taken as
            // a value for a callback-style kfunc.
            //
            // Worth stating plainly, because the shape is misleading: this
            // fallthrough currently accepts **nothing**. `provisional` rejects
            // every non-`Value` `LD_IMM64` itself, so both constructs are
            // rejected either way — and `interp.rs` cannot execute either one,
            // so an acceptance here would produce a program that traps on its
            // first run. Reaching `provisional` is not the same as being
            // admitted by it, and the difference is the whole of why this is
            // not fail-open.
            Err(VerifyError::NotImplemented(_)) => {
                crate::provisional::accept(&req.insns, req.context, registry)
                    .map_err(LoadError::Rejected)?;
                STUB_STACK_BYTES as u32
            }
            Err(e) => return Err(LoadError::Rejected(e)),
        };

        let prog = Arc::new(Self {
            name: req.name,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            tag,
            gpl_compatible: metadata.gpl_compatible,
            load_time_ns: narf_time::monotonic_ns(),
            created_by_uid: metadata.created_by_uid,
            linux_prog_type: metadata.linux_prog_type,
            insns: req.insns,
            context: req.context,
            uses_xdp_adjust,
            typed_probe,
            typed_load_sites,
            initial_fuel: DEFAULT_FUEL,
            stack_bytes,
            subprogs,
            jit,
            arenas,
            maps: req.maps,
            map_indices: req.map_indices,
            _load_references: req.load_references,
            bound_maps: IrqSafeSpinLock::new(Vec::new()),
            runs: AtomicU64::new(0),
            stats_runs: AtomicU64::new(0),
            run_time_ns: AtomicU64::new(0),
            recursion_misses: AtomicU64::new(0),
            accumulated: AtomicU64::new(0),
            traps: AtomicU64::new(0),
        });
        // Publish the id → program direction, so `BPF_PROG_GET_FD_BY_ID` can
        // resolve it. Here rather than in the `bpf(2)` handler because a
        // program loaded any other way (the bench suite, the in-kernel smokes)
        // has an id too, and an id the registry does not know about is an id
        // that enumerates as a hole.
        crate::idreg::progs().insert(prog.id, &prog);
        Ok(prog)
    }

    /// The arenas this program may address. Empty when it has none.
    #[inline]
    #[must_use]
    pub fn arenas(&self) -> &[Arc<crate::arena::ProgArena>] {
        self.arenas.as_ref().map_or(&[], |g| g.arenas())
    }

    /// The context this program was verified for.
    #[inline]
    #[must_use]
    pub const fn context(&self) -> Context {
        self.context
    }

    /// Stable type key of this program's typed tracing context, if any.
    #[inline]
    #[must_use]
    pub fn typed_probe_type(&self) -> Option<u32> {
        self.typed_probe.as_ref().map(|typed| typed.type_key)
    }

    /// Whether a live typed probe wrapper satisfies this program's schema.
    #[must_use]
    pub fn accepts_typed_probe(&self, typed: &narf_tracing::TypedProbeRef) -> bool {
        self.typed_probe.as_ref().is_some_and(|expected| {
            expected.type_key == typed.type_key()
                && usize::try_from(expected.size).ok() == Some(typed.len())
                && expected.fields.len() == typed.fields().len()
                && expected
                    .fields
                    .iter()
                    .zip(typed.fields())
                    .all(|(want, got)| want.offset == got.offset && want.size == got.size)
        })
    }

    /// Instruction count.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Whether the program is empty. Never true for a loaded program.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Immutable Linux instruction image accepted at load time.
    ///
    /// NARF keeps map resolution beside this image rather than rewriting its
    /// immediates, so these are also the bytes reported as translated
    /// instructions by `BPF_OBJ_GET_INFO_BY_FD`.
    #[inline]
    #[must_use]
    pub fn instructions(&self) -> &[Insn] {
        &self.insns
    }

    /// Linux-compatible program tag: the first eight bytes of SHA-256 over
    /// the submitted instruction image after normalizing unstable map file
    /// descriptors.
    #[inline]
    #[must_use]
    pub const fn tag(&self) -> [u8; PROG_TAG_SIZE] {
        self.tag
    }

    /// Whether the program's load-time license is GPL compatible under
    /// Linux's exact license-string classification.
    #[inline]
    #[must_use]
    pub const fn gpl_compatible(&self) -> bool {
        self.gpl_compatible
    }

    /// Monotonic nanoseconds since boot when this program finished loading.
    #[inline]
    #[must_use]
    pub const fn load_time_ns(&self) -> u64 {
        self.load_time_ns
    }

    /// Effective uid captured from the task that loaded this program.
    #[inline]
    #[must_use]
    pub const fn created_by_uid(&self) -> u32 {
        self.created_by_uid
    }

    /// Linux program type captured by a syscall-shaped loader.
    ///
    /// Direct in-kernel loaders return `None`; their execution context remains
    /// available through [`Self::context`].
    #[inline]
    #[must_use]
    pub const fn linux_prog_type(&self) -> Option<u32> {
        self.linux_prog_type
    }

    /// The map named by this file descriptor, or `None`.
    ///
    /// What the interpreter resolves `LD_IMM64`'s `MapFd` form against. The
    /// verifier already proved the fd is in the set — this is the runtime
    /// looking up the same entry, and a `None` here would mean the two
    /// disagreed.
    #[must_use]
    pub fn map_by_fd(&self, fd: i32) -> Option<&Arc<crate::map::BpfMap>> {
        self.maps.iter().find(|(f, _)| *f == fd).map(|(_, m)| m)
    }

    /// The map at this position in the loader's fd array — `LD_IMM64`'s
    /// `MapIdx` form.
    #[must_use]
    pub fn map_by_idx(&self, idx: usize) -> Option<&Arc<crate::map::BpfMap>> {
        let idx = i32::try_from(idx).ok()?;
        self.map_indices
            .iter()
            .find(|indexed| indexed.index == idx)
            .map(|indexed| &indexed.map)
    }

    /// How many maps the loaded instruction image may address.
    #[must_use]
    pub fn map_count(&self) -> usize {
        let direct = self
            .maps
            .iter()
            .enumerate()
            .filter(|(i, (_, map))| {
                !self.maps[..*i]
                    .iter()
                    .any(|(_, earlier)| Arc::ptr_eq(earlier, map))
            })
            .count();
        let indexed_only = self
            .map_indices
            .iter()
            .enumerate()
            .filter(|(i, indexed)| {
                !self
                    .maps
                    .iter()
                    .any(|(_, direct)| Arc::ptr_eq(direct, &indexed.map))
                    && !self.map_indices[..*i]
                        .iter()
                        .any(|earlier| Arc::ptr_eq(&earlier.map, &indexed.map))
            })
            .count();
        direct + indexed_only
    }

    /// Bind `map` to this program's lifetime without granting program access.
    ///
    /// This is the object operation behind Linux-compatible
    /// `BPF_PROG_BIND_MAP`. A map already referenced by the loaded instruction
    /// image, or already explicitly bound through another fd, is a successful
    /// no-op.
    ///
    /// # Errors
    ///
    /// [`BindError::NoMemory`] if the lifetime-reference set cannot grow.
    pub fn bind_map(&self, map: Arc<crate::map::BpfMap>) -> Result<(), BindError> {
        if self
            .maps
            .iter()
            .any(|(_, existing)| Arc::ptr_eq(existing, &map))
            || self
                .map_indices
                .iter()
                .any(|indexed| Arc::ptr_eq(&indexed.map, &map))
        {
            return Ok(());
        }

        // Allocate a replacement outside the IRQ-masking lock. On a race that
        // grows the live vector beyond our capacity, drop the lock and retry;
        // cloning Arcs and swapping two already-allocated vectors are the only
        // operations performed in the critical section.
        let mut replacement = Vec::new();
        loop {
            let needed = self.bound_maps.lock().len() + 1;
            if replacement.capacity() < needed {
                replacement
                    .try_reserve_exact(needed)
                    .map_err(|_| BindError::NoMemory)?;
            }

            let mut bound = self.bound_maps.lock();
            if bound.iter().any(|existing| Arc::ptr_eq(existing, &map)) {
                return Ok(());
            }
            if replacement.capacity() < bound.len() + 1 {
                drop(bound);
                continue;
            }
            replacement.extend(bound.iter().cloned());
            replacement.push(map);
            core::mem::swap(&mut *bound, &mut replacement);
            drop(bound);
            return Ok(());
        }
    }

    /// Snapshot every map id whose lifetime this program holds.
    ///
    /// Load-time references come first in loader order, followed by explicit
    /// bindings in bind order. The snapshot keeps `BPF_OBJ_GET_INFO_BY_FD`
    /// consistent while another task adds a binding.
    ///
    /// # Errors
    ///
    /// [`BindError::NoMemory`] if storage for the snapshot cannot be allocated.
    pub fn used_map_ids(&self) -> Result<Vec<u32>, BindError> {
        let mut ids = Vec::new();
        loop {
            let needed = self.maps.len() + self.map_indices.len() + self.bound_maps.lock().len();
            if ids.capacity() < needed {
                ids.try_reserve_exact(needed)
                    .map_err(|_| BindError::NoMemory)?;
            }

            let bound = self.bound_maps.lock();
            if ids.capacity() < self.maps.len() + self.map_indices.len() + bound.len() {
                drop(bound);
                continue;
            }
            for (_, map) in &self.maps {
                if !ids.contains(&map.id) {
                    ids.push(map.id);
                }
            }
            for indexed in &self.map_indices {
                if !ids.contains(&indexed.map.id) {
                    ids.push(indexed.map.id);
                }
            }
            for map in bound.iter() {
                if !ids.contains(&map.id) {
                    ids.push(map.id);
                }
            }
            return Ok(ids);
        }
    }

    /// Invocation count.
    #[inline]
    #[must_use]
    pub fn runs(&self) -> u64 {
        self.runs.load(Ordering::Relaxed)
    }

    /// Invocations counted while runtime statistics were globally enabled.
    #[inline]
    #[must_use]
    pub fn stats_runs(&self) -> u64 {
        self.stats_runs.load(Ordering::Relaxed)
    }

    /// Nanoseconds accumulated while runtime statistics were globally enabled.
    #[inline]
    #[must_use]
    pub fn run_time_ns(&self) -> u64 {
        self.run_time_ns.load(Ordering::Relaxed)
    }

    /// Atomic invocations declined because the per-CPU nesting limit was full.
    ///
    /// Unlike [`Self::stats_runs`] and [`Self::run_time_ns`], Linux accounts
    /// recursion misses even when `BPF_ENABLE_STATS` is disabled. Oversized
    /// stack requests and an unavailable provider are not recursion misses.
    #[inline]
    #[must_use]
    pub fn recursion_misses(&self) -> u64 {
        self.recursion_misses.load(Ordering::Relaxed)
    }

    /// Sum of return values across every invocation.
    #[inline]
    #[must_use]
    pub fn accumulated(&self) -> u64 {
        self.accumulated.load(Ordering::Relaxed)
    }

    /// Invocations that trapped.
    #[inline]
    #[must_use]
    pub fn traps(&self) -> u64 {
        self.traps.load(Ordering::Relaxed)
    }

    /// Run the program in atomic context, on the per-CPU stack.
    ///
    /// Safe to call with IRQs masked and a caller lock held, which is exactly
    /// how `tracing::dispatch::fire()` invokes handlers: no allocation, no
    /// locks beyond the per-CPU stack claim, and no await point reachable
    /// (a sleepable kfunc from an atomic program is [`crate::interp::Trap`],
    /// not a park).
    ///
    /// Returns `None` if the per-CPU stack provider declined — nesting, or a
    /// stack request larger than a frame. Declining is the designed
    /// behaviour: `bpf/specification/spec.md` §1.5 makes re-entrancy a depth
    /// counter, so depth N+1 loses its invocation rather than corrupting the
    /// frame below it.
    pub fn run_atomic(&self, ctx: [u64; MAX_CTX_WORDS], ctx_len: usize) -> Option<Outcome> {
        // Typed contexts contain a pointer to a short-lived kernel wrapper.
        // Only `run_typed_probe` may construct that context; admitting a raw
        // caller here would let it forge the wrapper pointer before the
        // runtime mediator had a chance to validate anything.
        if self.typed_probe.is_some() || self.linux_prog_type == Some(BPF_PROG_TYPE_XDP) {
            return None;
        }
        self.run_atomic_inner(ctx, ctx_len)
    }

    /// Run an XDP program against one live, writable packet frame, returning the
    /// verdict and the resulting packet length.
    ///
    /// This is also the safe test-run boundary: callers supply bytes, never
    /// raw context words. The returned length is what the frame's effective
    /// `[data, data_end)` window is after the program returns, and `frame` holds
    /// those bytes in `frame[..len]` — that is what `XDP_PASS` delivers and
    /// `XDP_TX`/`XDP_REDIRECT` retransmit. For a program that does not resize the
    /// frame the length is just `frame.len()`.
    ///
    /// The frame is `&mut`: a program that rewrites a header byte writes it in
    /// place, so the borrow the caller passed in reflects the mutation on
    /// return. The native (JITed) path writes the packet through the address the
    /// ctx pair already carries, and the interpreter services the same bounded
    /// store against this slice; the two agree on `[data, data_end)`.
    ///
    /// ## Frame resizing
    ///
    /// A program that calls `bpf_xdp_adjust_head`/`_tail` needs head/tailroom the
    /// bare RX frame does not have — the driver hands a slice sized to exactly
    /// the packet. So a resizing program (known from a load-time flag, and always
    /// interpreted — the JIT refuses one) is staged into a per-CPU buffer laid
    /// out `[headroom | packet | tailroom]`, with `data`/`data_end` pointing at
    /// the packet sub-range. The adjust intrinsics move those pointers within the
    /// buffer; on return the effective packet is `[data, data_end)` of the
    /// staged buffer, which is copied back into `frame[..len]`. Because `frame`
    /// is the delivery/retransmit buffer, a grown packet can only be delivered up
    /// to `frame.len()` bytes — the staging gives the program room to work, and
    /// the copy-back is bounded by the caller's frame. A non-resizing program
    /// runs against `frame` directly with no staging copy, so the common RX path
    /// is untouched.
    pub fn run_xdp(&self, frame: &mut [u8]) -> Option<(Outcome, usize)> {
        if self.linux_prog_type != Some(BPF_PROG_TYPE_XDP) || self.context != Context::Atomic {
            return None;
        }
        if self.uses_xdp_adjust {
            return self.run_xdp_staged(frame);
        }
        let range = frame.as_ptr_range();
        let len = frame.len();
        let outcome = self.run_atomic_inner_with_region(
            [range.start as u64, range.end as u64, 0, 0],
            2,
            Some(frame),
            None,
        )?;
        Some((outcome, len))
    }

    /// Run a frame-resizing XDP program against a per-CPU staged buffer.
    ///
    /// The frame is copied into `[headroom | packet | tailroom]`; the program
    /// runs against the packet sub-range with `data`/`data_end` pointing into the
    /// staged buffer, so `bpf_xdp_adjust_head`/`_tail` have real room on either
    /// side. On return the effective packet `[data, data_end)` is copied back
    /// into `frame`, truncated to `frame.len()` — the delivery/retransmit ceiling
    /// — and its length returned. Always interpreted: the JIT refuses a program
    /// that calls an adjust intrinsic.
    fn run_xdp_staged(&self, frame: &mut [u8]) -> Option<(Outcome, usize)> {
        // Larger than a staged buffer fits: deliver it unresized rather than
        // truncating. The program still runs against the frame directly; any
        // adjust it attempts finds no headroom/tailroom and returns `-ENOMEM`.
        if frame.len() > XDP_STAGE_PACKET_MAX {
            let range = frame.as_ptr_range();
            let len = frame.len();
            let outcome = self.run_atomic_inner_with_region(
                [range.start as u64, range.end as u64, 0, 0],
                2,
                Some(frame),
                None,
            )?;
            return Some((outcome, len));
        }
        // Claim this CPU's staging buffer. An XDP program runs with IRQs masked
        // and `XDP_PROGS` held (`classifier::run_xdp`), so between the claim and
        // the copy-back the running CPU cannot change and no other frame on this
        // CPU can reach the same buffer — the same invariant the per-CPU redirect
        // slot in `crate::kfuncs` relies on.
        let mut stage = crate::xdp_stage::Guard::claim();
        let plen = frame.len();
        {
            let buf = stage.bytes_mut();
            // Zero the headroom/tailroom the program may grow into, then place
            // the packet after the headroom. Zeroed slack is harmless to read
            // (the verifier still confines a legitimate access to
            // `[data, data_end)`) and is what a grown header/trailer starts as,
            // matching Linux.
            buf[..XDP_HEADROOM].fill(0);
            buf[XDP_HEADROOM..XDP_HEADROOM + plen].copy_from_slice(frame);
            buf[XDP_HEADROOM + plen..].fill(0);
        }
        let base = stage.bytes_mut().as_ptr() as u64;
        let data = base + XDP_HEADROOM as u64;
        let data_end = data + plen as u64;

        // Interpreted, always: the JIT refuses a program that calls an adjust
        // intrinsic, so this never has a native image to prefer. The interpreter
        // reports the final context words back, from which the effective packet
        // window is recovered.
        let (outcome, final_ctx) =
            self.run_xdp_staged_interp([data, data_end, 0, 0], stage.bytes_mut())?;

        // The effective packet is `[data, data_end)` the program left behind.
        // The intrinsics only ever move these within `[base, base + STAGE_LEN]`,
        // so the offsets recover exactly; guard against a nonsensical pair by
        // falling back to the original window.
        let (out_data, out_end) = (final_ctx[0], final_ctx[1]);
        let (off, out_len) =
            if out_end >= out_data && out_data >= base && out_end <= base + XDP_STAGE_LEN as u64 {
                ((out_data - base) as usize, (out_end - out_data) as usize)
            } else {
                (XDP_HEADROOM, plen)
            };
        let copy = out_len.min(frame.len());
        frame[..copy].copy_from_slice(&stage.bytes_mut()[off..off + copy]);
        Some((outcome, copy))
    }

    /// Interpret a staged XDP program, returning the verdict and the final
    /// context words (`[data, data_end, …]`) the program left behind.
    ///
    /// Split from [`Self::run_atomic_interpreted_inner`] because the staged path
    /// alone needs the resized window back: `bpf_xdp_adjust_head`/`_tail` rewrite
    /// `ctx[0]`/`ctx[1]`, and the caller copies out `[data, data_end)`. Every
    /// other interpreter caller discards the context on return.
    fn run_xdp_staged_interp(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        region: &mut [u8],
    ) -> Option<(Outcome, [u64; MAX_CTX_WORDS])> {
        let _confined = crate::domain::enter();
        let frame = self.acquire_atomic_frame()?;
        let registry = crate::kfunc::registry()?;
        let mut vm = Vm::new(
            crate::interp::VmProgram {
                insns: &self.insns,
                subprogs: &self.subprogs,
                context: self.context,
                fuel: self.initial_fuel,
                maps: &self.maps,
            },
            ctx,
            2,
            frame,
            registry,
        )
        .with_arenas(self.arenas())
        .with_map_indices(&self.map_indices)
        .with_packet_region(region);
        let stats_start = crate::stats::run_start();
        let outcome = crate::interp::drive(vm.run());
        self.record(outcome, stats_start);
        Some((outcome, vm.context_words()))
    }

    /// Run the XDP path through the interpreter for kernel differential tests.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn run_xdp_interpreted(&self, frame: &mut [u8]) -> Option<Outcome> {
        if self.linux_prog_type != Some(BPF_PROG_TYPE_XDP) || self.context != Context::Atomic {
            return None;
        }
        let range = frame.as_ptr_range();
        let _confined = crate::domain::enter();
        self.run_atomic_interpreted_inner(
            [range.start as u64, range.end as u64, 0, 0],
            2,
            Some(frame),
            None,
        )
    }

    /// Run against the live wrapper supplied by synchronous typed dispatch.
    pub(crate) fn run_typed_probe(&self, typed: &narf_tracing::TypedProbeRef) -> Option<Outcome> {
        if !self.accepts_typed_probe(typed) {
            return None;
        }
        // The wrapper travels alongside its context word: the context word is
        // what the program reads through `ctx[0]`, and the wrapper is what a
        // certified typed load reads its field from — the authoritative source
        // the interpreter uses rather than the program's own register.
        self.run_atomic_inner_with_region([typed.as_context_word(), 0, 0, 0], 1, None, Some(typed))
    }

    fn run_atomic_inner(&self, ctx: [u64; MAX_CTX_WORDS], ctx_len: usize) -> Option<Outcome> {
        self.run_atomic_inner_with_region(ctx, ctx_len, None, None)
    }

    fn run_atomic_inner_with_region(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
        packet_region: Option<&mut [u8]>,
        typed: Option<&narf_tracing::TypedProbeRef>,
    ) -> Option<Outcome> {
        // Confine the whole run to the BPF hardware domain: a verifier or JIT
        // escape that stores into another subsystem's domain (the cap table, the
        // scheduler, a driver) takes a protection-key fault rather than
        // corrupting it. FRAME stays reachable, so the interpreter's own stack,
        // the kfunc shims, the maps on the heap, and the fault handler all keep
        // working. A no-op unless the PKS backend is live. See `crate::domain`.
        let _confined = crate::domain::enter();
        if let Some(image) = self.jit.as_ref() {
            // The belt to `jit_glue`'s gate-2 brace, in the shape the lifted gate
            // needs. It used to read "native only if the program has no arena",
            // which the gate already guaranteed; now the gate admits exactly one
            // arena, so the belt is that an image which *dereferences* the slot
            // base is only ever entered with the slot base it was compiled for.
            //
            // Tested against the image rather than against `uses_arena`, because
            // it is the emitted code that will do the dereferencing, and one
            // comparison per invocation makes the failure mode — native code
            // indexing off a zero base — structurally impossible rather than
            // merely currently absent.
            let slot_base = self.arenas.as_ref().map_or(0, |g| g.slot_base());
            if self.native_path_admits(image, slot_base) {
                // Emitted code gets the *tagged* base. The admission check
                // above deliberately uses the untagged one: it is a `!= 0`
                // test, and a tag would only obscure what is being asserted.
                // See `ArenaGroup::slot_base_tagged` for why tagging the base
                // is the entirety of the JIT-side addressing contract.
                let entry_base = self.arenas.as_ref().map_or(0, |g| g.slot_base_tagged());
                return self.run_atomic_native(ctx, ctx_len, entry_base);
            }
        }
        self.run_atomic_interpreted_inner(ctx, ctx_len, packet_region, typed)
    }

    /// Run interpreted, whatever `self.jit` holds.
    ///
    /// Public so the differential smoke can compare the two paths on the same
    /// program. That comparison is the only test that checks the emitter's
    /// *semantics* rather than its bytes — golden encodings prove the emitter
    /// produced what was intended, and the interpreter is the oracle for
    /// whether the intent was right.
    pub fn run_atomic_interpreted(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
    ) -> Option<Outcome> {
        if self.typed_probe.is_some() || self.linux_prog_type == Some(BPF_PROG_TYPE_XDP) {
            return None;
        }
        // This public differential-test entry point is still an execution
        // boundary. Keep it under the same hardware fence as the normal
        // atomic dispatcher so external callers cannot bypass confinement by
        // forcing the interpreter.
        let _confined = crate::domain::enter();
        self.run_atomic_interpreted_inner(ctx, ctx_len, None, None)
    }

    fn run_atomic_interpreted_inner(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
        packet_region: Option<&mut [u8]>,
        typed: Option<&narf_tracing::TypedProbeRef>,
    ) -> Option<Outcome> {
        if self.context != Context::Atomic {
            return None;
        }
        // Prefer the real per-CPU region; fall back to the stub only before
        // `memory::bpf_stack::init` has run. The fallback is deliberately
        // small, so a program verified against the real ceiling is *declined*
        // rather than silently run on a frame smaller than it was proved to
        // need — the two sizes disagreeing silently is what the stub-only path
        // used to do (4 KiB stub against a 16 KiB verified ceiling).
        let frame = self.acquire_atomic_frame()?;
        let registry = crate::kfunc::registry()?;
        // Four readable words, tail zero-filled — the same contract
        // `run_atomic_native` provides, because the verifier proved all four
        // readable and the two paths must not disagree. See the note there.
        let mut ctx = ctx;
        for w in ctx.iter_mut().skip(ctx_len.min(MAX_CTX_WORDS)) {
            *w = 0;
        }
        let mut vm = Vm::new(
            crate::interp::VmProgram {
                insns: &self.insns,
                subprogs: &self.subprogs,
                context: self.context,
                fuel: self.initial_fuel,
                maps: &self.maps,
            },
            ctx,
            MAX_CTX_WORDS,
            frame,
            registry,
        )
        .with_arenas(self.arenas())
        .with_map_indices(&self.map_indices);
        if let Some(region) = packet_region {
            vm = vm.with_packet_region(region);
        }
        // Only a typed run binds a wrapper, and only then can a certified typed
        // load reach a field — a program with no bound wrapper traps on one,
        // which is the fail-closed shape an unbound arena has.
        if let Some(wrapper) = typed {
            vm = vm.with_typed_probe(wrapper, &self.typed_load_sites);
        }
        // An atomic program cannot reach an await point, so the future
        // completes on its first poll and `drive` never spins.
        let stats_start = crate::stats::run_start();
        let outcome = crate::interp::drive(vm.run());
        self.record(outcome, stats_start);
        Some(outcome)
    }

    /// Run the compiled image.
    ///
    /// Only reachable when [`crate::jit_glue::try_compile`] accepted the
    /// program, which means: the verifier proved it (not the `provisional`
    /// path), it touches at most one arena, it has no *non-arena* faulting
    /// accesses, and every non-arena dereference has a verifier-published stack
    /// or context certificate. Those gates are why this can hand control to
    /// generated code without the interpreter's per-access bounds checks.
    /// ("No back-edge" was lifted when the emitter learned to
    /// burn fuel per block; "no arena" when it learned the slot-relative access
    /// shape and the exception table behind it.)
    ///
    /// `slot_base` is the program's arena slot, or zero when it has none, and
    /// carries the arena's MTE tag in bits 59:56 on a machine with MTE — see
    /// [`crate::arena::ArenaGroup::slot_base_tagged`]. The caller establishes
    /// that an image containing arena accesses is never entered with a zero —
    /// see [`BpfProg::run_atomic`]. The tag does not disturb that check: it
    /// occupies bits no VA in the slot uses, and is applied only to a base
    /// that was already non-zero.
    fn run_atomic_native(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
        slot_base: u64,
    ) -> Option<Outcome> {
        if self.context != Context::Atomic {
            return None;
        }
        let image = self.jit.as_ref()?;
        let mut frame = self.acquire_atomic_frame()?;
        // The frame is already zeroed by the provider, which native code relies
        // on exactly as the interpreter does: the verifier permits reading a
        // widened stack slot before any concrete write, so the bytes must not be
        // a previous program's.
        let top = frame.top_addr();
        let _ = frame.bytes_mut();
        // The verifier types every program's context as four scalars
        // (`CTX_SCALARS`), so it proves all four readable — but the interpreter
        // additionally bounds reads at the *runtime* `ctx_len`, while native
        // code emits no such check. A caller passing fewer words therefore got
        // `Trap::BadAccess` interpreted and a zero read JITed: same program,
        // different answer. Reachable through perf, whose `ctx_len` is
        // `raw.len() / 8` and can be zero.
        //
        // Resolved in favour of what was actually proved: the runtime supplies
        // four readable words, zero-filling the tail. A caller with less data
        // is not lying to the program — `ctx[0]`-style length fields remain the
        // authority on how much is meaningful, as the XDP summary already does.
        // Per-attach-point context typing is the real fix and is spec §8's
        // remaining ctx item; this makes the two execution paths agree in the
        // meantime, which is the property that cannot be allowed to differ.
        let mut ctx = ctx;
        for w in ctx.iter_mut().skip(ctx_len.min(MAX_CTX_WORDS)) {
            *w = 0;
        }
        let entry = image.entry();
        let stats_start = crate::stats::run_start();
        // SAFETY: `entry` points at sealed, executable text emitted for this
        // program, entered with the ABI its prologue expects — `top` is the
        // frame's highest address (R10), `ctx.as_ptr()` a live `[u64; 4]` (R1),
        // and `slot_base` this program's own arena slot, which the caller has
        // established is non-zero whenever the image dereferences it. `ctx`
        // outlives the call; `frame` is held across it so the memory R10
        // addresses stays leased. The gates above are what make the absence of
        // runtime bounds checks sound; for arena accesses specifically it is the
        // slot's guards plus the exception table registered before the text was
        // sealed.
        let packed = unsafe { entry(top, ctx.as_ptr() as u64, self.initial_fuel, slot_base) };
        // SysV's rax:rdx pair: low half is R0 (or, on an arena fault, the
        // offending handle), high half a status code. Reported out of band
        // because no in-band sentinel works — the obvious one, u64::MAX, is
        // exactly what `r0 = -1; exit` returns.
        let value = packed as u64;
        let outcome = match (packed >> 64) as u64 {
            narf_bpf_jit::status::OK => Outcome::Returned(value),
            // Matches the interpreter: exhaustion stops the program with a
            // diagnostic rather than a fault, and the return value is
            // meaningless (§4.9). `at` is not recoverable from native code
            // without a side table, so it names the entry.
            narf_bpf_jit::status::OUT_OF_FUEL => {
                Outcome::Trapped(crate::interp::Trap::OutOfFuel { at: 0 })
            }
            // An arena access faulted and the exception table recovered it into
            // the arena epilogue. The same trap the interpreter raises for the
            // same handle — deliberately not a zeroed register and a resumed
            // program, which would make the two paths disagree. `at` and `len`
            // are not recoverable without a side table; the handle is, because
            // the emitter folds the displacement into the index register so the
            // epilogue can return it.
            narf_bpf_jit::status::ARENA_FAULT => {
                Outcome::Trapped(crate::interp::Trap::ArenaOutOfBounds {
                    at: 0,
                    handle: value,
                    len: 0,
                })
            }
            // The arena atomic's emitted alignment guard branches here before
            // touching memory. As with a recovered arena fault, the handle is
            // retained in the low half; the exact instruction and width would
            // require a side table and are reported as their native sentinel.
            narf_bpf_jit::status::ARENA_UNALIGNED => {
                Outcome::Trapped(crate::interp::Trap::ArenaUnaligned {
                    at: 0,
                    handle: value,
                    len: 0,
                })
            }
            // Unreachable: the emitters return one of the four above and
            // nothing else. Treated as a stop rather than a value, because the
            // one thing that must not happen is a status nobody understands
            // being read as a successful return.
            _ => Outcome::Trapped(crate::interp::Trap::Unsupported {
                at: 0,
                what: "compiled program returned an unknown status",
            }),
        };
        self.record(outcome, stats_start);
        Some(outcome)
    }

    /// Claim the stack for one atomic invocation and classify a refusal.
    ///
    /// A loaded program is verifier-bounded to the real region's per-level
    /// size. Therefore a real-provider refusal after boot means the nesting
    /// budget is full. Before boot reaches that provider, the smaller stub can
    /// also reject an otherwise valid program for size; that case must not be
    /// reported as Linux's `recursion_misses`.
    fn acquire_atomic_frame(&self) -> Option<StackFrame<'_>> {
        let bytes = self.stack_bytes as usize;
        if crate::mem::region_ready() {
            let frame = PerCpuRegion.acquire(bytes);
            if frame.is_none() && (bytes as u64) <= narf_memory::bpf_stack::bytes_per_level() {
                self.recursion_misses.fetch_add(1, Ordering::Relaxed);
            }
            frame
        } else {
            let frame = PerCpuStackStub.acquire(bytes);
            if frame.is_none() && bytes <= STUB_STACK_BYTES {
                self.recursion_misses.fetch_add(1, Ordering::Relaxed);
            }
            frame
        }
    }

    /// Whether this program runs as native code.
    #[inline]
    #[must_use]
    pub fn is_jited(&self) -> bool {
        match self.jit.as_ref() {
            None => false,
            Some(image) => {
                let slot_base = self.arenas.as_ref().map_or(0, |g| g.slot_base());
                self.native_path_admits(image, slot_base)
            }
        }
    }

    /// Whether `run_atomic` would actually enter native code.
    ///
    /// Holding a `JitImage` is necessary but **not** sufficient: the run path
    /// also re-checks, per invocation, that an image whose emitted code
    /// dereferences the arena slot base is only ever entered with a non-zero
    /// base and exactly one arena.
    ///
    /// This exists as one predicate, consulted by both the run path and
    /// [`Self::is_jited`], because they were two. `is_jited` answered
    /// `self.jit.is_some()` while the run path applied the extra clause — so
    /// breaking that clause would have sent every arena program down the
    /// interpreter while `is_jited` still reported `true`, and
    /// `tests::diff_run`'s non-vacuity assertion is built on `is_jited`. All
    /// seven arena differential tests would have compared the interpreter with
    /// itself and stayed green, with the arena lowering — the one lowering
    /// carrying no bounds check — not executing at all.
    #[inline]
    fn native_path_admits(&self, image: &crate::jit_glue::JitImage, slot_base: u64) -> bool {
        !image.uses_arena() || (slot_base != 0 && self.arenas().len() == 1)
    }

    /// Bytes of emitted native code, or 0 when the program runs interpreted.
    ///
    /// `bpf_prog_info.jited_prog_len` is how every Linux tool decides whether a
    /// program is JITed — bpftool prints "jited" on `jited_prog_len != 0` and
    /// nothing else. Reporting 0 for a compiled program would therefore be a
    /// lie in the one field that answers the question.
    #[inline]
    #[must_use]
    pub fn jited_len(&self) -> usize {
        self.jit
            .as_ref()
            .map_or(0, crate::jit_glue::JitImage::text_len)
    }

    /// Emitted native instruction bytes, empty when this program is interpreted.
    ///
    /// This is the privileged introspection view behind
    /// `bpf_prog_info.jited_prog_insns`; execution continues to enter through
    /// the sealed image owned by the program.
    #[inline]
    #[must_use]
    pub fn jited_bytes(&self) -> &[u8] {
        self.jit
            .as_ref()
            .map_or(&[], crate::jit_glue::JitImage::text)
    }

    /// Run the program on a heap stack owned by the caller's future.
    ///
    /// The sleepable path (spec §4.8): a sleeping program cannot hold a
    /// per-CPU slot across a yield, because another task may run on that CPU.
    pub async fn run_sleepable(
        &self,
        ctx: [u64; MAX_CTX_WORDS],
        ctx_len: usize,
    ) -> Option<Outcome> {
        let stack = HeapStack::new(self.stack_bytes as usize);
        let frame = stack.acquire(self.stack_bytes as usize)?;
        let registry = crate::kfunc::registry()?;
        let mut vm = Vm::new(
            crate::interp::VmProgram {
                insns: &self.insns,
                subprogs: &self.subprogs,
                context: self.context,
                fuel: self.initial_fuel,
                maps: &self.maps,
            },
            ctx,
            ctx_len,
            frame,
            registry,
        )
        .with_arenas(self.arenas())
        .with_map_indices(&self.map_indices);
        let stats_start = crate::stats::run_start();
        let outcome = crate::domain::run_sleepable(vm.run()).await;
        self.record(outcome, stats_start);
        Some(outcome)
    }

    fn record(&self, outcome: Outcome, stats_start: Option<u64>) {
        self.runs.fetch_add(1, Ordering::Relaxed);
        if let Some(elapsed) = crate::stats::run_elapsed(stats_start) {
            self.run_time_ns.fetch_add(elapsed, Ordering::Relaxed);
            self.stats_runs.fetch_add(1, Ordering::Relaxed);
        }
        match outcome {
            Outcome::Returned(v) => {
                self.accumulated.fetch_add(v, Ordering::Relaxed);
            }
            Outcome::Trapped(_) => {
                self.traps.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for BpfProg {
    fn drop(&mut self) {
        // Prune the id entry. The registry holds a `Weak`, so a lookup racing
        // this teardown already fails rather than resurrecting anything — this
        // is about the table not growing by one slot per program for the whole
        // boot. See `crate::idreg` for why both halves are needed.
        crate::idreg::progs().remove(self.id);
    }
}

/// Refuse a construct the verifier accepts but no backend can execute.
///
/// A program the verifier proves and the runtime then cannot run is a contract
/// break even though it is not a safety hole — the same one [`MAX_STACK_BYTES`]
/// and `MAX_CALL_DEPTH` exist to prevent, and it is much worse to discover at
/// fire time than at load. The verifier is a library and stays general; this is
/// the runtime stating its own limit.
///
/// Today that is exactly one construct: `LD_IMM64`'s map-*value* pseudo-forms.
/// The verifier resolves and bounds them, but neither the interpreter (which has
/// no synthetic region aliasing a map's value bytes) nor the x86_64 emitter
/// (which does not lower `LD_IMM64` at all) can produce the address.
fn reject_unrunnable(insns: &[Insn]) -> Result<(), LoadError> {
    use narf_bpf_isa::{Decoded, Imm64};
    let mut i = 0usize;
    while i < insns.len() {
        // An undecodable image is the verifier's error to report, with its own
        // instruction index; stopping here would pre-empt a better diagnostic.
        let Ok((d, width)) = narf_bpf_isa::decode(insns, i) else {
            return Ok(());
        };
        if let Decoded::LoadImm64 {
            value: Imm64::MapValue { .. } | Imm64::MapIdxValue { .. },
            ..
        } = d
        {
            return Err(LoadError::Rejected(VerifyError::NotImplemented(
                "LD_IMM64 map-value pseudo-form: no backend can produce the address",
            )));
        }
        i += width;
    }
    Ok(())
}

/// The four scalar fields of the probe context tuple.
static CTX_SCALARS: [narf_bpf_verifier::ArgDesc; MAX_CTX_WORDS] =
    [narf_bpf_verifier::ArgDesc::SCALAR64; MAX_CTX_WORDS];

/// A loaded program behind an fd.
///
/// Anon-fd pattern, as `sys_eventfd` / `sys_memfd_create` use: an
/// `Arc<dyn FileOps>` in an `FdEntry` with no backing file. Reads and writes are
/// `Unsupported` — a prog fd is a handle, not a stream, and `read(2)` on one
/// returns `-EINVAL` on Linux too.
///
/// Lives here rather than beside the `bpf(2)` handler because more than one
/// caller needs to recover a program from a file descriptor —
/// `BPF_PROG_TEST_RUN` and `PERF_EVENT_IOC_SET_BPF` — and a downcast only works
/// if every one of them can name the concrete type. When it was private to the
/// syscall module, perf had no way to express the downcast at all.
#[derive(Debug)]
pub struct ProgFile {
    prog: Arc<BpfProg>,
}

impl ProgFile {
    /// Wrap a loaded program for installation in an fd table.
    #[must_use]
    pub fn new(prog: Arc<BpfProg>) -> Self {
        Self { prog }
    }

    /// The program behind this fd.
    #[must_use]
    pub fn prog(&self) -> Arc<BpfProg> {
        Arc::clone(&self.prog)
    }
}

impl narf_filesystem::FileOps for ProgFile {
    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RO,
            mtime_cycles: 0,
        }
    }
    /// The hook every fd-to-program recovery goes through.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}
