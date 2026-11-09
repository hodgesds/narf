//! Intel render-node UAPI over per-open GEM/context/VM namespaces.
//!
//! Production GuC cards identify as Xe and accept its exact ioctl encodings
//! plus the explicit i915 compatibility subset. Submission admission is
//! independent of display admission.
//! Unsupported acceleration is reported as such, never as a completed job.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use narf_filesystem::{FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

use crate::intel_gpu::Generation;
use crate::intel_gpu_gem::GemState;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_hwconfig::HardwareConfig;
use crate::intel_gpu_uapi::{self as abi, put32, put64, u32_at, u64_at};

const MAX_COPY: usize = 1024 * 1024;
const MAX_QUERIES: usize = 64;
const MAX_CONTEXTS: usize = 64;
const MAX_VMS: usize = 64;
/// The proto-context's key inside CREATE's private, unshared Namespaces.
/// It is never a visible name: publication re-keys it to the reserved ID.
const PROTO_NAME: u32 = u32::MAX;
/// include/uapi/linux/capability.h.
const CAP_SYS_ADMIN: u32 = 21;
const CAP_SYS_NICE: u32 = 23;
/// I915_SCHEDULER_CAP_ENABLED, _PRIORITY and _PREEMPTION.
const SCHEDULER_CAP_ENABLED: i32 = 1 << 0;
const SCHEDULER_CAP_PRIORITY: i32 = 1 << 1;
const SCHEDULER_CAP_PREEMPTION: i32 = 1 << 2;
/// I915_CONTEXT_MAX_USER_PRIORITY; I915_CONTEXT_MIN_USER_PRIORITY is its
/// negation and I915_CONTEXT_DEFAULT_PRIORITY is 0.
const CONTEXT_MAX_USER_PRIORITY: i64 = 1023;

/// i915->caps.scheduler, as GETPARAM HAS_SCHEDULER reports it and as
/// validate_priority and proto_context_set_persistence test it. Linux's
/// intel_engine_user.c::set_scheduler_caps gives every GuC device ENABLED
/// and PRIORITY (sched_engine->schedule), and PREEMPTION, ENGINE_BUSY_STATS
/// and STATIC_PRIORITY_MAP from its engine flags; with no uabi engine the
/// caps are 0. NARF advertises ENABLED and PRIORITY while a live owner admits
/// submission: every hardware member registers with its context's priority
/// through map_i915_prio_to_guc_prio, and a request queued behind a job in
/// flight raises that job's registered GuC priority
/// (UserContext::queue_request). PREEMPTION, BUSY_STATS and
/// STATIC_PRIORITY_MAP stay clear because no preempt-to-idle cancellation,
/// busy-stat or priority-map contract exists.
fn scheduler_caps(info: &DeviceInfo) -> i32 {
    if info.submission_ready() {
        SCHEDULER_CAP_ENABLED | SCHEDULER_CAP_PRIORITY
    } else {
        0
    }
}

/// What set_proto_ctx_param and ctx_setparam consult beyond the argument,
/// sampled before the namespace's IRQ-safe lock. capable() is asked exactly
/// where Linux asks it: CAP_SYS_ADMIN for a size-0 BANNABLE (the left
/// operand of `!capable(CAP_SYS_ADMIN) && !args->value`), CAP_SYS_NICE for
/// an in-range PRIORITY above I915_CONTEXT_DEFAULT_PRIORITY.
#[derive(Copy, Clone, Debug)]
struct ParamFacts {
    /// set_proto_ctx_param's intel_uc_uses_guc_submission for LOW_LATENCY.
    low_latency: bool,
    scheduler: i32,
    sys_admin: bool,
    sys_nice: bool,
}

impl ParamFacts {
    /// GETPARAM (`set` false) asks no capability.
    fn sample(info: &DeviceInfo, param: &[u8], set: bool, low_latency: bool) -> Self {
        let size = u32_at(param, 4);
        let value = u64_at(param, 16);
        let scheduler = scheduler_caps(info);
        let (sys_admin, sys_nice) = match u64_at(param, 8) {
            _ if !set => (false, false),
            abi::CONTEXT_PARAM_BANNABLE if size == 0 => {
                (narf_filesystem::caller_capable(CAP_SYS_ADMIN), false)
            }
            // validate_priority asks CAP_SYS_NICE only after its size,
            // capability and range checks have passed.
            abi::CONTEXT_PARAM_PRIORITY
                if size == 0
                    && scheduler & SCHEDULER_CAP_PRIORITY != 0
                    && (1..=CONTEXT_MAX_USER_PRIORITY).contains(&(value as i64)) =>
            {
                (false, narf_filesystem::caller_capable(CAP_SYS_NICE))
            }
            _ => (false, false),
        };
        Self {
            low_latency,
            scheduler,
            sys_admin,
            sys_nice,
        }
    }
}

/// i915_gem_context.c::validate_priority:173, in its order.
fn validate_priority(size: u32, value: u64, facts: ParamFacts) -> Result<(), FsError> {
    let priority = value as i64;
    if size != 0 {
        return Err(FsError::InvalidData);
    }
    if facts.scheduler & SCHEDULER_CAP_PRIORITY == 0 {
        return Err(FsError::NoDevice);
    }
    if !(-CONTEXT_MAX_USER_PRIORITY..=CONTEXT_MAX_USER_PRIORITY).contains(&priority) {
        return Err(FsError::InvalidData);
    }
    if priority > 0 && !facts.sys_nice {
        return Err(FsError::OperationNotPermitted);
    }
    Ok(())
}

/// A submission profile, deliberately separate from display generation gates.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubmissionProfile {
    Gen12Execlists,
    Gen12GuC,
    XeLpgGuC,
    Unsupported,
}

impl SubmissionProfile {
    pub const fn for_generation(generation: Generation) -> Self {
        match generation {
            Generation::TigerLake | Generation::AlderLake => Self::Gen12GuC,
            Generation::MeteorLake => Self::XeLpgGuC,
            Generation::LunarLake | Generation::PantherLake => Self::Unsupported,
        }
    }
}

/// Probe-owned facts. No topology, memory size or firmware version is guessed.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub device_id: u16,
    pub platform: GtPlatform,
    pub memory_bytes: u64,
    pub hwconfig: Option<Arc<HardwareConfig>>,
    pub topology: Option<Arc<crate::intel_gpu_topology::GtTopology>>,
    pub vram: Option<Arc<crate::intel_gpu_vram::Vram>>,
    pub backend: Option<Arc<dyn crate::intel_gpu_user::UserBackend>>,
}

impl DeviceInfo {
    pub fn for_card(card: u32) -> Option<Self> {
        let card = crate::drm_registry::card(card)?;
        if card.driver() != "intel-gpu" {
            return None;
        }
        let device_id = card.device_id();
        let platform = GtPlatform::from_pci(card.vendor_id(), device_id)?;
        Some(Self {
            device_id,
            platform,
            memory_bytes: narf_memory::frame::stats().total as u64 * 4096,
            hwconfig: card.intel_hwconfig(),
            topology: card.intel_topology(),
            vram: card.intel_vram(),
            backend: card.intel_user_backend(),
        })
    }

    /// No userspace engine is published until isolation, context setup,
    /// completion and reset/loss handling are installed by the GT owner.
    pub fn submission_ready(&self) -> bool {
        self.user_status().is_some()
    }
    fn object_async_ready(&self) -> bool {
        crate::intel_gpu_exec::object_async_profile(self.platform)
            && self
                .user_status()
                .is_some_and(|status| status.engines.bits() != 0)
    }

    pub fn native_xe(&self) -> bool {
        self.platform.guc().is_some()
            && self
                .backend
                .as_ref()
                .is_some_and(|backend| backend.native_xe())
    }

    fn user_status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        self.backend
            .as_ref()
            .and_then(|backend| backend.status())
            .filter(|status| status.epoch != 0 && status.platform == self.platform)
    }
}

#[derive(Debug)]
struct Vm {
    _identity: u32,
}

type EngineMap = Vec<Option<crate::intel_gpu_engine::EngineSet>>;

/// One i915 context. Legacy rings select its RCS0/BCS0 states; a user
/// engine map gives every slot its own hardware context, as i915 does.
#[derive(Clone, Debug)]
struct Context {
    user: Arc<crate::intel_gpu_user::UserContext>,
    copy: Arc<crate::intel_gpu_user::UserContext>,
    media: BTreeMap<crate::intel_gpu_engine::Engine, Arc<crate::intel_gpu_user::UserContext>>,
    /// Host-only legacy SSEU lookup inventory observed from this context's
    /// matching live Gen12 publication. It never admits execution after stop.
    sseu_media: Option<(GtPlatform, crate::intel_gpu_engine::EngineSet)>,
    engines: Option<Vec<Option<Arc<crate::intel_gpu_user::UserContext>>>>,
    /// i915 GRAPHICS_VER 12 contexts stay proto-contexts until first lookup;
    /// only then is the engine map immutable.
    finalized: bool,
    vm: Arc<Vm>,
    no_error_capture: Arc<crate::intel_gpu_user::CapturePolicy>,
    /// Proto/create-only intent, inherited by every retained engine context.
    low_latency: bool,
    /// LINUX-GAP: stored and reported only. A reset bans every context it
    /// finds (UserContext::check_epoch), bannable or not.
    bannable: bool,
    /// LINUX-GAP: stored and reported only. No context is ever recovered
    /// across a reset, whatever this says.
    recoverable: bool,
    /// Always true: clearing it needs I915_SCHEDULER_CAP_PREEMPTION, which
    /// NARF does not advertise (scheduler_caps).
    persistence: bool,
    /// ctx->sched.priority, I915_CONTEXT_MIN..=MAX_USER_PRIORITY. Every
    /// hardware member, including ones created later, stores
    /// map_i915_prio_to_guc_prio of it for its next GuC registration.
    /// LINUX-GAP: only a submission on the same hardware context raises a
    /// job in flight; __i915_schedule's bumps through object and fence
    /// dependencies on other contexts are not modelled.
    priority: i32,
}

impl Context {
    /// proto_context_create's priority is I915_PRIORITY_NORMAL.
    fn new(vm: Arc<Vm>, finalized: bool) -> Self {
        use crate::intel_gpu_engine::Engine;
        let no_error_capture = Arc::new(crate::intel_gpu_user::CapturePolicy::default());
        let priority = 0;
        Self {
            user: crate::intel_gpu_user::UserContext::for_i915_engine(
                Engine::Rcs0,
                no_error_capture.clone(),
                priority,
            ),
            copy: crate::intel_gpu_user::UserContext::for_i915_engine(
                Engine::Bcs0,
                no_error_capture.clone(),
                priority,
            ),
            media: BTreeMap::new(),
            sseu_media: None,
            engines: None,
            finalized,
            vm,
            no_error_capture,
            low_latency: false,
            bannable: true,
            recoverable: true,
            persistence: true,
            priority,
        }
    }

    fn users(&self) -> Vec<Arc<crate::intel_gpu_user::UserContext>> {
        let mut users = alloc::vec![self.user.clone(), self.copy.clone()];
        users.extend(self.engines.iter().flatten().flatten().cloned());
        users.extend(self.media.values().cloned());
        users
    }

    fn retain_sseu_media(&mut self, info: &DeviceInfo) {
        if self.sseu_media.is_none() && info.platform.is_gen12() {
            // user_status verifies the nonzero epoch and matching platform;
            // this is an already-published engine set, never raw fuse guesses.
            self.sseu_media = info
                .user_status()
                .filter(|status| status.engines.bits() != 0)
                .map(|status| (status.platform, status.engines));
        }
    }

    /// An indexed map uses only RING_MASK; legacy media is selected from the
    /// current published dense class map before a context state is allocated.
    fn select(
        &mut self,
        ring: u32,
        media: Option<crate::intel_gpu_engine::Engine>,
    ) -> Result<Arc<crate::intel_gpu_user::UserContext>, FsError> {
        self.finalized = true;
        match &self.engines {
            Some(map) => map
                .get((ring & 0x3f) as usize)
                .cloned()
                .flatten()
                .ok_or(FsError::InvalidData),
            None => match u64::from(ring & 0x3f) {
                0 | abi::EXEC_RENDER => Ok(self.user.clone()),
                abi::EXEC_BLT => Ok(self.copy.clone()),
                abi::EXEC_BSD | abi::EXEC_VEBOX => {
                    let engine = media.ok_or(FsError::InvalidData)?;
                    if let Some(user) = self.media.get(&engine) {
                        return Ok(user.clone());
                    }
                    let user = crate::intel_gpu_user::UserContext::for_i915_engine(
                        engine,
                        self.no_error_capture.clone(),
                        self.priority,
                    );
                    if self.low_latency {
                        user.configure_low_latency()?;
                    }
                    self.media.insert(engine, user.clone());
                    Ok(user)
                }
                _ => Err(FsError::InvalidData),
            },
        }
    }
}

/// i915_gem_context.c::set_proto_ctx_engines, after the caller has checked
/// that the proto-context has no map. Entries are copied and resolved in
/// order; holes are INVALID/INVALID_NONE; extensions are read last.
fn read_engines(
    info: &DeviceInfo,
    user: &dyn IoctlContext,
    size: u32,
    value: u64,
) -> Result<EngineMap, FsError> {
    if size < 8 || (size - 8) % 4 != 0 || (size - 8) / 4 > 64 {
        return Err(FsError::InvalidData);
    }
    let present = info
        .user_status()
        .map_or_else(Default::default, |status| status.engines);
    let mut map = Vec::new();
    for n in 0..u64::from((size - 8) / 4) {
        let address = value.checked_add(8 + n * 4).ok_or(FsError::BadAddress)?;
        let entry = read(user, address, 4)?;
        let class = u16::from_le_bytes([entry[0], entry[1]]);
        let instance = u16::from_le_bytes([entry[2], entry[3]]);
        if class == abi::ENGINE_INVALID && instance == abi::ENGINE_INVALID {
            map.push(None);
            continue;
        }
        let engine = present
            .from_class_instance(class, instance)
            .ok_or(FsError::NotFound)?;
        map.push(Some(crate::intel_gpu_engine::EngineSet::of(&[engine])));
    }
    let extensions_at = u64_at(&read(user, value, 8)?, 0);
    abi::user_extensions(user, extensions_at, |address, name| match name {
        abi::CONTEXT_ENGINES_EXT_LOAD_BALANCE => {
            // i915_gem_context.c::set_proto_ctx_engines_balance checks the
            // destination slot before reading sibling count, flags or data.
            let at = address.checked_add(32).ok_or(FsError::BadAddress)?;
            let index = read(user, at, 2)?;
            let index = usize::from(u16::from_le_bytes(index[..].try_into().unwrap()));
            let slot = map.get_mut(index).ok_or(FsError::InvalidData)?;
            if slot.is_some() {
                return Err(FsError::AlreadyExists);
            }
            let count = read(user, at.checked_add(2).ok_or(FsError::BadAddress)?, 2)?;
            let count = u16::from_le_bytes(count[..].try_into().unwrap());
            // check_user_mbz(&ext->flags), then check_user_mbz(&ext->mbz64):
            // two get_users, so a nonzero flags word is -EINVAL even when
            // mbz64 is unreadable.
            for (offset, size) in [(4, 4), (8, 8)] {
                let field = read(
                    user,
                    at.checked_add(offset).ok_or(FsError::BadAddress)?,
                    size,
                )?;
                if field.iter().any(|byte| *byte != 0) {
                    return Err(FsError::InvalidData);
                }
            }
            if count == 0 {
                return Ok(());
            }
            let mut siblings = Vec::new();
            for n in 0..u64::from(count) {
                let at = address.checked_add(48 + n * 4).ok_or(FsError::BadAddress)?;
                let entry = read(user, at, 4)?;
                let class = u16::from_le_bytes(entry[..2].try_into().unwrap());
                let logical = u16::from_le_bytes(entry[2..].try_into().unwrap());
                let engine = present
                    .from_class_instance(class, logical)
                    .ok_or(FsError::InvalidData)?;
                // GuC guc_create_virtual refuses duplicate siblings and mixed
                // classes. Refuse before publishing an unusable proto-map.
                // Distinct admitted siblings inherently bound this loop.
                if siblings.contains(&engine)
                    || siblings
                        .first()
                        .is_some_and(|first: &crate::intel_gpu_engine::Engine| {
                            first.xe_class() != engine.xe_class()
                        })
                {
                    return Err(FsError::InvalidData);
                }
                siblings.push(engine);
            }
            *slot = Some(crate::intel_gpu_engine::EngineSet::of(&siblings));
            Ok(())
        }
        // Bonding and multi-LRC parallel submission need their own owners.
        1 | 2 => Err(FsError::NotImplemented),
        _ => Err(FsError::InvalidData),
    })?;
    Ok(map)
}

#[derive(Debug)]
struct Namespaces {
    next_context: u32,
    next_context_nonce: u64,
    /// Reserved names are capacity charged but absent from the visible map.
    pending_contexts: BTreeMap<u32, u64>,
    next_vm: u32,
    contexts: BTreeMap<u32, Context>,
    vms: BTreeMap<u32, Arc<Vm>>,
    bsd_default: Option<crate::intel_gpu_engine::Engine>,
    /// HOLD_PREEMPTION references per gem context: how many open i915 OA
    /// streams pinned this context with HOLD_PREEMPTION set. The
    /// execbuffer path consults this set (see `oa_holds_preemption`); the
    /// count matters because two hold streams may pin one context, and
    /// one stream's close must not drop the other's hold. This is the
    /// NARF analogue of Linux storing the preemption setting in
    /// intel_context: NARF has no per-context OA slot, so the namespace
    /// carries the reference count instead.
    oa_hold_preempt: BTreeMap<u32, u32>,
}

impl Namespaces {
    const fn new() -> Self {
        Self {
            next_context: 1,
            next_context_nonce: 1,
            pending_contexts: BTreeMap::new(),
            next_vm: 1,
            contexts: BTreeMap::new(),
            vms: BTreeMap::new(),
            bsd_default: None,
            oa_hold_preempt: BTreeMap::new(),
        }
    }

    /// Pin a context for a single-context i915 OA stream: the handle must
    /// name a context in this namespace (handle 0 never does — it is not
    /// a userspace-allocated context). When `hold` is set, also record
    /// one HOLD_PREEMPTION reference for the execbuffer path. Returns
    /// false (and records nothing) when the handle is unknown.
    ///
    /// NOTE: the pin does not keep the context alive. Linux refcounts the
    /// context so a destroy only drops the caller's reference; NARF has
    /// no context refcount, so a destroy of a pinned context still
    /// succeeds (the Linux-observable result) and the pin's record simply
    /// stops matching new reports. Context ids are never reused
    /// (`next_context` only increments), so a stale pin cannot alias a
    /// new context. A refcount still belongs with the LRC-image hook
    /// (issue #1821 landed the hook itself; the refcount is the open
    /// remainder).
    fn oa_pin(&mut self, id: u32, hold: bool) -> bool {
        if id == 0 || !self.contexts.contains_key(&id) {
            return false;
        }
        if hold {
            *self.oa_hold_preempt.entry(id).or_insert(0) += 1;
        }
        true
    }

    /// Drop one HOLD_PREEMPTION pin reference; the id leaves the set when
    /// the last referencing stream closes. No-op when the id holds no
    /// reference (a non-hold pin, or an already-released one).
    fn oa_unpin_hold(&mut self, id: u32) {
        if let Some(count) = self.oa_hold_preempt.get_mut(&id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.oa_hold_preempt.remove(&id);
            }
        }
    }

    /// Whether any open HOLD_PREEMPTION OA stream pins this context: the
    /// execbuffer path's half of the `eb_oa_config` rule (the other half
    /// is the ext_perf extension on the request itself).
    fn oa_holds_preemption(&self, id: u32) -> bool {
        self.oa_hold_preempt.contains_key(&id)
    }

    fn reserve_context(&mut self) -> Result<(u32, u64), FsError> {
        // Context0 counts even before its lazy initialization. Every pending
        // copyout consumes exactly one additional slot, excluding overcommit.
        let occupied = self.contexts.len()
            + self.pending_contexts.len()
            + usize::from(!self.contexts.contains_key(&0));
        if occupied >= MAX_CONTEXTS {
            return Err(FsError::OutOfMemory);
        }
        let id = self.next_context;
        let next = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
        let nonce = self.next_context_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(FsError::OutOfMemory)?;
        self.pending_contexts.insert(id, nonce);
        self.next_context = next;
        self.next_context_nonce = next_nonce;
        Ok((id, nonce))
    }

    fn cancel_context(&mut self, id: u32, nonce: u64) {
        if self.pending_contexts.get(&id) != Some(&nonce) {
            return;
        }
        self.pending_contexts.remove(&id);
        // Preserve the ordinary failed-create ID behavior when no later
        // reservation exists. Concurrent successes may leave opaque ID gaps.
        if id.checked_add(1) == Some(self.next_context) {
            self.next_context = id;
        }
    }

    fn initialize(&mut self) {
        self.contexts
            .entry(0)
            .or_insert_with(|| Context::new(Arc::new(Vm { _identity: 0 }), true));
    }

    /// Pinned i915_gem_execbuffer.c::eb_select_legacy_ring: explicit maps
    /// ignore BSD flags; legacy non-BSD rejects them. With one VIDEO engine,
    /// Linux ignores BSD selector bits; with multiple, only DEFAULT/1/2 exist.
    fn select(
        &mut self,
        id: u32,
        ring: u32,
        info: &DeviceInfo,
    ) -> Result<Arc<crate::intel_gpu_user::UserContext>, FsError> {
        self.initialize();
        let context = self.contexts.get_mut(&id).ok_or(FsError::NotFound)?;
        context.finalized = true;
        if context.engines.is_some() {
            return context.select(ring, None);
        }
        let selector = (u64::from(ring) & abi::EXEC_BSD_MASK) >> abi::EXEC_BSD_SHIFT;
        let legacy = u64::from(ring & 0x3f);
        if legacy != abi::EXEC_BSD && selector != 0 {
            return Err(FsError::InvalidData);
        }
        let media = if matches!(legacy, abi::EXEC_BSD | abi::EXEC_VEBOX) {
            if !info.platform.is_gen12() {
                return Err(FsError::InvalidData);
            }
            let present = info.user_status().ok_or(FsError::NoDevice)?.engines;
            context.retain_sseu_media(info);
            let class = if legacy == abi::EXEC_BSD { 2 } else { 3 };
            let count = present.iter().filter(|e| e.xe_class() == class).count();
            if count == 0 {
                return Err(FsError::InvalidData);
            }
            Some(if legacy == abi::EXEC_BSD && count > 1 {
                match selector {
                    0 => {
                        // Linux retains one default VIDEO per open. NARF's
                        // bounded scheduling choice rotates between opens;
                        // neither random balancing nor fairness is UAPI.
                        static NEXT: core::sync::atomic::AtomicU32 =
                            core::sync::atomic::AtomicU32::new(0);
                        let engine = *self.bsd_default.get_or_insert_with(|| {
                            let logical = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
                                as usize
                                % count;
                            present
                                .from_class_instance(2, logical as u16)
                                .expect("published VIDEO")
                        });
                        if !present.contains(engine) {
                            return Err(FsError::NoDevice);
                        }
                        engine
                    }
                    1 | 2 => present
                        .from_class_instance(2, selector as u16 - 1)
                        .ok_or(FsError::InvalidData)?,
                    _ => return Err(FsError::InvalidData),
                }
            } else {
                present
                    .from_class_instance(class, 0)
                    .expect("nonempty class")
            })
        } else {
            None
        };
        context.select(ring, media)
    }

    /// setparam_ioctl's lookup (-ENOENT), which precedes every parameter
    /// check and so every capable() question.
    fn lookup(&mut self, id: u32) -> Result<(), FsError> {
        self.initialize();
        if self.contexts.contains_key(&id) {
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    /// ENGINES may only be set once, on a proto-context.
    fn engines_settable(&mut self, id: u32) -> Result<(), FsError> {
        self.initialize();
        let context = self.contexts.get(&id).ok_or(FsError::NotFound)?;
        if context.finalized || context.engines.is_some() {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }

    /// GEM_CONTEXT_GETPARAM and SETPARAM on a copied
    /// drm_i915_gem_context_param, SSEU excepted (sseu_parameter).
    /// i915_gem_context_getparam_ioctl:2527 and setparam_ioctl:2600 look the
    /// context up first (-ENOENT); SET then applies set_proto_ctx_param:877
    /// to a proto-context and ctx_setparam:2190 to a finalized one.
    fn parameter(
        &mut self,
        bytes: &mut [u8],
        set: bool,
        engines: Option<EngineMap>,
        facts: ParamFacts,
    ) -> Result<(), FsError> {
        let id = u32_at(bytes, 0);
        let size = u32_at(bytes, 4);
        let param = u64_at(bytes, 8);
        let value = u64_at(bytes, 16);
        if (param, set) == (abi::CONTEXT_PARAM_ENGINES, true) {
            self.engines_settable(id)?;
            let map = engines.ok_or(FsError::InvalidData)?;
            let context = self.contexts.get_mut(&id).ok_or(FsError::NotFound)?;
            context.engines = Some(
                map.into_iter()
                    .map(|slot| {
                        slot.map(|placements| {
                            let user = crate::intel_gpu_user::UserContext::for_i915_placements(
                                placements,
                                context.no_error_capture.clone(),
                                context.priority,
                            )?;
                            if context.low_latency {
                                user.configure_low_latency()?;
                            }
                            Ok::<_, FsError>(user)
                        })
                        .transpose()
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
            return Ok(());
        }
        self.initialize();
        let context = self.contexts.get_mut(&id).ok_or(FsError::NotFound)?;
        if !set {
            // i915_gem_context_lookup finalizes a proto-context, even for a
            // parameter (LOW_LATENCY, ENGINES) that GETPARAM then refuses.
            // GETPARAM never reads the input size; it reports size 0.
            context.finalized = true;
            let value = match param {
                abi::CONTEXT_PARAM_GTT_SIZE => 1 << 48,
                abi::CONTEXT_PARAM_NO_ERROR_CAPTURE => {
                    u64::from(context.no_error_capture.protected())
                }
                abi::CONTEXT_PARAM_BANNABLE => u64::from(context.bannable),
                abi::CONTEXT_PARAM_RECOVERABLE => u64::from(context.recoverable),
                // `args->value = ctx->sched.priority`: an int, sign-extended.
                abi::CONTEXT_PARAM_PRIORITY => i64::from(context.priority) as u64,
                abi::CONTEXT_PARAM_VM => {
                    let vm = context.vm.clone();
                    let existing = self
                        .vms
                        .iter()
                        .find(|(_, entry)| Arc::ptr_eq(entry, &vm))
                        .map(|(id, _)| *id);
                    let id = if let Some(id) = existing {
                        id
                    } else {
                        if self.vms.len() >= MAX_VMS {
                            return Err(FsError::OutOfMemory);
                        }
                        let id = self.next_vm;
                        self.next_vm = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
                        self.vms.insert(id, vm);
                        id
                    };
                    u64::from(id)
                }
                abi::CONTEXT_PARAM_PERSISTENCE => u64::from(context.persistence),
                // get_protected: without PXP no context uses protected
                // content.
                abi::CONTEXT_PARAM_PROTECTED_CONTENT => 0,
                // NO_ZEROMAP, BAN_PERIOD, ENGINES, RINGSIZE, CONTEXT_IMAGE,
                // LOW_LATENCY and unknown parameters.
                _ => return Err(FsError::InvalidData),
            };
            put32(bytes, 4, 0);
            put64(bytes, 16, value);
            return Ok(());
        }
        let proto = !context.finalized;
        match param {
            abi::CONTEXT_PARAM_NO_ERROR_CAPTURE => {
                if size != 0 {
                    return Err(FsError::InvalidData);
                }
                // Source live SET accepts any nonzero value, including after
                // finalization/claim. Every retained hardware member sees it.
                context.no_error_capture.set(value);
            }
            abi::CONTEXT_PARAM_BANNABLE => {
                // Both tables: size, then `!capable(CAP_SYS_ADMIN) &&
                // !args->value`; any nonzero value sets it. The
                // uses_protected_content -EPERM for clearing it cannot apply:
                // no context uses protected content without PXP.
                if size != 0 {
                    return Err(FsError::InvalidData);
                }
                if !facts.sys_admin && value == 0 {
                    return Err(FsError::OperationNotPermitted);
                }
                context.bannable = value != 0;
            }
            abi::CONTEXT_PARAM_RECOVERABLE => {
                // Both tables: size, then 0 clears and any other value sets
                // it (its uses_protected_content -EPERM cannot apply).
                if size != 0 {
                    return Err(FsError::InvalidData);
                }
                context.recoverable = value != 0;
            }
            abi::CONTEXT_PARAM_PRIORITY => {
                // set_proto_ctx_param stores pc->sched.priority; ctx_setparam's
                // set_priority stores ctx->sched.priority and also retunes
                // semaphore use, which GuC submission never has. Neither
                // sends GuC anything: each hardware member stores the GuC
                // band for the requests queued from now on, and the next
                // request on a member raises its job in flight (exec_ioctl).
                validate_priority(size, value, facts)?;
                context.priority = value as i64 as i32;
                for user in context.users() {
                    user.set_i915_priority(context.priority);
                }
            }
            abi::CONTEXT_PARAM_PERSISTENCE => {
                if size != 0 {
                    return Err(FsError::InvalidData);
                }
                let persist = value != 0;
                // __context_set_persistence:1560 returns early when a live
                // context is already in the requested state.
                if !proto && context.persistence == persist {
                    return Ok(());
                }
                // Setting it requires i915.enable_hangcheck (-EINVAL without):
                // NARF's job watchdog is always armed. Clearing it requires
                // I915_SCHEDULER_CAP_PREEMPTION, then intel_has_reset_engine;
                // NARF has no preempt-to-idle cancellation and does not
                // advertise the capability, so the first is -ENODEV.
                if !persist && facts.scheduler & SCHEDULER_CAP_PREEMPTION == 0 {
                    return Err(FsError::NoDevice);
                }
                context.persistence = persist;
            }
            // proto_context_set_protected:253 has no size check: 0 clears
            // it; anything else needs intel_pxp_is_enabled, which no NARF
            // i915 device is. ctx_setparam refuses it (-EINVAL).
            abi::CONTEXT_PARAM_PROTECTED_CONTENT if proto => {
                if value != 0 {
                    return Err(FsError::NoDevice);
                }
            }
            // set_proto_ctx_param only; ctx_setparam refuses it (-EINVAL).
            abi::CONTEXT_PARAM_LOW_LATENCY if proto => {
                if !facts.low_latency {
                    return Err(FsError::InvalidData);
                }
                // Pinned set_proto_ctx_param ignores size/value for this
                // one-way enable: even value 0 enables it, with no payload
                // dereference.
                if context.low_latency {
                    return Ok(());
                }
                let users = context.users();
                if users.iter().any(|user| !user.can_rebind()) {
                    return Err(FsError::Busy);
                }
                // No claim-capable UserContext escapes before finalization.
                // Internal SSEU SET clones immediately refuse without a claim.
                // This context is either namespace serialized or an
                // unpublished private proto, so no claim can race the
                // complete preflight and none of these enables can fail
                // midway.
                for user in users {
                    user.configure_low_latency()?;
                }
                context.low_latency = true;
            }
            // set_proto_ctx_vm:366: size, then upper_32_bits and the lookup
            // (-ENOENT). ctx_setparam refuses VM (-EINVAL): a finalized
            // context's VM is immutable.
            abi::CONTEXT_PARAM_VM if proto => {
                if size != 0 {
                    return Err(FsError::InvalidData);
                }
                let vm_id = u32::try_from(value).map_err(|_| FsError::NotFound)?;
                // Defensive only: no claim-capable UserContext of a
                // proto-context exists (select() finalizes before claiming,
                // under this lock), so this preflight never refuses.
                let users = context.users();
                let mut idle = Vec::new();
                for user in &users {
                    idle.push(user.serial.try_lock().ok_or(FsError::Busy)?);
                    if !user.can_rebind() {
                        return Err(FsError::Busy);
                    }
                }
                context.vm = self.vms.get(&vm_id).cloned().ok_or(FsError::NotFound)?;
            }
            // GTT_SIZE, NO_ZEROMAP, BAN_PERIOD, RINGSIZE and unknown
            // parameters in both tables (and VM in ctx_setparam's);
            // CONTEXT_IMAGE needs
            // CONFIG_DRM_I915_REPLAY_GPU_HANGS_API (set_context_image).
            _ => return Err(FsError::InvalidData),
        }
        Ok(())
    }
}

/// A private, non-Copy reservation. Only this exact nonce may publish or
/// roll back its slot; a pending name is never in the claimable context map.
struct PendingContext<'a> {
    namespaces: &'a IrqSafeSpinLock<Namespaces>,
    id: u32,
    nonce: u64,
}

impl PendingContext<'_> {
    fn publish(self, context: Context, default: Context) -> Result<(), FsError> {
        let mut context = Some(context);
        let mut default = Some(default);
        let published = {
            let mut namespaces = self.namespaces.lock();
            if namespaces.pending_contexts.get(&self.id) != Some(&self.nonce)
                || namespaces.contexts.contains_key(&self.id)
            {
                false
            } else {
                // Vacant entries do not replace/drop any other owned graph.
                if let alloc::collections::btree_map::Entry::Vacant(slot) =
                    namespaces.contexts.entry(0)
                {
                    slot.insert(default.take().expect("owned context0"));
                }
                if let alloc::collections::btree_map::Entry::Vacant(slot) =
                    namespaces.contexts.entry(self.id)
                {
                    slot.insert(context.take().expect("owned proto"));
                }
                namespaces.pending_contexts.remove(&self.id);
                true
            }
        };
        // Unused default/proto references are destroyed after the IRQ guard.
        drop(context);
        drop(default);
        if published {
            Ok(())
        } else {
            Err(FsError::NoDevice)
        }
    }
}

impl Drop for PendingContext<'_> {
    fn drop(&mut self) {
        // Metadata only: never remove/drop a published Context or VM graph.
        self.namespaces.lock().cancel_context(self.id, self.nonce);
    }
}

#[derive(Debug)]
pub struct RenderFile {
    pub gem: GemState,
    pub(crate) syncobjs: Arc<IrqSafeSpinLock<crate::drm::syncobj::SyncObjTable>>,
    /// Shared (not merely borrowed) so the i915 OA pin's release callback
    /// — built during PERF_OPEN dispatch — can outlive the dispatch and
    /// unpin the context when the stream closes. Every other use goes
    /// through `Arc`'s deref to the lock and is unchanged.
    namespaces: Arc<IrqSafeSpinLock<Namespaces>>,
    xe: crate::intel_gpu_xe::XeFile,
}

impl Default for RenderFile {
    fn default() -> Self {
        Self::new()
    }
}

impl RenderFile {
    pub fn new() -> Self {
        Self {
            gem: GemState::new(),
            xe: crate::intel_gpu_xe::XeFile::new(),
            syncobjs: Arc::new(IrqSafeSpinLock::new(
                crate::drm::syncobj::SyncObjTable::new(),
            )),
            namespaces: Arc::new(IrqSafeSpinLock::new(Namespaces::new())),
        }
    }

    pub(crate) fn dispatch_card(
        &self,
        card: u32,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Option<Result<u64, FsError>> {
        if crate::drm_registry::driver_name(card) != Some("intel-gpu") {
            return None;
        }
        if let Some(result) = crate::drm_ioctl_bridge::intel_get_modifiers_cap(card, cmd, arg, user)
        {
            return Some(result);
        }
        let info = match DeviceInfo::for_card(card) {
            Some(info) => info,
            None => return Some(Err(FsError::NoDevice)),
        };
        self.dispatch(&info, cmd, arg, user)
    }

    pub(crate) async fn dispatch_card_user(
        &self,
        card: u32,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Option<Result<u64, FsError>> {
        if crate::drm_registry::driver_name(card) != Some("intel-gpu") {
            return None;
        }
        if let Some(result) = crate::drm_ioctl_bridge::intel_get_modifiers_cap(card, cmd, arg, user)
        {
            return Some(result);
        }
        let Some(info) = DeviceInfo::for_card(card) else {
            return Some(Err(FsError::NoDevice));
        };
        self.dispatch_user(&info, cmd, arg, user).await
    }

    /// User waits retain one future and its original relative deadline while
    /// the stackful syscall parks. No reservation/handle lock spans a sleep.
    pub async fn dispatch_user(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Option<Result<u64, FsError>> {
        if crate::drm_uapi::ioc_type(cmd) == b'd' as u32
            && crate::drm::syncobj_ioctl::is_syncobj_ioctl(crate::drm_uapi::ioc_nr(cmd))
        {
            return crate::drm::syncobj_ioctl::dispatch(
                crate::drm_uapi::ioc_nr(cmd),
                arg as usize,
                &self.syncobjs,
                true,
                user,
            )
            .await;
        }
        if info.native_xe()
            && (crate::intel_gpu_xe_uapi::driver_ioctl(cmd) || !abi::compatibility_ioctl(cmd))
        {
            if matches!(
                cmd,
                crate::intel_gpu_xe_uapi::DEVICE_QUERY
                    | crate::intel_gpu_xe_uapi::GEM_CREATE
                    | crate::intel_gpu_xe_uapi::VM_BIND
                    | crate::intel_gpu_xe_uapi::EXEC
                    | crate::intel_gpu_xe_uapi::WAIT_USER_FENCE
                    | crate::intel_gpu_xe_uapi::OBSERVATION
            ) {
                return self
                    .xe
                    .dispatch_user(info, cmd, arg, user, &self.gem, &self.syncobjs)
                    .await;
            }
            return self.dispatch(info, cmd, arg, user);
        }
        if matches!(cmd, abi::GEM_EXECBUFFER2 | abi::GEM_EXECBUFFER2_WR) {
            return Some(self.exec_ioctl(info, cmd, arg, user).await);
        }
        if cmd == abi::GEM_THROTTLE {
            let fences: Vec<_> = {
                let namespaces = self.namespaces.lock();
                namespaces
                    .contexts
                    .values()
                    .flat_map(Context::users)
                    .filter_map(|user| user.last())
                    .collect()
            };
            for fence in fences {
                if fence.wait().await.is_err() {
                    return Some(Err(crate::intel_gpu_user::io_error()));
                }
            }
            return Some(Ok(0));
        }
        if cmd == abi::GEM_WAIT {
            return Some(self.wait_ioctl(arg, user).await.map(|()| 0));
        }
        if matches!(cmd, abi::GEM_PREAD | abi::GEM_PWRITE) {
            return Some(self.copy_ioctl(info, cmd, arg, user).await.map(|()| 0));
        }
        if matches!(cmd, abi::GEM_SET_DOMAIN | abi::GEM_SW_FINISH) {
            return Some(self.domain_ioctl(cmd, arg, user).await.map(|()| 0));
        }
        if cmd == abi::PERF_OPEN {
            let backend = info.backend.clone();
            // The pin lookup closes over this file's namespace: the
            // context must exist here (contexts are per file in Linux,
            // and so is the pin), and the release callback must outlive
            // this dispatch, hence the shared namespaces handle.
            let namespaces = self.namespaces.clone();
            let pin = |id: u32, hold: bool| -> Option<crate::intel_gpu_oa::PinToken> {
                let unpin_ns = namespaces.clone();
                if !namespaces.lock().oa_pin(id, hold) {
                    return None;
                }
                // The hardware context id is the gem handle: NARF
                // programs no distinct LRC tag per context yet (see
                // intel_gpu_oa::PinToken). The pinned context's GuC
                // user context rides the token so the OA layer can
                // program its saved LRC image at stream enable
                // (issue #1821).
                let user = namespaces
                    .lock()
                    .contexts
                    .get(&id)
                    .map(|ctx| ctx.user.clone());
                Some(crate::intel_gpu_oa::PinToken::new(
                    id,
                    id,
                    Arc::new(move |id| {
                        unpin_ns.lock().oa_unpin_hold(id);
                    }),
                    user,
                ))
            };
            return Some(crate::intel_gpu_oa::errno(
                crate::intel_gpu_oa::i915_open(
                    backend,
                    arg,
                    user,
                    &pin,
                    crate::intel_gpu_oa::Gate::PHYSICAL,
                )
                .await,
            ));
        }
        if cmd == abi::PERF_ADD_CONFIG {
            let backend = info.backend.as_deref();
            return Some(crate::intel_gpu_oa::errno(
                crate::intel_gpu_oa::i915_add_config(
                    backend,
                    arg,
                    user,
                    crate::intel_gpu_oa::Gate::PHYSICAL,
                ),
            ));
        }
        if cmd == abi::PERF_REMOVE_CONFIG {
            let backend = info.backend.as_deref();
            return Some(crate::intel_gpu_oa::errno(
                crate::intel_gpu_oa::remove_config(
                    backend,
                    arg,
                    user,
                    crate::intel_gpu_oa::Gate::PHYSICAL,
                ),
            ));
        }
        self.dispatch(info, cmd, arg, user)
    }

    async fn exec_ioctl(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Result<u64, FsError> {
        use crate::intel_gpu_user::{OutputError, UserOutput};
        let wire = crate::intel_gpu_exec::ExecWire::read(user, arg, true)?;
        // Linux parses the execbuffer extensions
        // (parse_execbuf2_extensions) before the fence array and the
        // object lookups.
        let perf_ext = wire.perf_extension(user)?;
        let sync = crate::intel_gpu_exec_sync::SyncRequest::read(
            user,
            wire.raw_request(),
            &self.syncobjs,
        )?;
        // Context and engine selection precede object handle resolution, matching Linux:
        let context = {
            let mut namespaces = self.namespaces.lock();
            namespaces.initialize();
            namespaces.select(wire.context_id(), wire.ring(), info)?
        };
        let dr4_fixed_up = wire.dr4_fixed_up();
        let mut request = wire.resolve(&self.gem)?;
        // Linux eb_oa_config: the request must not be preempted when the
        // execbuffer carries the ext_perf extension on a context pinned by
        // a HOLD_PREEMPTION OA stream. Either half alone does not hold
        // preemption: an ext_perf on an unpinned context, or a pinned hold
        // context submitting without the extension, both run normally.
        if perf_ext.is_some()
            && self
                .namespaces
                .lock()
                .oa_holds_preemption(request.context_id)
        {
            request.no_preempt = true;
        }
        request.validate_for_gt(info.platform)?;
        if request.has_async() && !info.object_async_ready() {
            return Err(FsError::NoDevice);
        }
        if dr4_fixed_up && cmd == abi::GEM_EXECBUFFER2_WR {
            // Write back fixed-up DR4 (0) on writeable execbuffer2 ioctl.
            let _ = user.write(arg + 24, &0u32.to_ne_bytes());
        }
        let output = sync.output;
        let input_word = sync.input_word;
        let sync = sync.resolve();
        let backend = info.backend.as_ref().ok_or(FsError::NotImplemented)?;
        // i915_request_add queues this request at the context's current
        // priority behind every earlier job on its timeline, and
        // __i915_schedule bumps them before anything waits; NARF's request
        // waits below.
        let mut queued = context.queue_request();
        let _order = context.serial.lock().await;
        sync.wait().await;
        if let Some(previous) = context.last() {
            previous
                .wait()
                .await
                .map_err(|_| crate::intel_gpu_user::io_error())?;
        }
        loop {
            let status = backend
                .status()
                .filter(|status| {
                    status.platform == info.platform
                        && (!request.has_async()
                            || (status.epoch != 0 && status.engines.bits() != 0))
                })
                .ok_or(FsError::NoDevice)?;
            context.check_epoch(status.epoch)?;
            for entry in &request.objects {
                if entry.writable && entry.object.is_read_only() {
                    return Err(FsError::InvalidData);
                }
                if !entry.asynchronous {
                    entry.object.wait_idle(entry.writable, None).await?;
                }
            }
            let batch = request.prepare_user(status.platform)?;
            queued.stage();
            let result = if output {
                let address = arg.checked_add(56).ok_or(FsError::BadAddress)?;
                backend
                    .submit_with_output(
                        context.clone(),
                        batch,
                        UserOutput {
                            user,
                            address,
                            input: input_word,
                        },
                    )
                    .await
            } else {
                backend
                    .submit(context.clone(), batch)
                    .await
                    .map_err(OutputError::Io)
            };
            match result {
                Ok(fence) => {
                    sync.publish(fence);
                    return Ok(0);
                }
                Err(OutputError::Io(FsError::WouldBlock)) => {
                    narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant())
                        .await;
                }
                Err(OutputError::Io(error)) => return Err(error),
                Err(OutputError::Install(narf_filesystem::InstallFdError::NoDescriptor)) => {
                    return Ok((-24i64) as u64);
                }
                Err(OutputError::Install(narf_filesystem::InstallFdError::Report(error))) => {
                    return Err(error);
                }
            }
        }
    }

    async fn domain_ioctl(
        &self,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        let request = read(user, arg, if cmd == abi::GEM_SET_DOMAIN { 12 } else { 4 })?;
        let object = self.gem.object(u32_at(&request, 0))?;
        let write = cpu_domain_write(cmd, &request)?;
        if write && object.is_read_only() {
            return Err(FsError::InvalidData);
        }
        if !object.idle(write) && user.restart_after(1_000_000) {
            return Err(FsError::WouldBlock);
        }
        object.wait_idle(write, None).await
    }

    async fn wait_ioctl(&self, arg: u64, user: &dyn IoctlContext) -> Result<(), FsError> {
        let mut request = read(user, arg, 16)?;
        if u32_at(&request, 4) != 0 {
            return Err(FsError::InvalidData);
        }
        let object = self.gem.object(u32_at(&request, 0))?;
        let timeout = u64_at(&request, 8) as i64;
        if timeout < 0 && !object.idle(true) && user.restart_after(1_000_000) {
            return Err(FsError::WouldBlock);
        }
        let deadline =
            (timeout >= 0).then(|| narf_time::monotonic_ns().saturating_add(timeout as u64));
        let result = object.wait_idle(true, deadline).await;
        if let Some(deadline) = deadline {
            put64(
                &mut request,
                8,
                deadline
                    .saturating_sub(narf_time::monotonic_ns())
                    .min(timeout as u64),
            );
            // Copy only the output field; a copy fault never changes residency.
            user.write(
                arg.checked_add(8).ok_or(FsError::BadAddress)?,
                &request[8..16],
            )?;
        }
        result
    }

    async fn copy_ioctl(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        let request = read(user, arg, 32)?;
        if u32_at(&request, 4) != 0 {
            return Err(FsError::InvalidData);
        }
        let object = self.gem.object(u32_at(&request, 0))?;
        let offset = u64_at(&request, 8);
        let size = usize::try_from(u64_at(&request, 16)).map_err(|_| FsError::InvalidData)?;
        object.range(offset, size)?;
        if size == 0 {
            return Ok(());
        }
        // i915_gem_pread_ioctl's runtime-PM wakeref: a VRAM copy goes through
        // the LMEM BAR, so resume a runtime-suspended function first and keep
        // it in D0 for the whole copy.
        let _wakeref = match (&info.backend, object.is_vram()) {
            (Some(backend), true) => Some(backend.cpu_vram_wakeref().await?),
            _ => None,
        };
        let pointer = u64_at(&request, 24);
        pointer
            .checked_add(size as u64)
            .ok_or(FsError::BadAddress)?;
        let write = cmd == abi::GEM_PWRITE;
        if write && object.is_read_only() {
            return Err(FsError::PermissionDenied);
        }
        let mut done = 0;
        while done < size {
            let count = (size - done).min(16 * 1024);
            let mut data = if write {
                read(user, pointer + done as u64, count)?
            } else {
                vec![0; count]
            };
            loop {
                object.wait_idle(write, None).await?;
                let result = if write {
                    object.write(offset + done as u64, &data)
                } else {
                    object.read(offset + done as u64, &mut data)
                };
                // A new job may win the reservation gate after the wait. Retry
                // this chunk without replaying an already copied prefix.
                if result != Err(FsError::WouldBlock) {
                    result?;
                    break;
                }
            }
            if !write {
                user.write(pointer + done as u64, &data)?;
            }
            done += count;
        }
        Ok(())
    }

    /// `None` means a generic DRM command, not an error from an Intel ioctl.
    /// Once recognized, a malformed Intel command cannot fall through to KMS.
    pub fn dispatch(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Option<Result<u64, FsError>> {
        if cmd == crate::drm_uapi::DRM_IOCTL_VERSION
            && (info.native_xe() || info.submission_ready())
        {
            return Some(
                version(arg, user, if info.native_xe() { b"xe" } else { b"i915" }).map(|()| 0),
            );
        }
        if cmd == crate::drm_uapi::DRM_IOCTL_GET_CAP {
            let result = (|| {
                let mut request = read(user, arg, 16)?;
                if !matches!(u64_at(&request, 0), 0x13 | 0x14) {
                    return Ok(None);
                }
                put64(&mut request, 8, u64::from(info.submission_ready()));
                user.write(arg, &request)?;
                Ok(Some(0))
            })();
            match result {
                Ok(None) => return None,
                Ok(Some(value)) => return Some(Ok(value)),
                Err(error) => return Some(Err(error)),
            }
        }
        if info.native_xe()
            && (crate::intel_gpu_xe_uapi::driver_ioctl(cmd) || !abi::compatibility_ioctl(cmd))
        {
            return self.xe.dispatch(info, cmd, arg, user, &self.gem);
        }
        let nr = crate::drm_uapi::ioc_nr(cmd);
        if crate::drm_uapi::ioc_type(cmd) != b'd' as u32 {
            return None;
        }
        if nr != 9 && !(0x40..0x80).contains(&nr) {
            return None;
        }
        if cmd == abi::PERF_ADD_CONFIG {
            let backend = info.backend.as_deref();
            return Some(crate::intel_gpu_oa::errno(
                crate::intel_gpu_oa::i915_add_config(
                    backend,
                    arg,
                    user,
                    crate::intel_gpu_oa::Gate::PHYSICAL,
                ),
            ));
        }
        if cmd == abi::PERF_REMOVE_CONFIG {
            let backend = info.backend.as_deref();
            return Some(crate::intel_gpu_oa::errno(
                crate::intel_gpu_oa::remove_config(
                    backend,
                    arg,
                    user,
                    crate::intel_gpu_oa::Gate::PHYSICAL,
                ),
            ));
        }
        Some(self.ioctl(info, cmd, arg, user).map(|()| 0))
    }

    /// Read the immutable default SSEU image. On these >=Gen12 profiles Linux
    /// refuses SSEU reconfiguration (only Gen11 supports set_proto_ctx_sseu).
    /// Its old context ABI deliberately contains only an eight-bit DSS view;
    /// full-width geometry/compute masks remain in QUERY_TOPOLOGY.
    fn sseu_parameter(
        &self,
        info: &DeviceInfo,
        request: &mut [u8],
        set: bool,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        let context = {
            let mut namespaces = self.namespaces.lock();
            namespaces.initialize();
            let context = namespaces
                .contexts
                .get_mut(&u32_at(request, 0))
                .ok_or(FsError::NotFound)?;
            if !set {
                context.finalized = true;
                context.retain_sseu_media(info);
            }
            context.clone()
        };
        let size = u32_at(request, 4);
        if set {
            return Err(sseu_set_refusal(size));
        }
        if size == 0 {
            put32(request, 4, 32);
            return Ok(());
        }
        if size < 32 {
            return Err(FsError::InvalidData);
        }
        let mut wire = read(user, u64_at(request, 16), 32)?;
        let flags = u32_at(&wire, 4);
        if flags & !1 != 0 || u32_at(&wire, 28) != 0 {
            return Err(FsError::InvalidData);
        }
        let class = u16::from_le_bytes([wire[0], wire[1]]);
        let instance = u16::from_le_bytes([wire[2], wire[3]]);
        match context.engines.as_ref() {
            Some(map) if flags == 1 => {
                // lookup_user_engine ignores engine_class for indexed maps.
                map.get(instance as usize)
                    .and_then(Option::as_ref)
                    .ok_or(FsError::InvalidData)?;
            }
            None if flags == 0 && matches!((class, instance), (0 | 1, 0)) => {}
            None if flags == 0 && matches!(class, 2 | 3) && info.platform.is_gen12() => {
                // Linux lookup_user_engine uses the published class/instance
                // map; every engine inherits whole-device default SSEU. Keep
                // this immutable host query usable after stop only if this
                // context actually observed a qualified publication earlier.
                let (platform, present) = context.sseu_media.ok_or(FsError::NoDevice)?;
                if platform != info.platform {
                    return Err(FsError::NoDevice);
                }
                present
                    .from_class_instance(class, instance)
                    .ok_or(FsError::InvalidData)?;
            }
            _ => return Err(FsError::InvalidData),
        }
        let topology = observed_topology(info)?;
        if info.platform.is_ptl() {
            return Err(FsError::NoDevice);
        }
        let eus = match topology.eu_type() {
            crate::intel_gpu_topology::EuType::Simd8 => 16u16,
            crate::intel_gpu_topology::EuType::Simd16 => 8,
        };
        // intel_sseu_from_device_info: default is whole-device; min/max are
        // the architecture maximum, not an invented per-context fuse setting.
        put64(&mut wire, 8, 1);
        put64(
            &mut wire,
            16,
            ((topology.geometry_dss() | topology.compute_dss()) & 0xff) as u64,
        );
        wire[24..26].copy_from_slice(&eus.to_le_bytes());
        wire[26..28].copy_from_slice(&eus.to_le_bytes());
        user.write(u64_at(request, 16), &wire)?;
        put32(request, 4, 32);
        Ok(())
    }

    fn ioctl(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        match cmd {
            abi::GETPARAM => {
                let request = read(user, arg, 16)?;
                let value = getparam(info, u32_at(&request, 0))?;
                user.write(u64_at(&request, 8), &value.to_le_bytes())
            }
            abi::GEM_CREATE | abi::GEM_CREATE_EXT => {
                let mut request = read(user, arg, if cmd == abi::GEM_CREATE { 16 } else { 24 })?;
                let mut pat = None;
                if cmd == abi::GEM_CREATE_EXT {
                    // i915_gem_create_ext_ioctl: unknown flags, then the
                    // chain, then I915_GEM_CREATE_EXT_FLAG_NEEDS_CPU_ACCESS,
                    // which `n_placements == 1` refuses. SYSTEM is the only
                    // region NARF reports, so every request has one.
                    let flags = u32_at(&request, 12);
                    if flags & !GEM_CREATE_EXT_NEEDS_CPU_ACCESS != 0 {
                        return Err(FsError::InvalidData);
                    }
                    pat = create_extensions(info, user, u64_at(&request, 16))?;
                    if flags & GEM_CREATE_EXT_NEEDS_CPU_ACCESS != 0 {
                        return Err(FsError::InvalidData);
                    }
                }
                self.gem.create_with_pat(
                    u64_at(&request, 0),
                    None,
                    crate::intel_gpu_gem::Placement::System,
                    pat,
                    |handle, size| {
                        put64(&mut request, 0, size);
                        put32(&mut request, 8, handle);
                        user.write(arg, &request)
                    },
                )?;
                Ok(())
            }
            abi::GEM_USERPTR => {
                let mut request = read(user, arg, 24)?;
                let user_ptr = u64_at(&request, 0);
                let user_size = u64_at(&request, 8);
                let flags = u32_at(&request, 16);
                let handle = self.gem.userptr(user_ptr, user_size, flags, user)?;
                put32(&mut request, 20, handle);
                user.write(arg, &request)
            }
            abi::GEM_CLOSE => {
                let request = read(user, arg, 8)?;
                if u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                self.gem.close(u32_at(&request, 0))
            }
            abi::GEM_PREAD | abi::GEM_PWRITE => {
                let request = read(user, arg, 32)?;
                if u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                let object = self.gem.object(u32_at(&request, 0))?;
                let offset = u64_at(&request, 8);
                let size =
                    usize::try_from(u64_at(&request, 16)).map_err(|_| FsError::InvalidData)?;
                object.range(offset, size)?;
                if size == 0 {
                    return Ok(());
                }
                let pointer = u64_at(&request, 24);
                pointer
                    .checked_add(size as u64)
                    .ok_or(FsError::BadAddress)?;
                let mut done = 0;
                // Bound temporary copies while accepting uploads larger than
                // one copy buffer. A later EFAULT may leave a written prefix,
                // as in the Linux pread/pwrite interface.
                while done < size {
                    let count = (size - done).min(16 * 1024);
                    if cmd == abi::GEM_PWRITE {
                        let data = read(user, pointer + done as u64, count)?;
                        object.write(offset + done as u64, &data)?;
                    } else {
                        let mut data = vec![0; count];
                        object.read(offset + done as u64, &mut data)?;
                        user.write(pointer + done as u64, &data)?;
                    }
                    done += count;
                }
                Ok(())
            }
            abi::GEM_MMAP_GTT | abi::GEM_MMAP_OFFSET => {
                let mut request = read(user, arg, if cmd == abi::GEM_MMAP_GTT { 16 } else { 32 })?;
                if cmd == abi::GEM_MMAP_OFFSET {
                    // i915_gem_mmap_offset_ioctl never checks pad or offset
                    // ("if (args->pad) return -EINVAL; is verbotten!") and
                    // walks extensions against an empty table: a link is
                    // refused (-EINVAL) after its own copies and checks.
                    abi::user_extensions(user, u64_at(&request, 24), |_, _| {
                        Err(FsError::InvalidData)
                    })?;
                    // Compatibility supports only WB system mappings; native
                    // Xe handles retain their own cache/memory placement.
                    if u64_at(&request, 16) != 2 {
                        return Err(FsError::InvalidData);
                    }
                } else {
                    return Err(FsError::NotImplemented);
                }
                let object = self.gem.object(u32_at(&request, 0))?;
                if object.is_wc() || object.is_vram() {
                    return Err(FsError::InvalidData);
                }
                let offset = self.gem.mmap_offset(u32_at(&request, 0))?;
                put64(&mut request, 8, offset);
                user.write(arg, &request)
            }
            abi::GEM_BUSY | abi::GEM_WAIT | abi::GEM_SET_DOMAIN | abi::GEM_SW_FINISH => {
                let size = match cmd {
                    abi::GEM_BUSY => 8,
                    abi::GEM_WAIT => 16,
                    abi::GEM_SET_DOMAIN => 12,
                    _ => 4,
                };
                let mut request = read(user, arg, size)?;
                let object = self.gem.object(u32_at(&request, 0))?;
                if cmd == abi::GEM_WAIT && u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                let write = cpu_domain_write(cmd, &request)?;
                if cmd == abi::GEM_BUSY {
                    put32(&mut request, 4, object.busy());
                    return user.write(arg, &request);
                }
                if object.idle(write) {
                    Ok(())
                } else if cmd == abi::GEM_WAIT && u64_at(&request, 8) == 0 {
                    Err(FsError::TimedOut)
                } else {
                    Err(FsError::WouldBlock)
                }
            }
            abi::GEM_GET_TILING
            | abi::GEM_SET_TILING
            | abi::GEM_GET_CACHING
            | abi::GEM_SET_CACHING => {
                let size = if matches!(cmd, abi::GEM_GET_TILING | abi::GEM_SET_TILING) {
                    16
                } else {
                    8
                };
                let mut request = read(user, arg, size)?;
                let object = self.gem.object(u32_at(&request, 0))?;
                if matches!(cmd, abi::GEM_GET_CACHING | abi::GEM_SET_CACHING)
                    && (object.is_wc() || object.is_vram())
                {
                    // This WB-only compatibility policy cannot retype or
                    // describe a native object's explicit cache placement.
                    return Err(FsError::Unsupported);
                }
                match cmd {
                    abi::GEM_SET_TILING if u32_at(&request, 4) != 0 || u32_at(&request, 8) != 0 => {
                        return Err(FsError::InvalidData);
                    }
                    abi::GEM_SET_CACHING if u32_at(&request, 4) != 1 => {
                        return Err(FsError::InvalidData);
                    }
                    abi::GEM_GET_CACHING => put32(&mut request, 4, 1),
                    abi::GEM_GET_TILING | abi::GEM_SET_TILING => request[4..].fill(0),
                    _ => {}
                }
                if cmd == abi::GEM_SET_CACHING {
                    // This command is _IOW: a readable request does not need
                    // to be writable, unlike the GET/TILING reply structs.
                    return Ok(());
                }
                user.write(arg, &request)
            }
            abi::GEM_MADVISE => {
                let mut request = read(user, arg, 12)?;
                self.gem.object(u32_at(&request, 0))?;
                if u32_at(&request, 4) > 1 {
                    return Err(FsError::InvalidData);
                }
                // Retaining DONTNEED storage is allowed; no fabricated purge.
                put32(&mut request, 8, 1);
                user.write(arg, &request)
            }
            abi::GEM_GET_APERTURE => {
                // PPGTT VA width is not the physical GGTT aperture size.
                Err(FsError::NotImplemented)
            }
            abi::GEM_CONTEXT_CREATE | abi::GEM_CONTEXT_CREATE_EXT => {
                self.create_context(info, cmd, arg, user)
            }
            abi::GEM_CONTEXT_DESTROY => {
                let request = read(user, arg, 8)?;
                let id = u32_at(&request, 0);
                if id == 0 || u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                self.namespaces
                    .lock()
                    .contexts
                    .remove(&id)
                    .ok_or(FsError::NotFound)?;
                Ok(())
            }
            abi::GEM_CONTEXT_GETPARAM | abi::GEM_CONTEXT_SETPARAM => {
                let mut request = read(user, arg, 24)?;
                let set = cmd == abi::GEM_CONTEXT_SETPARAM;
                if u64_at(&request, 8) == 7 {
                    self.sseu_parameter(info, &mut request, set, user)?;
                    return user.write(arg, &request);
                }
                let engines = if set && u64_at(&request, 8) == abi::CONTEXT_PARAM_ENGINES {
                    // Check first, then copy without the namespace spinlock.
                    self.namespaces
                        .lock()
                        .engines_settable(u32_at(&request, 0))?;
                    Some(read_engines(
                        info,
                        user,
                        u32_at(&request, 4),
                        u64_at(&request, 16),
                    )?)
                } else {
                    None
                };
                // GRAPHICS_VER >12 finalizes at create in pinned i915. DG2
                // 12.55 and MTL/ARL 12.70/12.74 still permit late proto SET.
                // Keep backend and credential callbacks outside the namespace
                // IRQ lock.
                let low_latency_admitted = matches!(
                    info.platform,
                    GtPlatform::Gen12(_)
                        | GtPlatform::Alchemist
                        | GtPlatform::Integrated(Generation::MeteorLake)
                ) && crate::intel_gpu_xe::low_latency_supported(info);
                if set {
                    // A missing context is -ENOENT before validate_priority
                    // or BANNABLE asks capable(); parameter() looks it up
                    // again under the lock.
                    self.namespaces.lock().lookup(u32_at(&request, 0))?;
                }
                let facts = ParamFacts::sample(info, &request, set, low_latency_admitted);
                self.namespaces
                    .lock()
                    .parameter(&mut request, set, engines, facts)?;
                user.write(arg, &request)
            }
            abi::GEM_VM_CREATE | abi::GEM_VM_DESTROY => {
                let mut request = read(user, arg, 16)?;
                if u64_at(&request, 0) != 0 || u32_at(&request, 8) != 0 {
                    return Err(FsError::InvalidData);
                }
                let mut namespaces = self.namespaces.lock();
                if cmd == abi::GEM_VM_DESTROY {
                    namespaces
                        .vms
                        .remove(&u32_at(&request, 12))
                        .ok_or(FsError::NotFound)?;
                } else {
                    if namespaces.vms.len() >= MAX_VMS {
                        return Err(FsError::OutOfMemory);
                    }
                    let id = namespaces.next_vm;
                    let next = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
                    put32(&mut request, 12, id);
                    user.write(arg, &request)?;
                    namespaces.vms.insert(id, Arc::new(Vm { _identity: id }));
                    namespaces.next_vm = next;
                }
                Ok(())
            }
            abi::GET_RESET_STATS => {
                let mut request = read(user, arg, 24)?;
                if u32_at(&request, 4) != 0 || u32_at(&request, 20) != 0 {
                    return Err(FsError::InvalidData);
                }
                let mut namespaces = self.namespaces.lock();
                namespaces.initialize();
                let context = namespaces
                    .contexts
                    .get_mut(&u32_at(&request, 0))
                    .ok_or(FsError::NotFound)?;
                context.finalized = true;
                let (active, pending) = context.users().iter().fold((0u32, 0u32), |sum, user| {
                    let (active, pending) = user.reset_stats();
                    (sum.0.saturating_add(active), sum.1.saturating_add(pending))
                });
                // Linux restricts the device-wide count to administrative
                // callers. No such authority is granted by this render fd.
                put32(&mut request, 8, 0);
                put32(&mut request, 12, active);
                put32(&mut request, 16, pending);
                user.write(arg, &request)
            }
            abi::QUERY => query(info, arg, user),
            abi::GEM_THROTTLE => Ok(()),
            abi::GEM_EXECBUFFER2 | abi::GEM_EXECBUFFER2_WR => {
                let request = crate::intel_gpu_exec::ExecRequest::read(user, arg, &self.gem)?;
                let mut namespaces = self.namespaces.lock();
                namespaces.initialize();
                if !namespaces.contexts.contains_key(&request.context_id) {
                    return Err(FsError::NotFound);
                }
                if info.submission_ready() {
                    Err(FsError::WouldBlock)
                } else {
                    Err(FsError::NotImplemented)
                }
            }
            _ => Err(FsError::InvalidData),
        }
    }

    fn create_context(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        let mut request = read(
            user,
            arg,
            if cmd == abi::GEM_CONTEXT_CREATE {
                8
            } else {
                16
            },
        )?;
        let flags = u32_at(&request, 4);
        if (cmd == abi::GEM_CONTEXT_CREATE && flags != 0) || flags & !3 != 0 {
            return Err(FsError::InvalidData);
        }
        // CREATE_EXT applies proto parameters before source finalization on
        // every admitted generation. Sample cached admission before locking.
        let low_latency_admitted = crate::intel_gpu_xe::low_latency_supported(info);
        // i915_gem_context_create_ioctl makes the proto-context before the
        // chain and create_setparam applies each SETPARAM link through
        // set_proto_ctx_param as i915_user_extensions reaches it, so a link's
        // error ends the walk before any later link is read. The proto is an
        // unshared host-only container under a private name, never the
        // visible namespace: even reentrant copyout cannot find or
        // finalize/claim either of its context graphs. An error discards it,
        // as err_pc's proto_context_close does, before any name is reserved;
        // its contexts, maps and Arc drops all happen outside the guard.
        let mut proto = Namespaces::new();
        proto.initialize();
        proto.contexts.insert(
            PROTO_NAME,
            Context::new(
                Arc::new(Vm {
                    _identity: PROTO_NAME,
                }),
                false,
            ),
        );
        if cmd == abi::GEM_CONTEXT_CREATE_EXT && flags & 1 != 0 {
            abi::user_extensions(user, u64_at(&request, 8), |address, name| {
                // create_extensions[]: SETPARAM; CLONE is invalid_ext.
                if name != 0 {
                    return Err(FsError::InvalidData);
                }
                let ext = read(user, address, 56)?;
                let mut param = ext[32..].to_vec();
                if u32_at(&param, 0) != 0 {
                    return Err(FsError::InvalidData);
                }
                self.proto_parameter(info, user, &mut proto, &mut param, low_latency_admitted)
            })?;
        }
        let context = proto
            .contexts
            .remove(&PROTO_NAME)
            .expect("owned private proto");
        let default = proto.contexts.remove(&0).expect("private context0");
        drop(proto);
        // Linux allocates the context ID only after the chain applied.
        let reserved = self.namespaces.lock().reserve_context();
        let (id, nonce) = reserved?;
        let pending = PendingContext {
            namespaces: &self.namespaces,
            id,
            nonce,
        };
        put32(&mut request, 0, id);
        user.write(arg, &request)?;
        pending.publish(context, default)
    }

    /// One CREATE_EXT SETPARAM link, i915_gem_context.c::set_proto_ctx_param
    /// on the private proto. Only lookups that Linux makes at the link
    /// itself touch the visible namespace.
    fn proto_parameter(
        &self,
        info: &DeviceInfo,
        user: &dyn IoctlContext,
        proto: &mut Namespaces,
        param: &mut [u8],
        low_latency_admitted: bool,
    ) -> Result<(), FsError> {
        put32(param, 0, PROTO_NAME);
        let size = u32_at(param, 4);
        let value = u64_at(param, 16);
        let engines = match u64_at(param, 8) {
            // set_proto_ctx_sseu, as GEM_CONTEXT_SETPARAM's.
            7 => return Err(sseu_set_refusal(size)),
            abi::CONTEXT_PARAM_ENGINES => {
                // set_proto_ctx_engines: "Cannot set engines twice" precedes
                // the size check and every copy.
                proto.engines_settable(PROTO_NAME)?;
                Some(read_engines(info, user, size, value)?)
            }
            9 => {
                // set_proto_ctx_vm takes its i915_gem_vm_lookup reference at
                // this link. The clone is side-effect free, so parameter()
                // still checks size first; a replaced or unused reference is
                // dropped after the guard.
                if let Ok(vm_id) = u32::try_from(value) {
                    let vm = self.namespaces.lock().vms.get(&vm_id).cloned();
                    if let Some(vm) = vm {
                        drop(proto.vms.insert(vm_id, vm));
                    }
                }
                None
            }
            _ => None,
        };
        let facts = ParamFacts::sample(info, param, true, low_latency_admitted);
        proto.parameter(param, true, engines, facts)
    }
}

/// set_proto_ctx_sseu / set_sseu: `args->size < sizeof(user_sseu)` is
/// -EINVAL, then `GRAPHICS_VER(i915) != 11` (every NARF i915 profile) is
/// -ENODEV, before the payload is copied.
fn sseu_set_refusal(size: u32) -> FsError {
    if size < 32 {
        FsError::InvalidData
    } else {
        FsError::NoDevice
    }
}

fn cpu_domain_write(cmd: u32, request: &[u8]) -> Result<bool, FsError> {
    if cmd != abi::GEM_SET_DOMAIN {
        return Ok(true);
    }
    let reads = u32_at(request, 4);
    let write = u32_at(request, 8);
    if reads & !0xc1 != 0
        || write & !0xc1 != 0
        || write.count_ones() > 1
        || (write != 0 && reads != write)
    {
        return Err(FsError::InvalidData);
    }
    Ok(write != 0)
}

/// Synchronous kernel callers use the same guarded copy seam as other DRM
/// ioctls. Userspace FileOps::ioctl_user supplies its fault-contained context.
pub(crate) struct GuardedIoctl;
impl IoctlContext for GuardedIoctl {
    fn read_u64_acquire(&self, address: u64) -> Result<u64, FsError> {
        atomic_user(address, None)
    }
    fn write_u64_release(&self, address: u64, value: u64) -> Result<(), FsError> {
        atomic_user(address, Some(value)).map(|_| ())
    }
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        // SAFETY: called only in the ioctl trap context, like the shared bridge.
        let bytes =
            unsafe { crate::drm_ioctl_bridge::copy_in(address as usize, destination.len())? };
        destination.copy_from_slice(&bytes);
        Ok(())
    }
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        // SAFETY: same syscall/address-space contract as read().
        unsafe { crate::drm_ioctl_bridge::copy_out(address as usize, source) }
    }
    fn nonblocking(&self) -> bool {
        false
    }
}

fn atomic_user(address: u64, write: Option<u64>) -> Result<u64, FsError> {
    if address == 0 || address.checked_add(8).is_none_or(|end| end > 1 << 47) {
        return Err(FsError::BadAddress);
    }
    if address & 7 != 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: the internal ioctl adapter is used only in the trapping task's
    // address space; range/alignment are validated and the access is guarded.
    unsafe { narf_arch::access_user_u64_guarded(address as *mut u64, write) }
        .map_err(|_| FsError::BadAddress)
}

fn read(user: &dyn IoctlContext, address: u64, size: usize) -> Result<Vec<u8>, FsError> {
    if size > MAX_COPY {
        return Err(FsError::InvalidData);
    }
    let mut bytes = vec![0; size];
    user.read(address, &mut bytes)?;
    Ok(bytes)
}

/// I915_GEM_CREATE_EXT_FLAG_NEEDS_CPU_ACCESS.
const GEM_CREATE_EXT_NEEDS_CPU_ACCESS: u32 = 1;
/// ARRAY_SIZE(i915->mm.regions): INTEL_REGION_UNKNOWN.
const REGION_IDS: u32 = 7;
/// mtl_info.max_pat_index.
const MAX_PAT_INDEX: u32 = 4;

/// i915_gem_create.c's create_extensions[] table under i915_user_extensions.
/// Returns whether SET_PAT asked for a PAT index.
fn create_extensions(
    info: &DeviceInfo,
    user: &dyn IoctlContext,
    address: u64,
) -> Result<Option<u8>, FsError> {
    let mut placements = false;
    let mut pat = None;
    abi::user_extensions(user, address, |address, name| match name {
        // I915_GEM_CREATE_EXT_MEMORY_REGIONS: ext_set_placements copies the
        // 48-byte drm_i915_gem_create_ext_memory_regions; set_placements
        // folds a nonzero pad, zero regions and more than INTEL_REGION_UNKNOWN
        // into one -EINVAL, then copies each region in turn. SYSTEM/0 is the
        // only region NARF reports, so any other entry is missing and a
        // second one a duplicate (-EINVAL). A second MEMORY_REGIONS
        // extension is refused only after its regions validate.
        0 => {
            let extension = read(user, address, 48)?;
            let count = u32_at(&extension, 36);
            if u32_at(&extension, 32) != 0 || count == 0 || count > REGION_IDS {
                return Err(FsError::InvalidData);
            }
            let regions = u64_at(&extension, 40);
            for n in 0..u64::from(count) {
                let at = regions.checked_add(n * 4).ok_or(FsError::BadAddress)?;
                if read(user, at, 4)? != [0, 0, 0, 0] || n != 0 {
                    return Err(FsError::InvalidData);
                }
            }
            if placements {
                return Err(FsError::InvalidData);
            }
            placements = true;
            Ok(())
        }
        // I915_GEM_CREATE_EXT_PROTECTED_CONTENT: ext_set_protected copies the
        // 36-byte extension and refuses nonzero flags; no NARF device enables
        // PXP, so intel_pxp_is_enabled is false: -ENODEV.
        1 => {
            if u32_at(&read(user, address, 36)?, 32) != 0 {
                return Err(FsError::InvalidData);
            }
            Err(FsError::NoDevice)
        }
        // I915_GEM_CREATE_EXT_SET_PAT: ext_set_pat refuses
        // `GRAPHICS_VER_FULL(i915) < IP_VER(12, 70)` before its copy, then
        // checks pat_index against max_pat_index (rsvd is unchecked). Linux
        // i915 has no descriptor past MTL; NARF's i915 ABI on later cards
        // keeps MTL's.
        2 => {
            if matches!(
                info.platform,
                GtPlatform::Gen12(_)
                    | GtPlatform::Alchemist
                    | GtPlatform::Integrated(Generation::TigerLake | Generation::AlderLake)
            ) {
                return Err(FsError::NoDevice);
            }
            let pat_index = u32_at(&read(user, address, 40)?, 32);
            if pat_index > MAX_PAT_INDEX {
                return Err(FsError::InvalidData);
            }
            pat = Some(pat_index as u8);
            Ok(())
        }
        _ => Err(FsError::InvalidData),
    })?;
    Ok(pat)
}

/// Immutable observed facts stay queryable after an owned GT stop; no query
/// here reads MMIO or wakes firmware. MIT Linux b90c984d i915_getparam.c.
fn observed_topology(info: &DeviceInfo) -> Result<&crate::intel_gpu_topology::GtTopology, FsError> {
    info.topology
        .as_deref()
        .filter(|topology| topology.platform() == info.platform)
        .ok_or(FsError::NoDevice)
}

fn getparam(info: &DeviceInfo, param: u32) -> Result<i32, FsError> {
    Ok(match param {
        // Obsolete UMS/DRI parameters are ENODEV in Linux, not fabricated zero.
        1..=3 | 14 => return Err(FsError::NoDevice),
        4 => info.device_id as i32,
        5 => 1, // GEM storage is available independently of acceleration.
        9 | 25 | 26 | 37 | 44 | 48 | 49 | 50 | 53 | 55 => i32::from(info.submission_ready()),
        // i915_getparam.c queries published logical engines, not raw fuse
        // presence or a different native profile's unadmitted media GT.
        10 | 11 | 22 | 31 => {
            let (class, logical) = match param {
                10 => (2, 0),
                11 => (1, 0),
                22 => (3, 0),
                _ => (2, 1),
            };
            i32::from(
                (param == 11 || info.platform.is_gen12())
                    && info.user_status().is_some_and(|status| {
                        status.engines.from_class_instance(class, logical).is_some()
                    }),
            )
        }
        18 => {
            if info.submission_ready() {
                3
            } else {
                0
            }
        }
        19 => 1, // GEM_WAIT supports the timeout wire request
        30 => 0, // legacy GEM_MMAP returns a CPU VA: not supported
        32 => i32::from(
            info.backend
                .as_ref()
                .and_then(|backend| backend.device_facts())
                .ok_or(FsError::NoDevice)?
                .revision,
        ),
        33 => i32::try_from(observed_topology(info)?.dss_count()).map_err(|_| FsError::NoDevice)?,
        34 => i32::try_from(observed_topology(info)?.eu_count()).map_err(|_| FsError::NoDevice)?,
        // Linux i915_getparam.c: full automatic reset is level1, not a
        // bitmask. A retained physical worker must qualify this exact epoch.
        35 => i32::from(info.user_status().is_some_and(|status| {
            info.platform.guc().is_some()
                && status.submission_version.0 == 1
                && status.engines.iter().next().is_some()
                && info
                    .backend
                    .as_ref()
                    .and_then(|backend| backend.reset_availability_epoch())
                    == Some(status.epoch)
        })),
        40 => 4, // MMAP_OFFSET
        43 => i32::from(info.object_async_ready()),
        // Bounded NARF capability: Linux advertises this unconditionally.
        // Cached callbacks only; raw capture still needs its independent owner.
        45 => i32::from(
            info.platform.guc().is_some()
                && info.user_status().is_some_and(|status| {
                    status.submission_version.0 == 1 && status.engines.bits() != 0
                }),
        ),
        // i915_getparam.c writes value=-EINVAL (not an ioctl error) when
        // GuC submission is unavailable, then uses the common put_user path.
        59 => {
            if crate::intel_gpu_xe::low_latency_supported(info) {
                1
            } else {
                -22
            }
        }
        // ENABLED and PRIORITY while live; busy-stat, semaphore, preemption
        // and static-map bits require their own implemented contracts.
        41 => scheduler_caps(info),
        46 | 47 if info.platform.is_gen12() => {
            let topology = observed_topology(info)?;
            if param == 46 {
                1
            } else {
                i32::try_from(topology.geometry_dss()).map_err(|_| FsError::NoDevice)?
            }
        }
        46 | 47 => {
            // xehp_sseu_info_init's software slice is not a legacy power-gating
            // mask. Linux requires full topology queries from Xe_HP onward.
            return Err(if info.platform.guc().is_some() {
                FsError::InvalidData
            } else {
                FsError::NoDevice
            });
        }
        51 => {
            let frequency = info
                .backend
                .as_ref()
                .and_then(|backend| backend.device_facts())
                .ok_or(FsError::NoDevice)?
                .reference_clock;
            if frequency == 0 {
                return Err(FsError::NoDevice);
            }
            i32::try_from(frequency).map_err(|_| FsError::NoDevice)?
        }
        // I915_PARAM_OA_TIMESTAMP_FREQUENCY: i915_perf_oa_timestamp_frequency,
        // unconditional in i915_getparam.c (no perf or OA opt-in). The CTC
        // shift is cached with the clock rather than read per call.
        57 => {
            let frequency = info
                .backend
                .as_ref()
                .and_then(|backend| backend.device_facts())
                .ok_or(FsError::NoDevice)?
                .oa_timestamp_frequency;
            if frequency == 0 {
                return Err(FsError::NoDevice);
            }
            i32::try_from(frequency).map_err(|_| FsError::NoDevice)?
        }
        23 => 1, // I915_PARAM_HAS_GEM_USERPTR
        abi::PARAM_PERF_REVISION => i32::from(
            info.backend
                .as_ref()
                .and_then(|backend| backend.oa_device())
                .is_some(),
        ),
        // Explicitly absent features; do not advertise secure dispatch,
        // CPU coherency or unimplemented scheduler controls.
        6..=8 | 12..=13 | 15..=17 | 20..=21 | 24 | 27..=29 | 36 | 38..=39 | 42 | 52 | 56 | 58 => 0,
        _ => return Err(FsError::InvalidData),
    })
}

// The internal registry identity remains intel-gpu. A live i915-compatible
// render UAPI exposes the loader name through fault-aware userspace copies.
fn version(arg: u64, user: &dyn IoctlContext, name: &[u8]) -> Result<(), FsError> {
    let mut request = read(user, arg, 64)?;
    put32(&mut request, 0, 1);
    put32(&mut request, 4, 6);
    put32(&mut request, 8, 0);
    for (offset, value) in [
        (16, name),
        (32, b"".as_slice()),
        (48, b"NARF Intel RCS".as_slice()),
    ] {
        let count = u64_at(&request, offset).min(value.len() as u64) as usize;
        let pointer = u64_at(&request, offset + 8);
        if count != 0 && pointer != 0 {
            user.write(pointer, &value[..count])?;
        }
        put64(&mut request, offset, value.len() as u64);
    }
    user.write(arg, &request)
}

fn query_perf_config(
    info: &DeviceInfo,
    subcmd: u32,
    capacity: i32,
    data_ptr: u64,
    user: &dyn IoctlContext,
) -> Result<i32, FsError> {
    let device = info
        .backend
        .as_ref()
        .and_then(|b| b.oa_device())
        .ok_or(FsError::NoDevice)?;

    match subcmd {
        abi::QUERY_PERF_CONFIG_LIST => {
            let ids = crate::intel_gpu_oa::query_config_ids(device.card);
            let n_configs = ids.len();
            let total_size = 48 + 8 * n_configs;
            if capacity == 0 {
                return Ok(total_size as i32);
            }
            if (capacity as usize) < total_size {
                return Err(FsError::InvalidData);
            }
            if data_ptr == 0 {
                return Err(FsError::BadAddress);
            }
            let mut flags_bytes = [0u8; 4];
            user.read(data_ptr + 40, &mut flags_bytes)?;
            if u32::from_le_bytes(flags_bytes) != 0 {
                return Err(FsError::InvalidData);
            }
            user.write(data_ptr, &(n_configs as u64).to_le_bytes())?;
            for (idx, &cid) in ids.iter().enumerate() {
                let at = data_ptr + 48 + (idx as u64) * 8;
                user.write(at, &cid.to_le_bytes())?;
            }
            Ok(total_size as i32)
        }
        abi::QUERY_PERF_CONFIG_DATA_FOR_UUID | abi::QUERY_PERF_CONFIG_DATA_FOR_ID => {
            let total_size = 48 + 72;
            if capacity == 0 {
                return Ok(total_size as i32);
            }
            if (capacity as usize) < total_size {
                return Err(FsError::InvalidData);
            }
            if data_ptr == 0 {
                return Err(FsError::BadAddress);
            }
            let mut flags_bytes = [0u8; 4];
            user.read(data_ptr + 40, &mut flags_bytes)?;
            if u32::from_le_bytes(flags_bytes) != 0 {
                return Err(FsError::InvalidData);
            }
            let config = if subcmd == abi::QUERY_PERF_CONFIG_DATA_FOR_UUID {
                let mut uuid = [0u8; 36];
                user.read(data_ptr, &mut uuid)?;
                crate::intel_gpu_oa::query_config_by_uuid(device.card, &uuid)
                    .ok_or(FsError::NotFound)?
            } else {
                let mut cid_bytes = [0u8; 8];
                user.read(data_ptr, &mut cid_bytes)?;
                let cid = u64::from_le_bytes(cid_bytes);
                crate::intel_gpu_oa::query_config_by_id(device.card, cid)
                    .ok_or(FsError::NotFound)?
            };

            let mut user_config = [0u8; 72];
            user.read(data_ptr + 48, &mut user_config)?;
            let mut n_mux = u32_at(&user_config, 36);
            let mut n_bool = u32_at(&user_config, 40);
            let mut n_flex = u32_at(&user_config, 44);
            let mux_ptr = u64_at(&user_config, 48);
            let bool_ptr = u64_at(&user_config, 56);
            let flex_ptr = u64_at(&user_config, 64);

            if (n_bool > 0 && n_bool < config.n_bool)
                || (n_flex > 0 && n_flex < config.n_flex)
                || (n_mux > 0 && n_mux < config.n_mux)
            {
                return Err(FsError::InvalidData);
            }

            let copy_reg_group = |user: &dyn IoctlContext,
                                  regs: &[(u32, u32)],
                                  user_n_regs: &mut u32,
                                  user_regs_ptr: u64|
             -> Result<(), FsError> {
                let kernel_n_regs = regs.len() as u32;
                if *user_n_regs == 0 {
                    *user_n_regs = kernel_n_regs;
                    return Ok(());
                }
                if user_regs_ptr == 0 {
                    return Err(FsError::BadAddress);
                }
                for (i, (addr, val)) in regs.iter().enumerate() {
                    let at = user_regs_ptr
                        .checked_add((i as u64) * 8)
                        .ok_or(FsError::BadAddress)?;
                    user.write(at, &addr.to_le_bytes())?;
                    user.write(at + 4, &val.to_le_bytes())?;
                }
                *user_n_regs = kernel_n_regs;
                Ok(())
            };

            let bool_regs = &config.regs[0..config.n_bool as usize];
            copy_reg_group(user, bool_regs, &mut n_bool, bool_ptr)?;
            put32(&mut user_config, 40, n_bool);

            let flex_start = config.n_bool as usize;
            let flex_end = flex_start + config.n_flex as usize;
            let flex_regs = &config.regs[flex_start..flex_end];
            copy_reg_group(user, flex_regs, &mut n_flex, flex_ptr)?;
            put32(&mut user_config, 44, n_flex);

            let mux_regs = &config.regs[flex_end..];
            copy_reg_group(user, mux_regs, &mut n_mux, mux_ptr)?;
            put32(&mut user_config, 36, n_mux);

            user_config[..36].copy_from_slice(&config.uuid);
            user.write(data_ptr + 48, &user_config)?;

            Ok(total_size as i32)
        }
        _ => Err(FsError::InvalidData),
    }
}

fn query(info: &DeviceInfo, arg: u64, user: &dyn IoctlContext) -> Result<(), FsError> {
    let request = read(user, arg, 16)?;
    let count = u32_at(&request, 0) as usize;
    if count > MAX_QUERIES || u32_at(&request, 4) != 0 {
        return Err(FsError::InvalidData);
    }
    if count == 0 {
        return Ok(());
    }
    let pointer = u64_at(&request, 8);
    let items = read(user, pointer, count * 24)?;
    for (i, item) in items.chunks_exact(24).enumerate() {
        let id = u64_at(item, 0);
        let capacity = u32_at(item, 8) as i32;
        let flags = u32_at(item, 12);
        let data_ptr = u64_at(item, 16);
        let result = (|| {
            if capacity < 0 {
                return Err(FsError::InvalidData);
            }
            if id == abi::QUERY_PERF_CONFIG {
                return query_perf_config(info, flags, capacity, data_ptr, user);
            }
            if flags != 0 {
                return Err(FsError::InvalidData);
            }
            let reply: Cow<'_, [u8]> = match id {
                abi::QUERY_ENGINES => {
                    // RENDER/COPY/COMPUTE share Xe's class numbers. Public
                    // instances are dense within this exact physical set.
                    let present = info
                        .user_status()
                        .map_or_else(Default::default, |status| status.engines);
                    let engines: Vec<_> = present.iter().collect();
                    let mut reply = vec![0; 16 + engines.len() * 56];
                    put32(&mut reply, 0, engines.len() as u32);
                    for (i, engine) in engines.iter().enumerate() {
                        let entry = &mut reply[16 + i * 56..16 + (i + 1) * 56];
                        entry[..2].copy_from_slice(&engine.xe_class().to_le_bytes());
                        let logical = present.logical_instance(*engine).expect("published engine");
                        entry[2..4].copy_from_slice(&logical.to_le_bytes());
                        put64(entry, 8, 1); // I915_ENGINE_INFO_HAS_LOGICAL_INSTANCE
                        entry[24..26].copy_from_slice(&logical.to_le_bytes());
                    }
                    Cow::Owned(reply)
                }
                abi::QUERY_MEMORY_REGIONS if info.memory_bytes != 0 => {
                    let mut reply = vec![0; 104]; // header16 + memory_region_info88
                    put32(&mut reply, 0, 1);
                    put64(&mut reply, 24, info.memory_bytes);
                    put64(&mut reply, 32, info.memory_bytes);
                    Cow::Owned(reply)
                }
                abi::QUERY_HWCONFIG => {
                    Cow::Borrowed(info.hwconfig.as_ref().ok_or(FsError::NoDevice)?.as_bytes())
                }
                abi::QUERY_TOPOLOGY | abi::QUERY_GEOMETRY_SUBSLICES => {
                    let topology = info.topology.as_ref().ok_or(FsError::NoDevice)?;
                    if topology.platform() != info.platform
                        || (id == abi::QUERY_GEOMETRY_SUBSLICES && !topology.has_render())
                    {
                        return Err(FsError::NoDevice);
                    }
                    Cow::Owned(topology.i915_bytes(id == abi::QUERY_GEOMETRY_SUBSLICES))
                }
                // Linux reports the GuC scheduling interface, not the loaded
                // firmware's release. Branch is zero for the upstream ABI.
                abi::QUERY_GUC_SUBMISSION_VERSION => {
                    let status = info.user_status().ok_or(FsError::NoDevice)?;
                    let mut reply = vec![0; 16];
                    put32(&mut reply, 4, u32::from(status.submission_version.0));
                    put32(&mut reply, 8, u32::from(status.submission_version.1));
                    put32(&mut reply, 12, u32::from(status.submission_version.2));
                    Cow::Owned(reply)
                }
                _ => return Err(FsError::InvalidData),
            };
            let required = reply.len() as i32;
            if capacity != 0 {
                if capacity < required {
                    return Err(FsError::InvalidData);
                }
                if matches!(id, abi::QUERY_TOPOLOGY | abi::QUERY_GEOMETRY_SUBSLICES) {
                    // i915_query.c::copy_query_item requires a readable header
                    // before replacing it, even though its contents are ignored.
                    read(user, u64_at(item, 16), 16)?;
                }
                if id == abi::QUERY_ENGINES && read(user, u64_at(item, 16), 16)? != [0; 16] {
                    // query_engine_info: num_engines and rsvd are input MBZ.
                    return Err(FsError::InvalidData);
                }
                user.write(u64_at(item, 16), &reply)?;
            }
            Ok(required)
        })();
        let length = match result {
            Ok(size) => size,
            Err(FsError::BadAddress) => -14,
            Err(FsError::NotFound) => -2,
            Err(FsError::NoDevice) => -19,
            Err(_) => -22,
        };
        // Only length is an output field. Preserve item flags, pointer and id.
        let output = pointer
            .checked_add(i as u64 * 24 + 8)
            .ok_or(FsError::BadAddress)?;
        user.write(output, &length.to_le_bytes())?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    pub(crate) struct User {
        bytes: IrqSafeSpinLock<Vec<u8>>,
        fail_write: IrqSafeSpinLock<Option<u64>>,
        fail_read: IrqSafeSpinLock<Option<u64>>,
    }
    impl User {
        pub(crate) fn new() -> Self {
            Self {
                bytes: IrqSafeSpinLock::new(vec![0; 32768]),
                fail_write: IrqSafeSpinLock::new(None),
                fail_read: IrqSafeSpinLock::new(None),
            }
        }
        pub(crate) fn store(&self, address: u64, data: &[u8]) {
            self.write(address, data).expect("fixture store");
        }
        pub(crate) fn load(&self, address: u64, len: usize) -> Vec<u8> {
            read(self, address, len).expect("fixture load")
        }
        pub(crate) fn fault_read_at(&self, address: Option<u64>) {
            *self.fail_read.lock() = address;
        }
        pub(crate) fn fault_write_at(&self, address: Option<u64>) {
            *self.fail_write.lock() = address;
        }
    }
    impl IoctlContext for User {
        fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
            if *self.fail_read.lock() == Some(address) {
                return Err(FsError::BadAddress);
            }
            let memory = self.bytes.lock();
            let end = address
                .checked_add(destination.len() as u64)
                .ok_or(FsError::BadAddress)?;
            if address == 0 || end > memory.len() as u64 {
                return Err(FsError::BadAddress);
            }
            destination.copy_from_slice(&memory[address as usize..end as usize]);
            Ok(())
        }
        fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
            if *self.fail_write.lock() == Some(address) {
                return Err(FsError::BadAddress);
            }
            let mut memory = self.bytes.lock();
            let end = address
                .checked_add(source.len() as u64)
                .ok_or(FsError::BadAddress)?;
            if address == 0 || end > memory.len() as u64 {
                return Err(FsError::BadAddress);
            }
            memory[address as usize..end as usize].copy_from_slice(source);
            Ok(())
        }
        fn nonblocking(&self) -> bool {
            false
        }
        fn pin_user_pages(
            &self,
            address: u64,
            pages: u64,
            _writable: bool,
        ) -> Result<Vec<narf_memory::address_space::UserPagePin>, FsError> {
            let memory = self.bytes.lock();
            let len = pages.checked_mul(4096).ok_or(FsError::BadAddress)?;
            let end = address.checked_add(len).ok_or(FsError::BadAddress)?;
            if address == 0 || end > memory.len() as u64 {
                return Err(FsError::BadAddress);
            }
            drop(memory);
            let mut pins = Vec::new();
            for _ in 0..pages {
                let frame = narf_memory::alloc_frame().map_err(|_| FsError::OutOfMemory)?;
                // SAFETY: newly allocated frame retained by UserPagePin for this test
                let pin = unsafe {
                    narf_memory::address_space::UserPagePin::retain_ram(frame.start_address())
                };
                pins.push(pin);
            }
            Ok(pins)
        }
    }
    fn info(generation: Generation) -> DeviceInfo {
        DeviceInfo {
            device_id: 0x7d55,
            platform: GtPlatform::Integrated(generation),
            memory_bytes: 0x8000_0000,
            hwconfig: None,
            topology: None,
            vram: None,
            backend: None,
        }
    }
    fn invoke(file: &RenderFile, user: &User, cmd: u32) -> Result<u64, FsError> {
        file.dispatch(&info(Generation::MeteorLake), cmd, 64, user)
            .expect("Intel command")
    }
    fn check(run: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
        match run() {
            Ok(()) => TestResult::Pass,
            Err(why) => TestResult::Fail(why),
        }
    }

    /// Exercise the actual primary/render file dispatchers against one card's
    /// immutable snapshot, including when its firmware owner has been dropped.
    pub(crate) fn check_card_hwconfig(
        card: u32,
        expected: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        use narf_filesystem::DirOps;
        for name in [
            alloc::format!("card{card}"),
            alloc::format!("renderD{}", card + 128),
        ] {
            let file = crate::drm_devfs_bridge::DriDir
                .lookup(&name)
                .ok_or("DRM node")?;
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 5);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            let mut items = [0; 120];
            for (item, id) in items.chunks_exact_mut(24).zip([5, 7, 2, 1, 4]) {
                put64(item, 0, id);
            }
            user.store(256, &items);
            narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                .map_err(|_| "node query")?;
            let lengths = user.load(256, 120);
            if u32_at(&lengths, 8) as i32 != expected.map_or(-19, |bytes| bytes.len() as i32)
                || u32_at(&lengths, 32) as i32 != -19 // no GuC submission interface
                || u32_at(&lengths, 56) != 16 // no admitted engines
                || u32_at(&lengths, 80) as i32 != -19 // no observed topology
                || u32_at(&lengths, 104) != 104
            // system RAM only
            {
                return Err("card query availability/length");
            }
            if let Some(bytes) = expected {
                put32(&mut items, 8, bytes.len() as u32 + 8);
                put64(&mut items, 16, 1024);
                put32(&mut items, 56, 16);
                put64(&mut items, 64, 2048);
                put32(&mut items, 104, 104);
                put64(&mut items, 112, 4096);
                user.store(256, &items);
                user.store(1024 + bytes.len() as u64, &[0xaa; 8]);
                narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                    .map_err(|_| "node data query")?;
                if user.load(1024, bytes.len()) != bytes
                    || user.load(1024 + bytes.len() as u64, 8) != [0xaa; 8]
                    || user.load(2048, 16) != [0; 16]
                {
                    return Err("exact HWCONFIG bytes/extent or invented engine");
                }
                let memory = user.load(4096, 104);
                if u32_at(&memory, 0) != 1 || u32_at(&memory, 16) != 0 {
                    return Err("system memory misreported as VRAM");
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn check_card_topology(
        card: u32,
        expected: Option<&[u8]>,
        geometry: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        use narf_filesystem::DirOps;
        for name in [
            alloc::format!("card{card}"),
            alloc::format!("renderD{}", card + 128),
        ] {
            let file = crate::drm_devfs_bridge::DriDir
                .lookup(&name)
                .ok_or("DRM topology node")?;
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 3);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            let mut items = [0; 72];
            for (item, id) in items.chunks_exact_mut(24).zip([1, 6, 2]) {
                put64(item, 0, id);
                put64(item, 16, u64::MAX); // size-only never touches it
            }
            user.store(256, &items);
            narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                .map_err(|_| "node topology size")?;
            let lengths = user.load(256, 72);
            if u32_at(&lengths, 8) as i32 != expected.map_or(-19, |v| v.len() as i32)
                || u32_at(&lengths, 32) as i32 != geometry.map_or(-19, |v| v.len() as i32)
                || u32_at(&lengths, 56) != 16
            {
                return Err("topology size/absence or engine admission");
            }
            for (index, bytes) in [expected, geometry].into_iter().enumerate() {
                let Some(bytes) = bytes else { continue };
                let address = 1024 + index as u64 * 1024;
                put32(&mut items, index * 24 + 8, bytes.len() as u32 + 8);
                put64(&mut items, index * 24 + 16, address);
                user.store(address, &vec![0xaa; bytes.len() + 8]);
            }
            put32(&mut items, 56, 16);
            put64(&mut items, 64, 4096);
            user.store(256, &items);
            narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                .map_err(|_| "node topology data")?;
            for (index, bytes) in [expected, geometry].into_iter().enumerate() {
                if let Some(bytes) = bytes {
                    let address = 1024 + index as u64 * 1024;
                    if user.load(address, bytes.len()) != bytes
                        || user.load(address + bytes.len() as u64, 8) != [0xaa; 8]
                    {
                        return Err("topology content or copy extent");
                    }
                }
            }
            if user.load(4096, 16) != [0; 16] {
                return Err("topology advertised execution");
            }
        }
        Ok(())
    }

    fn smoke_intel_topology_query_faults() -> TestResult {
        struct Fuses;
        impl crate::intel_gpu_aux::MmioWindow for Fuses {
            fn read32(&self, offset: u64) -> u32 {
                match offset {
                    0x913c => 5,
                    0x9144 => 6,
                    0x9134 => 5,
                    0x9118 => 1,    // MEML3_EN node 0
                    0x9114 => 0x10, // GT_L3_EXC_MASK pair 0
                    _ => panic!("topology register"),
                }
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("topology write")
            }
        }
        let mut info = info(Generation::MeteorLake);
        info.topology = Some(Arc::new(
            crate::intel_gpu_topology::GtTopology::read(&Fuses, info.platform).unwrap(),
        ));
        let user = User::new();
        let mut request = [0; 16];
        put32(&mut request, 0, 3);
        put64(&mut request, 8, 256);
        user.store(64, &request);
        for (capacity, flags, fault_read, fault_write, expected) in [
            (0, 0, true, true, 85),
            (84, 0, false, false, -22),
            (85, 1, false, false, -22),
            (85, 0, true, false, -14),
            (85, 0, false, true, -14),
            (85, 0, false, false, 85),
        ] {
            let mut items = [0; 72];
            put64(&mut items, 0, 1);
            put32(&mut items, 8, capacity);
            put32(&mut items, 12, flags);
            put64(&mut items, 16, 1024);
            put64(&mut items, 24, 6);
            put32(&mut items, 32, 85);
            put64(&mut items, 40, 2048);
            put64(&mut items, 48, 2);
            user.store(1024, &[0xaa; 93]);
            user.store(256, &items);
            *user.fail_read.lock() = fault_read.then_some(1024);
            *user.fail_write.lock() = fault_write.then_some(1024);
            query(&info, 64, &user).unwrap();
            *user.fail_read.lock() = None;
            *user.fail_write.lock() = None;
            let mut expected_items = items;
            put32(&mut expected_items, 8, expected as u32);
            put32(&mut expected_items, 32, 85);
            put32(&mut expected_items, 56, 16);
            assert_eq!(user.load(256, 72), expected_items);
            assert_eq!(user.load(1109, 8), [0xaa; 8]);
            if expected < 0 || capacity == 0 {
                assert_eq!(user.load(1024, 85), [0xaa; 85]);
            }
        }
        assert!(!info.submission_ready());
        info.platform = GtPlatform::Battlemage;
        query(&info, 64, &user).unwrap();
        assert_eq!(u32_at(&user.load(256, 72), 8) as i32, -19);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_topology_query_faults
    );

    fn smoke_intel_registry_routes_primary_and_render_nodes() -> TestResult {
        use narf_filesystem::DirOps;
        check(|| {
            for device_id in [0x9a49, 0x7d55, 0x56a0, 0xe20b] {
                let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
                    alloc::string::String::from("Intel routing fixture"),
                    0x8086,
                    device_id,
                    0,
                    0,
                ));
                let index = crate::drm_registry::register_drm_card(card);
                if crate::drm_registry::driver_name(index) != Some("intel-gpu") {
                    return Err("Intel driver identity missing from registry dispatch");
                }
                let info = DeviceInfo::for_card(index).ok_or("registered Intel profile")?;
                if info.device_id != device_id
                    || Some(info.platform) != GtPlatform::from_pci(0x8086, device_id)
                    || info.submission_ready()
                {
                    return Err("registered card facts or unproven submission");
                }
                check_card_hwconfig(index, None)?;
                for name in [
                    alloc::format!("card{index}"),
                    alloc::format!("renderD{}", index + 128),
                ] {
                    let file = crate::drm_devfs_bridge::DriDir
                        .lookup(&name)
                        .ok_or("DRM node")?;
                    let other = crate::drm_devfs_bridge::DriDir
                        .lookup(&name)
                        .ok_or("second open")?;
                    let user = User::new();
                    let mut request = [0; 16];
                    put32(&mut request, 0, 4); // actual PCI device ID
                    put64(&mut request, 8, 256);
                    user.store(64, &request);
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GETPARAM, 64, &user))
                        .map_err(|_| "GETPARAM through node")?;
                    if u32_at(&user.load(256, 4), 0) != u32::from(device_id) {
                        return Err("GETPARAM from another card");
                    }
                    put64(&mut request, 0, 4096);
                    put64(&mut request, 8, 0);
                    user.store(64, &request);
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GEM_CREATE, 64, &user))
                        .map_err(|_| "GEM_CREATE through node")?;
                    let handle = u32_at(&user.load(64, 16), 8);
                    let mut mmap = [0; 32];
                    put32(&mut mmap, 0, handle);
                    put64(&mut mmap, 16, 2); // I915_MMAP_OFFSET_WB
                    user.store(64, &mmap);
                    if narf_scheduler::block_on_spin(other.ioctl_user(
                        abi::GEM_MMAP_OFFSET,
                        64,
                        &user,
                    )) != Err(FsError::NotFound)
                    {
                        return Err("node opens shared GEM handles");
                    }
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GEM_MMAP_OFFSET, 64, &user))
                        .map_err(|_| "MMAP_OFFSET through node")?;
                    let offset = u64_at(&user.load(64, 32), 8);
                    let backing = file.mmap_backing(offset, 4096).map_err(|_| "node mmap")?;
                    if backing.frames.len() != 1 || backing.lifetime.is_none() {
                        return Err("node mmap did not retain GEM backing");
                    }
                    let mut close = [0; 8];
                    put32(&mut close, 0, handle);
                    user.store(64, &close);
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GEM_CLOSE, 64, &user))
                        .map_err(|_| "GEM_CLOSE through node")?;
                    if file.mmap_backing(offset, 4096).is_ok() {
                        return Err("closed handle still maps through node");
                    }
                }
            }
            for (vendor, device) in [(0x8086, 0xffff), (0x1002, 0x7d55)] {
                let index = crate::drm_registry::register_drm_card(Arc::new(
                    crate::drm_devfs_bridge::IntelGpuCard::new(
                        alloc::string::String::new(),
                        vendor,
                        device,
                        0,
                        0,
                    ),
                ));
                if DeviceInfo::for_card(index).is_some()
                    || RenderFile::new().dispatch_card(index, abi::GETPARAM, 0, &User::new())
                        != Some(Err(FsError::NoDevice))
                {
                    return Err("unknown/non-Intel identity admitted");
                }
            }
            let index = crate::drm_registry::register_drm_card(Arc::new(
                crate::drm_devfs_bridge::BochsCard::new(alloc::string::String::new()),
            ));
            if DeviceInfo::for_card(index).is_some()
                || RenderFile::new()
                    .dispatch_card(index, abi::GETPARAM, 0, &User::new())
                    .is_some()
            {
                return Err("another driver's ioctl intercepted");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_registry_routes_primary_and_render_nodes
    );

    fn smoke_intel_gem_namespace_mapping_and_close() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let other = RenderFile::new();
            let user = User::new();
            let mut create = [0; 16];
            put64(&mut create, 0, 4097);
            user.store(64, &create);
            invoke(&file, &user, abi::GEM_CREATE).map_err(|_| "create")?;
            let reply = user.load(64, 16);
            let handle = u32_at(&reply, 8);
            if u64_at(&reply, 0) != 8192 {
                return Err("create must round to a page");
            }
            if other.gem.object(handle).is_ok() {
                return Err("foreign handle resolved");
            }
            let object = file.gem.object(handle).map_err(|_| "own handle")?;
            let mut zeroes = [1; 8192];
            object.read(0, &mut zeroes).map_err(|_| "read zeroes")?;
            if zeroes != [0; 8192] {
                return Err("GEM allocation leaked old bytes");
            }
            object
                .write(4094, &[0x12, 0x34, 0x56, 0x78])
                .map_err(|_| "cross-page write")?;
            let mut data = [0; 4];
            object
                .read(4094, &mut data)
                .map_err(|_| "cross-page read")?;
            if data != [0x12, 0x34, 0x56, 0x78] {
                return Err("cross-page data corrupted");
            }
            let offset = file.gem.mmap_offset(handle).map_err(|_| "mmap offset")?;
            if other.gem.mmap_backing(offset, 4096).is_ok()
                || file.gem.mmap_backing(offset, 8193).is_ok()
                || file.gem.mmap_backing(offset + 1, 4096).is_ok()
                || file.gem.mmap_backing(offset + 8192, 4096).is_ok()
            {
                return Err("mmap escaped handle ownership/extent");
            }
            let mapping = file
                .gem
                .mmap_backing(offset + 4096, 4096)
                .map_err(|_| "subrange mmap")?;
            if mapping.frames != object.pages().skip(1).collect::<Vec<_>>() {
                return Err("mmap frame offset");
            }
            let references = Arc::strong_count(&object);
            file.gem.close(handle).map_err(|_| "close")?;
            if file.gem.object(handle).is_ok() || Arc::strong_count(&object) != references - 1 {
                return Err("close did not drop precisely the handle owner");
            }
            if mapping.lifetime.is_none() {
                return Err("mmap failed to retain backing");
            }
            object
                .read(4094, &mut data)
                .map_err(|_| "mapping lifetime after close")?;
            if data != [0x12, 0x34, 0x56, 0x78] {
                return Err("close released retained data");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_gem_namespace_mapping_and_close
    );

    fn smoke_intel_create_copy_failure_and_limits() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let mut request = [0; 16];
            put64(&mut request, 0, 4096);
            user.store(64, &request);
            *user.fail_write.lock() = Some(64);
            if invoke(&file, &user, abi::GEM_CREATE) != Err(FsError::BadAddress) {
                return Err("copy failure lost EFAULT");
            }
            *user.fail_write.lock() = None;
            invoke(&file, &user, abi::GEM_CREATE).map_err(|_| "create after failed copy")?;
            if u32_at(&user.load(64, 16), 8) != 0x4000_0000 {
                return Err("failed copy consumed a GEM handle");
            }
            for size in [0, u64::MAX, 256 * 1024 * 1024 + 1] {
                put64(&mut request, 0, size);
                user.store(64, &request);
                if invoke(&file, &user, abi::GEM_CREATE) != Err(FsError::InvalidData) {
                    return Err("invalid allocation extent");
                }
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_create_copy_failure_and_limits
    );

    fn smoke_intel_query_two_pass_and_item_errors() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 3);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            let mut items = [0; 72];
            put64(&mut items, 0, 4); // memory regions
            put64(&mut items, 24, 2); // engines
            put64(&mut items, 48, u64::MAX);
            user.store(256, &items);
            invoke(&file, &user, abi::QUERY).map_err(|_| "size query")?;
            let sizes = user.load(256, 72);
            if u32_at(&sizes, 8) != 104
                || u32_at(&sizes, 32) != 16
                || u32_at(&sizes, 56) as i32 != -22
            {
                return Err("two-pass query sizes/per-item failure");
            }
            put32(&mut items, 8, 104);
            put64(&mut items, 16, 1024);
            put32(&mut items, 32, 15); // undersized engine output
            put64(&mut items, 40, 2048);
            user.store(2048, &[0xaa; 16]);
            user.store(256, &items);
            invoke(&file, &user, abi::QUERY).map_err(|_| "data query")?;
            let memory = user.load(1024, 104);
            if u32_at(&memory, 0) != 1
                || u32_at(&memory, 16) != 0
                || u64_at(&memory, 24) != 0x8000_0000
                || u64_at(&memory, 32) != 0x8000_0000
                || memory[40..].iter().any(|v| *v != 0)
            {
                return Err("memory query wire fields/reserved bytes");
            }
            if u32_at(&user.load(256, 72), 32) as i32 != -22 || user.load(2048, 16) != [0xaa; 16] {
                return Err("short query overwrote output");
            }
            put32(&mut items, 8, 104);
            put64(&mut items, 16, u64::MAX - 8);
            user.store(256, &items);
            invoke(&file, &user, abi::QUERY).map_err(|_| "per-item EFAULT query")?;
            if u32_at(&user.load(256, 72), 8) as i32 != -14 {
                return Err("query data fault not item EFAULT");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_query_two_pass_and_item_errors
    );

    fn smoke_intel_hwconfig_query_faults_and_copy_extent() -> TestResult {
        // Local Linux i915_query.c::query_hwconfig_blob: size-only does not
        // dereference data_ptr; short buffers are EINVAL and copies are exact.
        check(|| {
            let bytes: Vec<u8> = [0x9000u32, 2, 0xffffffff, 0x01020304, 7, 1, 8]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let mut info = info(Generation::MeteorLake);
            info.hwconfig = Some(Arc::new(HardwareConfig::parse(bytes.clone()).unwrap()));
            let user = User::new();
            let file = RenderFile::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 2);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            for (capacity, flags, pointer, expected) in [
                (0, 0, u64::MAX, 28),
                (27, 0, 1024, -22),
                (-1, 0, 1024, -22),
                (28, 1, 1024, -22),
                (28, 0, 0, -14),
                (28, 0, u64::MAX - 8, -14),
                (28, 0, 1024, 28),
                (36, 0, 1024, 28),
            ] {
                let mut items = [0; 48];
                put64(&mut items, 0, 5);
                put32(&mut items, 8, capacity as u32);
                put32(&mut items, 12, flags);
                put64(&mut items, 16, pointer);
                put64(&mut items, 24, 2); // a later valid item still runs
                user.store(256, &items);
                user.store(1024, &[0xaa; 36]);
                file.dispatch(&info, abi::QUERY, 64, &user)
                    .unwrap()
                    .map_err(|_| "HWCONFIG item query")?;
                let result = user.load(256, 48);
                if u32_at(&result, 8) as i32 != expected
                    || result[..8] != items[..8]
                    || result[12..32] != items[12..32]
                    || u32_at(&result, 32) != 16
                {
                    return Err("HWCONFIG per-item length/isolation or input fields changed");
                }
                let output = user.load(1024, 36);
                if capacity >= 28 && flags == 0 && pointer == 1024 {
                    if output[..28] != bytes || output[28..] != [0xaa; 8] {
                        return Err("HWCONFIG output extent/order");
                    }
                } else if output != [0xaa; 36] {
                    return Err("failed/size-only item wrote output");
                }
            }
            *user.fail_write.lock() = Some(264); // item length itself faults
            if file.dispatch(&info, abi::QUERY, 64, &user) != Some(Err(FsError::BadAddress)) {
                return Err("length copy fault did not fail ioctl");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_hwconfig_query_faults_and_copy_extent
    );

    fn smoke_intel_context_vm_lifetime_and_foreign_ids() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let other = RenderFile::new();
            let user = User::new();
            user.store(64, &[0; 16]);
            invoke(&file, &user, abi::GEM_VM_CREATE).map_err(|_| "VM create")?;
            let vm = u32_at(&user.load(64, 16), 12);
            user.store(64, &[0; 8]);
            invoke(&file, &user, abi::GEM_CONTEXT_CREATE).map_err(|_| "context create")?;
            let ctx = u32_at(&user.load(64, 8), 0);
            let mut parameter = [0; 24];
            put32(&mut parameter, 0, ctx);
            put64(&mut parameter, 8, 9);
            put64(&mut parameter, 16, vm as u64);
            user.store(64, &parameter);
            invoke(&file, &user, abi::GEM_CONTEXT_SETPARAM).map_err(|_| "bind explicit VM")?;
            if invoke(&other, &user, abi::GEM_CONTEXT_SETPARAM) != Err(FsError::NotFound) {
                return Err("foreign context resolved");
            }
            let old_vm = file
                .namespaces
                .lock()
                .contexts
                .get(&ctx)
                .expect("ctx")
                .vm
                .clone();
            let mut destroy = [0; 16];
            put32(&mut destroy, 12, vm);
            user.store(64, &destroy);
            invoke(&file, &user, abi::GEM_VM_DESTROY).map_err(|_| "VM destroy")?;
            user.store(64, &parameter);
            invoke(&file, &user, abi::GEM_CONTEXT_GETPARAM).map_err(|_| "get retained VM")?;
            let new_vm = u64_at(&user.load(64, 24), 16) as u32;
            if new_vm == vm
                || !Arc::ptr_eq(
                    file.namespaces
                        .lock()
                        .vms
                        .get(&new_vm)
                        .expect("new VM handle"),
                    &old_vm,
                )
            {
                return Err("destroyed VM handle invalidated the context VM owner");
            }
            // A proto-context of the other open, which is the only kind
            // whose VM is settable, cannot name this open's VM.
            user.store(64, &[0; 8]);
            invoke(&other, &user, abi::GEM_CONTEXT_CREATE).map_err(|_| "other create")?;
            put32(&mut parameter, 0, u32_at(&user.load(64, 8), 0));
            put64(&mut parameter, 16, u64::from(new_vm));
            user.store(64, &parameter);
            if invoke(&other, &user, abi::GEM_CONTEXT_SETPARAM) != Err(FsError::NotFound) {
                return Err("foreign VM resolved");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_context_vm_lifetime_and_foreign_ids
    );

    /// MIT Linux b90c984d i915_gem_context.c: set_proto_ctx_vm:366 checks
    /// size (-EINVAL), upper_32_bits and the lookup (-ENOENT) on a
    /// proto-context; ctx_setparam:2190 refuses VM on a finalized one
    /// (-EINVAL) before reading size or value.
    fn smoke_i915_setparam_vm_only_on_a_proto_context() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            user.store(64, &[0; 16]);
            invoke(&file, &user, abi::GEM_VM_CREATE).map_err(|_| "VM create")?;
            let vm = u64::from(u32_at(&user.load(64, 16), 12));
            user.store(64, &[0; 8]);
            invoke(&file, &user, abi::GEM_CONTEXT_CREATE).map_err(|_| "create")?;
            let proto = u32_at(&user.load(64, 8), 0);
            let set = |id: u32, size: u32, value: u64| {
                let mut parameter = [0; 24];
                put32(&mut parameter, 0, id);
                put32(&mut parameter, 4, size);
                put64(&mut parameter, 8, abi::CONTEXT_PARAM_VM);
                put64(&mut parameter, 16, value);
                user.store(64, &parameter);
                invoke(&file, &user, abi::GEM_CONTEXT_SETPARAM)
            };
            // Context 0 is finalized at open.
            for (size, value) in [(0, vm), (1, vm), (0, vm + 1), (0, 1 << 32)] {
                if set(0, size, value) != Err(FsError::InvalidData) {
                    return Err("ctx_setparam accepted VM");
                }
            }
            for (size, value, expected, why) in [
                (1, vm, Err(FsError::InvalidData), "proto size"),
                (0, vm | 1 << 32, Err(FsError::NotFound), "upper_32_bits"),
                (0, vm + 1, Err(FsError::NotFound), "lookup"),
                (0, vm, Ok(0), "proto VM"),
            ] {
                if set(proto, size, value) != expected {
                    return Err(why);
                }
            }
            // GETPARAM's lookup finalizes the proto: its VM is now fixed.
            let mut get = [0; 24];
            put32(&mut get, 0, proto);
            put64(&mut get, 8, abi::CONTEXT_PARAM_VM);
            user.store(64, &get);
            invoke(&file, &user, abi::GEM_CONTEXT_GETPARAM).map_err(|_| "get VM")?;
            if u64_at(&user.load(64, 24), 16) != vm {
                return Err("bound VM");
            }
            if set(proto, 0, vm) != Err(FsError::InvalidData) {
                return Err("finalized context rebound its VM");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_i915_setparam_vm_only_on_a_proto_context
    );

    fn smoke_intel_extension_validation_is_transactional() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 4, 1);
            put64(&mut request, 8, 256);
            let mut extension = [0; 56];
            put64(&mut extension, 0, 256); // cycle
            put64(&mut extension, 40, 4); // NO_ERROR_CAPTURE parameter
            put64(&mut extension, 48, 1);
            user.store(64, &request);
            user.store(256, &extension);
            // i915_user_extensions keeps no visited set: the self-referencing
            // SETPARAM is applied 512 times and the 513th link is -E2BIG.
            if invoke(&file, &user, abi::GEM_CONTEXT_CREATE_EXT)
                != Err(FsError::ArgumentListTooLong)
            {
                return Err("cyclic context extension");
            }
            if file.namespaces.lock().next_context != 1 {
                return Err("invalid extension allocated context");
            }
            put64(&mut extension, 0, 0);
            user.store(256, &extension);
            invoke(&file, &user, abi::GEM_CONTEXT_CREATE_EXT)
                .map_err(|_| "valid context extension")?;
            if !file
                .namespaces
                .lock()
                .contexts
                .get(&1)
                .expect("context")
                .no_error_capture
                .protected()
            {
                return Err("context creation extension ignored");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_extension_validation_is_transactional
    );

    /// Destroys one VM handle from inside the outer ioctl's first copy-in of
    /// the extension link at `at`.
    struct DestroyVmOnRead<'a> {
        file: &'a RenderFile,
        user: &'a User,
        at: u64,
        vm: u32,
        done: core::sync::atomic::AtomicBool,
    }
    impl IoctlContext for DestroyVmOnRead<'_> {
        fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
            if address == self.at && !self.done.swap(true, core::sync::atomic::Ordering::Relaxed) {
                let nested = User::new();
                let mut destroy = [0; 16];
                put32(&mut destroy, 12, self.vm);
                nested.store(64, &destroy);
                invoke(self.file, &nested, abi::GEM_VM_DESTROY).expect("nested VM destroy");
            }
            self.user.read(address, destination)
        }
        fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
            self.user.write(address, source)
        }
        fn nonblocking(&self) -> bool {
            false
        }
        fn pin_user_pages(
            &self,
            address: u64,
            pages: u64,
            writable: bool,
        ) -> Result<Vec<narf_memory::address_space::UserPagePin>, FsError> {
            self.user.pin_user_pages(address, pages, writable)
        }
    }

    /// MIT Linux b90c984d i915_gem_context.c::create_setparam:2265 applies
    /// each SETPARAM link through set_proto_ctx_param:877 as
    /// i915_user_extensions reaches it, and i915_gem_context_create_ioctl
    /// allocates the ID only after the chain. A link's own errno therefore
    /// wins over a later unreadable link, and set_proto_ctx_vm's lookup
    /// happens at its link.
    fn smoke_i915_context_create_ext_applies_each_setparam_at_its_link() -> TestResult {
        check(|| {
            const UNREADABLE: u64 = 0x7fff_0000;
            let file = RenderFile::new();
            let user = User::new();
            user.store(64, &[0; 16]);
            invoke(&file, &user, abi::GEM_VM_CREATE).map_err(|_| "VM create")?;
            let vm = u32_at(&user.load(64, 16), 12);
            // A SETPARAM link: next_extension, then drm_i915_gem_context_param.
            let link = |at: u64, next: u64, size: u32, param: u64, value: u64| {
                let mut ext = [0; 56];
                put64(&mut ext, 0, next);
                put32(&mut ext, 36, size);
                put64(&mut ext, 40, param);
                put64(&mut ext, 48, value);
                user.store(at, &ext);
            };
            let request = |chain: u64| {
                let mut request = [0; 16];
                put32(&mut request, 4, 1);
                put64(&mut request, 8, chain);
                user.store(64, &request);
            };
            let create = |chain: u64| {
                request(chain);
                invoke(&file, &user, abi::GEM_CONTEXT_CREATE_EXT)
            };
            // Each refusal is set_proto_ctx_param's at the first link; the
            // second link's address is unreadable and is never reached.
            for (size, param, value, expected, why) in [
                (1, 4, 1, FsError::InvalidData, "NO_ERROR_CAPTURE size"),
                (1, 9, u64::from(vm), FsError::InvalidData, "VM size"),
                (0, 9, 1 << 32, FsError::NotFound, "VM upper_32_bits"),
                (0, 9, u64::from(vm) + 1, FsError::NotFound, "VM lookup"),
                (31, 7, 0, FsError::InvalidData, "SSEU size"),
                (32, 7, 0, FsError::NoDevice, "SSEU GRAPHICS_VER != 11"),
                (
                    0,
                    abi::CONTEXT_PARAM_LOW_LATENCY,
                    0,
                    FsError::InvalidData,
                    "LOW_LATENCY",
                ),
                (
                    4,
                    abi::CONTEXT_PARAM_ENGINES,
                    0,
                    FsError::InvalidData,
                    "ENGINES size",
                ),
                (0, u64::MAX, 0, FsError::InvalidData, "unknown parameter"),
            ] {
                link(256, UNREADABLE, size, param, value);
                if create(256) != Err(expected) {
                    return Err(why);
                }
            }
            // A link that applies continues the walk into the unreadable one.
            link(256, UNREADABLE, 0, 4, 1);
            if create(256) != Err(FsError::BadAddress) {
                return Err("an applied link did not continue the walk");
            }
            // The first refusing link wins over a later refusing one.
            link(256, 512, 0, 4, 1);
            link(512, 768, 32, 7, 0);
            link(768, UNREADABLE, 0, 9, u64::from(vm) + 1);
            if create(256) != Err(FsError::NoDevice) {
                return Err("a later link's errno won");
            }
            if file.namespaces.lock().next_context != 1 {
                return Err("a failed chain reserved a context name");
            }
            // set_proto_ctx_vm took its reference at the VM link, so the
            // handle's destruction while a later link is read leaves the
            // proto bound to that VM.
            let original = file.namespaces.lock().vms.get(&vm).cloned().ok_or("VM")?;
            link(256, 512, 0, 9, u64::from(vm));
            link(512, 0, 0, 4, 1);
            request(256);
            let reentrant = DestroyVmOnRead {
                file: &file,
                user: &user,
                at: 512 + 12,
                vm,
                done: core::sync::atomic::AtomicBool::new(false),
            };
            file.dispatch(
                &info(Generation::MeteorLake),
                abi::GEM_CONTEXT_CREATE_EXT,
                64,
                &reentrant,
            )
            .expect("Intel command")
            .map_err(|_| "VM destroyed after its link")?;
            let id = u32_at(&user.load(64, 16), 0);
            let namespaces = file.namespaces.lock();
            if namespaces.vms.contains_key(&vm)
                || !Arc::ptr_eq(
                    &namespaces.contexts.get(&id).ok_or("context")?.vm,
                    &original,
                )
            {
                return Err("VM was not resolved at its own link");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_i915_context_create_ext_applies_each_setparam_at_its_link
    );

    /// MIT Linux b90c984d i915_gem_create.c::{i915_gem_create_ext_ioctl,
    /// ext_set_placements,set_placements,ext_set_protected,ext_set_pat}.
    fn smoke_intel_gem_create_ext_follows_linux_table() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let create = |info: &DeviceInfo, flags: u32, extensions: u64, size: u64| {
                let mut request = [0; 24];
                put64(&mut request, 0, size);
                put32(&mut request, 12, flags);
                put64(&mut request, 16, extensions);
                user.store(64, &request);
                file.dispatch(info, abi::GEM_CREATE_EXT, 64, &user)
                    .expect("Intel command")
                    .map(|_| u32_at(&user.load(64, 24), 8))
            };
            let mtl = info(Generation::MeteorLake);
            let tgl = info(Generation::TigerLake);
            // A link at `at` naming `name`, with `next` and its body words.
            let link = |at: u64, next: u64, name: u32, words: &[(usize, u64)]| {
                let mut extension = [0; 48];
                put64(&mut extension, 0, next);
                put32(&mut extension, 8, name);
                for (offset, value) in words {
                    extension[*offset..*offset + 8].copy_from_slice(&value.to_le_bytes());
                }
                user.store(at, &extension);
            };
            // drm_i915_gem_memory_class_instance SYSTEM/0 at 4096.
            user.store(4096, &[0; 8]);
            let regions = |at: u64, next: u64, count: u64, array: u64| {
                link(at, next, 0, &[(32, count << 32), (40, array)]);
            };
            let first = create(&mtl, 0, 0, 4096).map_err(|_| "plain create")?;

            // Unknown flags precede the chain; NEEDS_CPU_ACCESS follows it
            // and, with SYSTEM the only placement, is -EINVAL.
            if create(&mtl, 2, 40000, 4096) != Err(FsError::InvalidData)
                || create(&mtl, 1, 40000, 4096) != Err(FsError::BadAddress)
            {
                return Err("GEM_CREATE_EXT flag order");
            }
            regions(1024, 0, 1, 4096);
            if create(&mtl, 1, 1024, 4096) != Err(FsError::InvalidData)
                || create(&mtl, 1, 0, 4096) != Err(FsError::InvalidData)
            {
                return Err("NEEDS_CPU_ACCESS with one placement");
            }

            // MEMORY_REGIONS: pad, zero and more than INTEL_REGION_UNKNOWN
            // regions are -EINVAL; each region is copied in turn, so a
            // second region is -EFAULT when unreadable and otherwise a
            // missing or duplicate SYSTEM/0 (-EINVAL).
            for (count, pad, array) in [(0, 0, 4096), (8, 0, 4096), (1, 1, 4096)] {
                link(1024, 0, 0, &[(32, count << 32 | pad), (40, array)]);
                if create(&mtl, 0, 1024, 4096) != Err(FsError::InvalidData) {
                    return Err("memory-regions header");
                }
            }
            for (array, expected) in [(32764, FsError::BadAddress), (4096, FsError::InvalidData)] {
                user.store(32764, &[0; 4]);
                regions(1024, 0, 2, array);
                if create(&mtl, 0, 1024, 4096) != Err(expected) {
                    return Err("second region copy");
                }
            }
            user.store(4100, &[1, 0, 0, 0]);
            regions(1024, 0, 1, 4100);
            if create(&mtl, 0, 1024, 4096) != Err(FsError::InvalidData) {
                return Err("missing region");
            }
            // A second MEMORY_REGIONS extension validates its regions
            // first, then finds the placements already set: -EINVAL, as
            // is the same extension visited twice.
            regions(1024, 1088, 1, 4096);
            regions(1088, 0, 1, 32766);
            if create(&mtl, 0, 1024, 4096) != Err(FsError::BadAddress) {
                return Err("second extension's regions");
            }
            regions(1088, 0, 1, 4096);
            if create(&mtl, 0, 1024, 4096) != Err(FsError::InvalidData) {
                return Err("second placement extension");
            }
            regions(1024, 1024, 1, 4096);
            if create(&mtl, 0, 1024, 4096) != Err(FsError::InvalidData) {
                return Err("revisited placement extension");
            }
            regions(1024, 0, 1, 4096);
            let placed = create(&mtl, 0, 1024, 4096).map_err(|_| "SYSTEM placement")?;
            if placed != first + 1 {
                return Err("a refused create consumed a handle");
            }

            // PROTECTED_CONTENT copies 36 bytes, refuses flags, then has no
            // enabled PXP: -ENODEV.
            for (at, flags, expected) in [
                (1024, 1, FsError::InvalidData),
                (1024, 0, FsError::NoDevice),
                (32768 - 32, 0, FsError::BadAddress),
            ] {
                user.store(at, &[0; 32]);
                user.store(at + 8, &1u32.to_le_bytes());
                if at == 1024 {
                    user.store(1056, &(flags as u32).to_le_bytes());
                }
                if create(&mtl, 0, at, 4096) != Err(expected) {
                    return Err("protected content");
                }
            }

            // SET_PAT: before IP 12.70 it is -ENODEV without a copy; on
            // MTL the 40-byte body is copied (-EFAULT) and pat_index above
            // max_pat_index (4) is -EINVAL. The chain goes on past an
            // accepted index, and the object's own size check precedes the
            // index's application.
            user.store(32768 - 32, &[0; 32]);
            user.store(32768 - 24, &2u32.to_le_bytes());
            if create(&tgl, 0, 32768 - 32, 4096) != Err(FsError::NoDevice)
                || create(&mtl, 0, 32768 - 32, 4096) != Err(FsError::BadAddress)
            {
                return Err("SET_PAT gate and copy");
            }
            link(1024, 0, 2, &[(32, 5)]);
            if create(&mtl, 0, 1024, 4096) != Err(FsError::InvalidData) {
                return Err("pat_index above max_pat_index");
            }
            link(1024, 1088, 2, &[(32, 4)]);
            link(1088, 0, 1, &[]);
            if create(&mtl, 0, 1024, 4096) != Err(FsError::NoDevice) {
                return Err("link after SET_PAT");
            }
            link(1024, 0, 2, &[(32, 4)]);
            if create(&mtl, 0, 1024, 0) != Err(FsError::InvalidData) {
                return Err("object size before PAT");
            }
            // Linux sets the index on the new object.
            let pat_handle = create(&mtl, 0, 1024, 4096).map_err(|_| "SET_PAT application")?;
            if file
                .gem
                .object(pat_handle)
                .map_err(|_| "lookup")?
                .pat_index()
                != Some(4)
            {
                return Err("SET_PAT did not set pat_index on object");
            }
            // Names past SET_PAT have no table entry.
            link(1024, 0, 3, &[]);
            if create(&mtl, 0, 1024, 4096) != Err(FsError::InvalidData) {
                return Err("unknown create extension");
            }
            if create(&mtl, 0, 0, 4096) != Ok(placed + 2) {
                return Err("a refused create consumed a handle");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_gem_create_ext_follows_linux_table
    );

    fn smoke_intel_generation_admission_is_independent_of_display() -> TestResult {
        check(|| {
            for entry in crate::intel_gpu::DEVICE_TABLE {
                let expected = match entry.generation {
                    Generation::TigerLake | Generation::AlderLake => SubmissionProfile::Gen12GuC,
                    Generation::MeteorLake => SubmissionProfile::XeLpgGuC,
                    Generation::LunarLake | Generation::PantherLake => {
                        SubmissionProfile::Unsupported
                    }
                };
                if SubmissionProfile::for_generation(entry.generation) != expected {
                    return Err("submission generation dispatch");
                }
                if info(entry.generation).submission_ready() {
                    return Err("display support admitted an uninitialized GT");
                }
            }
            let file = RenderFile::new();
            let user = User::new();
            for param in [9, 18, 35, 37, 44, 50, 53, 55] {
                let mut request = [0; 16];
                put32(&mut request, 0, param);
                put64(&mut request, 8, 256);
                user.store(64, &request);
                invoke(&file, &user, abi::GETPARAM).map_err(|_| "feature query")?;
                if user.load(256, 4) != [0; 4] {
                    return Err("unsupported render capability advertised");
                }
            }
            if invoke(&file, &user, abi::GEM_EXECBUFFER2).is_ok() {
                return Err("uninitialized submission reported success");
            }
            if invoke(&file, &user, abi::GEM_CREATE ^ (1 << 16)) != Err(FsError::InvalidData) {
                return Err("ioctl with wrong size accepted");
            }
            if file
                .dispatch(
                    &info(Generation::MeteorLake),
                    crate::drm_uapi::DRM_IOCTL_VERSION,
                    64,
                    &user,
                )
                .is_some()
            {
                return Err("generic DRM ioctl stolen by Intel");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_generation_admission_is_independent_of_display
    );

    fn smoke_intel_exec_residency_retains_gem_and_maps_xelpg() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let a = file
                .gem
                .create(8192, |_, _| Ok(()))
                .map_err(|_| "allocate data")?;
            let b = file
                .gem
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "allocate batch")?;
            let data = file.gem.object(a).map_err(|_| "data handle")?;
            let batch = file.gem.object(b).map_err(|_| "batch handle")?;
            let data_phys: Vec<_> = data.pages().collect();
            let batch_phys = batch.pages().next().ok_or("batch page")?;
            let mut request = [0; 64];
            put64(&mut request, 0, 256);
            put32(&mut request, 8, 2);
            put32(&mut request, 12, 8);
            put32(&mut request, 16, 8);
            put64(&mut request, 40, 0x1801); // render | NO_RELOC | HANDLE_LUT
            let mut objects = [0; 112];
            put32(&mut objects, 0, a);
            put64(&mut objects, 24, 0x20_0000);
            put64(&mut objects, 32, 0x1c); // WRITE | SUPPORTS_48B | PINNED
            put32(&mut objects, 56, b);
            put64(&mut objects, 80, 0x40_0000);
            put64(&mut objects, 88, 0x18); // SUPPORTS_48B | PINNED
            user.store(64, &request);
            user.store(256, &objects);
            let exec = crate::intel_gpu_exec::ExecRequest::read(&user, 64, &file.gem)
                .map_err(|_| "valid execbuffer")?;
            if exec.batch_va != 0x40_0008 || exec.batch_len != 8 || exec.context_id != 0 {
                return Err("batch selection/extent");
            }
            let gen12 = exec
                .address_space(crate::intel_gpu_gtt::PteFormat::Gen12, 3)
                .map_err(|_| "Gen12 residency")?;
            let xelpg = exec
                .address_space(crate::intel_gpu_gtt::PteFormat::XeLpg, 15)
                .map_err(|_| "Xe-LPG residency")?;
            if gen12.root_phys() == xelpg.root_phys() {
                return Err("VMs share a root table");
            }
            file.gem.close(a).map_err(|_| "data close")?;
            file.gem.close(b).map_err(|_| "batch close")?;
            drop(exec);
            drop(file);
            for space in [&gen12, &xelpg] {
                for (va, physical) in [
                    (0x20_0123, data_phys[0] + 0x123),
                    (0x20_1000, data_phys[1]),
                    (0x40_0008, batch_phys + 8),
                ] {
                    if space.translate(va)
                        != Ok(crate::intel_gpu_ppgtt::WalkOutcome::Mapped(physical))
                    {
                        return Err("owned residency translation after fd close");
                    }
                }
                if !matches!(
                    space.translate(0x30_0000),
                    Ok(crate::intel_gpu_ppgtt::WalkOutcome::NotMapped { .. })
                ) {
                    return Err("unbound address resolved");
                }
            }
            // Both page tables retain the leaf objects independently of the fd.
            if Arc::strong_count(&data) != 3 || Arc::strong_count(&batch) != 3 {
                return Err("residency failed to retain buffer ownership");
            }
            drop(gen12);
            drop(xelpg);
            if Arc::strong_count(&data) != 1 || Arc::strong_count(&batch) != 1 {
                return Err("residency teardown leaked leaf owners");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_exec_residency_retains_gem_and_maps_xelpg
    );

    fn smoke_intel_exec_rejects_hostile_wire_before_vm_changes() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let a = file
                .gem
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "allocate")?;
            let b = file
                .gem
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "allocate")?;
            let mut request = [0; 64];
            put64(&mut request, 0, 256);
            put32(&mut request, 8, 2);
            put32(&mut request, 16, 8);
            put64(&mut request, 40, 0x801);
            let mut objects = [0; 112];
            put32(&mut objects, 0, a);
            put64(&mut objects, 24, 0x20_0000);
            put64(&mut objects, 32, 0x18);
            put32(&mut objects, 56, b);
            put64(&mut objects, 80, 0x40_0000);
            put64(&mut objects, 88, 0x18);
            let parse = |request: &[u8], objects: &[u8]| {
                user.store(64, request);
                user.store(256, objects);
                crate::intel_gpu_exec::ExecRequest::read(&user, 64, &file.gem)
            };
            if parse(&request, &objects).is_err() {
                return Err("baseline execbuffer rejected");
            }
            let mut invalid = request;
            put64(&mut invalid, 40, 0xa01); // privileged SECURE bit
            if parse(&invalid, &objects).is_ok() {
                return Err("secure execution admitted");
            }
            put64(&mut invalid, 40, 0x801);
            put32(&mut invalid, 12, 4096);
            if parse(&invalid, &objects).is_ok() {
                return Err("batch past BO extent");
            }
            invalid = request;
            put32(&mut invalid, 8, 4097);
            if parse(&invalid, &objects).is_ok() {
                return Err("unbounded object list");
            }
            for (field, value) in [
                (80, 0x20_0000),
                (80, 0x0001_0000_0040_0000),
                (80, u64::MAX - 4095),
                (88, 0x10),
                (64, 1),
            ] {
                let mut bad_objects = objects;
                put64(&mut bad_objects, field, value);
                // 0x10 alone is a valid 32-bit pinned object at 4MiB; test
                // that flag separately at an address requiring SUPPORTS_48B.
                if field == 88 {
                    put64(&mut bad_objects, 80, 0x1_0000_0000);
                }
                if parse(&request, &bad_objects).is_ok() {
                    return Err("invalid residency placement/flags accepted");
                }
            }
            let mut duplicate = objects;
            put32(&mut duplicate, 56, a);
            if parse(&request, &duplicate).is_ok() {
                return Err("duplicate GEM object accepted");
            }
            user.store(64, &request);
            user.store(256, &objects);
            if invoke(&file, &user, abi::GEM_EXECBUFFER2) != Err(FsError::NotImplemented) {
                return Err("valid plan bypassed missing GT admission");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_exec_rejects_hostile_wire_before_vm_changes
    );

    fn smoke_intel_pread_pwrite_and_mmap_wire() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let handle = file
                .gem
                .create(24576, |_, _| Ok(()))
                .map_err(|_| "allocate")?;
            let pattern: Vec<_> = (0..20000).map(|i| (i % 251) as u8).collect();
            user.store(1024, &pattern);
            let mut request = [0; 32];
            put32(&mut request, 0, handle);
            put64(&mut request, 8, 4090);
            put64(&mut request, 16, 20000);
            put64(&mut request, 24, 1024);
            user.store(64, &request);
            invoke(&file, &user, abi::GEM_PWRITE).map_err(|_| "chunked pwrite")?;
            user.store(1024, &vec![0; 20000]);
            invoke(&file, &user, abi::GEM_PREAD).map_err(|_| "chunked pread")?;
            if user.load(1024, 20000) != pattern {
                return Err("ioctl copy corrupted cross-page/chunk data");
            }
            put64(&mut request, 8, u64::MAX - 15);
            user.store(64, &request);
            if invoke(&file, &user, abi::GEM_PREAD) != Err(FsError::InvalidData) {
                return Err("pread wrapped its object extent");
            }
            request = [0; 32];
            put32(&mut request, 0, handle);
            put64(&mut request, 16, 2); // WB
            user.store(64, &request);
            invoke(&file, &user, abi::GEM_MMAP_OFFSET).map_err(|_| "WB mmap offset")?;
            let reply = user.load(64, 32);
            if u64_at(&reply, 8) != file.gem.mmap_offset(handle).map_err(|_| "offset")? {
                return Err("mmap wire offset");
            }
            // Linux never checks pad. Extensions are walked with an empty
            // table before the flags: an unreadable link is -EFAULT, a
            // readable one -EINVAL, even under an unsupported flags value.
            put32(&mut request, 4, 0xa5a5_a5a5);
            user.store(64, &request);
            invoke(&file, &user, abi::GEM_MMAP_OFFSET).map_err(|_| "mmap offset pad")?;
            put32(&mut request, 4, 0);
            user.store(30000, &[0; 32]);
            for (flags, extensions, expected) in [
                (2, 40000, FsError::BadAddress),
                (7, 40000, FsError::BadAddress),
                (2, 30000, FsError::InvalidData),
            ] {
                put64(&mut request, 16, flags);
                put64(&mut request, 24, extensions);
                user.store(64, &request);
                if invoke(&file, &user, abi::GEM_MMAP_OFFSET) != Err(expected) {
                    return Err("mmap offset extensions");
                }
            }
            put64(&mut request, 24, 0);
            put64(&mut request, 16, 1); // WC cannot be implemented by a WB RAM alias.
            user.store(64, &request);
            if invoke(&file, &user, abi::GEM_MMAP_OFFSET) != Err(FsError::InvalidData) {
                return Err("incompatible cache alias admitted");
            }
            let mut caching = [0; 8];
            put32(&mut caching, 0, handle);
            put32(&mut caching, 4, 1);
            user.store(64, &caching);
            *user.fail_write.lock() = Some(64);
            if invoke(&file, &user, abi::GEM_SET_CACHING) != Ok(0)
                || invoke(&file, &user, abi::GEM_GET_CACHING) != Err(FsError::BadAddress)
            {
                return Err("SET_CACHING requires only a readable request");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_pread_pwrite_and_mmap_wire
    );

    fn smoke_i915_gem_userptr_creation_and_validation() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();

            // 1. Verify I915_PARAM_HAS_GEM_USERPTR reports 1
            let mut getparam_req = [0; 16];
            put32(&mut getparam_req, 0, 23); // I915_PARAM_HAS_GEM_USERPTR
            put64(&mut getparam_req, 8, 1024);
            user.store(64, &getparam_req);
            invoke(&file, &user, abi::GETPARAM).map_err(|_| "getparam 23")?;
            let val = i32::from_le_bytes(user.load(1024, 4).try_into().unwrap());
            if val != 1 {
                return Err("I915_PARAM_HAS_GEM_USERPTR != 1");
            }

            // 2. Alignment checks: unaligned pointer or unaligned size
            let mut userptr_req = [0; 24];
            put64(&mut userptr_req, 0, 4097); // unaligned ptr
            put64(&mut userptr_req, 8, 4096);
            put32(&mut userptr_req, 16, 0);
            user.store(64, &userptr_req);
            if invoke(&file, &user, abi::GEM_USERPTR) != Err(FsError::InvalidData) {
                return Err("unaligned ptr accepted");
            }

            put64(&mut userptr_req, 0, 4096);
            put64(&mut userptr_req, 8, 4095); // unaligned size
            user.store(64, &userptr_req);
            if invoke(&file, &user, abi::GEM_USERPTR) != Err(FsError::InvalidData) {
                return Err("unaligned size accepted");
            }

            // 3. Zero size check
            put64(&mut userptr_req, 8, 0);
            user.store(64, &userptr_req);
            if invoke(&file, &user, abi::GEM_USERPTR) != Err(FsError::InvalidData) {
                return Err("zero size accepted");
            }

            // 4. Invalid flags check
            put64(&mut userptr_req, 8, 4096);
            put32(&mut userptr_req, 16, 1 << 4); // unknown flag
            user.store(64, &userptr_req);
            if invoke(&file, &user, abi::GEM_USERPTR) != Err(FsError::InvalidData) {
                return Err("invalid flag accepted");
            }

            // 5. Valid creation: Read-Write
            put32(&mut userptr_req, 16, 0);
            user.store(64, &userptr_req);
            invoke(&file, &user, abi::GEM_USERPTR).map_err(|_| "valid userptr")?;
            let reply = user.load(64, 24);
            let handle = u32_at(&reply, 20);
            if handle == 0 {
                return Err("returned zero handle");
            }
            let obj = file.gem.object(handle).map_err(|_| "lookup")?;
            if obj.is_read_only() || !obj.is_userptr() {
                return Err("incorrect read_only or is_userptr state");
            }

            // Userptr cannot be mmapped or exported
            if file.gem.mmap_offset(handle) != Err(FsError::Unsupported) {
                return Err("userptr allowed mmap_offset");
            }
            if !matches!(file.gem.export_object(handle), Err(FsError::InvalidData)) {
                return Err("userptr allowed export");
            }

            // 6. Valid creation: Read-Only
            put64(&mut userptr_req, 0, 8192);
            put64(&mut userptr_req, 8, 4096);
            put32(&mut userptr_req, 16, abi::I915_USERPTR_READ_ONLY);
            user.store(64, &userptr_req);
            invoke(&file, &user, abi::GEM_USERPTR).map_err(|_| "ro userptr")?;
            let ro_handle = u32_at(&user.load(64, 24), 20);
            let ro_obj = file.gem.object(ro_handle).map_err(|_| "lookup ro")?;
            if !ro_obj.is_read_only() {
                return Err("read_only flag not set on object");
            }

            // Writing to read-only object via pwrite fails with PermissionDenied
            let mut pwrite_req = [0; 32];
            put32(&mut pwrite_req, 0, ro_handle);
            put64(&mut pwrite_req, 8, 0);
            put64(&mut pwrite_req, 16, 16);
            put64(&mut pwrite_req, 24, 1024);
            user.store(64, &pwrite_req);
            if invoke(&file, &user, abi::GEM_PWRITE) != Err(FsError::PermissionDenied) {
                return Err("pwrite on read-only userptr accepted");
            }

            // Setting write domain on read-only object fails with InvalidData
            let mut domain_req = [0; 12];
            put32(&mut domain_req, 0, ro_handle);
            put32(&mut domain_req, 4, 1);
            put32(&mut domain_req, 8, 1);
            user.store(64, &domain_req);
            if invoke(&file, &user, abi::GEM_SET_DOMAIN) != Err(FsError::InvalidData) {
                return Err("write domain on read-only userptr accepted");
            }

            // GEM_CLOSE releases the handles
            let mut close_req = [0; 8];
            put32(&mut close_req, 0, handle);
            user.store(64, &close_req);
            invoke(&file, &user, abi::GEM_CLOSE).map_err(|_| "close handle")?;
            if file.gem.object(handle).is_ok() {
                return Err("closed handle still looked up");
            }

            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_i915_gem_userptr_creation_and_validation
    );

    fn smoke_intel_prime_import_identity_offsets_and_mapping_owner() -> TestResult {
        check(|| {
            let exporter = GemState::new();
            let importer = GemState::new();
            let handle = exporter
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "export allocation")?;
            let unrelated = importer
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "importer allocation")?;
            let object = exporter.object(handle).map_err(|_| "export object")?;
            object
                .write(17, &[0x45, 0x67])
                .map_err(|_| "write shared bytes")?;
            let prime = crate::drm_devfs_bridge::intel_dma_buf_file(3, object.clone());
            let imported = crate::drm_devfs_bridge::intel_prime_import(3, &importer, &prime)
                .map_err(|_| "PRIME import")?;
            if imported == unrelated
                || !Arc::ptr_eq(
                    &object,
                    &importer.object(imported).map_err(|_| "imported handle")?,
                )
            {
                return Err("PRIME import replaced another handle or copied identity");
            }
            if crate::drm_devfs_bridge::intel_prime_import(3, &importer, &prime) != Ok(imported)
                || crate::drm_devfs_bridge::intel_prime_import(4, &importer, &prime)
                    != Err(FsError::InvalidData)
            {
                return Err("PRIME reimport identity or cross-card admission");
            }
            let exported_offset = exporter.mmap_offset(handle).map_err(|_| "export offset")?;
            let imported_offset = importer
                .mmap_offset(imported)
                .map_err(|_| "import offset")?;
            let unrelated_offset = importer
                .mmap_offset(unrelated)
                .map_err(|_| "other offset")?;
            if imported_offset != exported_offset || imported_offset == unrelated_offset {
                return Err("import mmap offset collision");
            }
            let mapping = prime.mmap_backing(0, 4096).map_err(|_| "PRIME mmap")?;
            if prime.mmap_backing(4096, 4096).is_ok()
                || mapping.frames != object.pages().collect::<Vec<_>>()
            {
                return Err("PRIME mmap frames or extent");
            }
            exporter.close(handle).map_err(|_| "export GEM_CLOSE")?;
            importer.close(imported).map_err(|_| "import GEM_CLOSE")?;
            drop(exporter);
            drop(importer);
            drop(prime);
            if mapping.lifetime.is_none() || Arc::strong_count(&object) != 2 {
                return Err("PRIME mapping lost backing after all fds closed");
            }
            let mut bytes = [0; 2];
            object.read(17, &mut bytes).map_err(|_| "retained data")?;
            if bytes != [0x45, 0x67] {
                return Err("PRIME storage changed after close");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_prime_import_identity_offsets_and_mapping_owner
    );

    fn smoke_i915_exec_context_order_and_dr4_fixup() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let handle = file.gem.create(4096, |_, _| Ok(())).map_err(|_| "alloc")?;

            // 1. Verify that context validation precedes object resolution.
            // Pass an unknown context ID (0x9999) along with a non-existent GEM handle (0xbeef).
            let mut request = [0; 64];
            put64(&mut request, 0, 256); // objects ptr
            put32(&mut request, 8, 1); // count = 1
            put32(&mut request, 12, 0); // batch start
            put32(&mut request, 16, 8); // batch len
            put64(&mut request, 40, abi::EXEC_NO_RELOC);
            put64(&mut request, 48, 0x9999); // bad context ID

            let mut obj = [0; 56];
            put32(&mut obj, 0, 0xbeef); // non-existent GEM handle
            put64(&mut obj, 24, 0x20_0000);
            put64(&mut obj, 32, abi::OBJECT_PINNED | abi::OBJECT_SUPPORTS_48B);

            user.store(64, &request);
            user.store(256, &obj);

            // Fails with NotFound from context lookup, proving context lookup precedes object lookup.
            if invoke(&file, &user, abi::GEM_EXECBUFFER2) != Err(FsError::NotFound) {
                return Err("context selection must precede object resolution");
            }

            // 2. DR4 fixup writeback on GEM_EXECBUFFER2_WR:
            // UXA submitting DR4 = 0xffffffff is fixed up to 0 and written back on _WR.
            put64(&mut request, 48, 0); // valid default context 0
            put32(&mut request, 24, u32::MAX); // DR4 = 0xffffffff
            put32(&mut obj, 0, handle); // valid handle
            user.store(64, &request);
            user.store(256, &obj);

            let res = invoke(&file, &user, abi::GEM_EXECBUFFER2_WR);
            let written_dr4 = u32_at(&user.load(64, 64), 24);
            if written_dr4 != 0 {
                return Err("DR4 fixup was not written back");
            }
            if res != Err(FsError::NotImplemented) {
                return Err("unexpected execution result");
            }

            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_i915_exec_context_order_and_dr4_fixup
    );

    fn smoke_i915_perf_getparam_and_query_config() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();

            // 1. GETPARAM 54 (PARAM_PERF_REVISION) when no OA device is published -> returns 0
            let mut info_no_oa = info(Generation::MeteorLake);
            info_no_oa.backend = None;
            let mut wire = [0u8; 16];
            put32(&mut wire, 0, abi::PARAM_PERF_REVISION);
            put64(&mut wire, 8, 1024);
            user.store(64, &wire);
            file.dispatch(&info_no_oa, abi::GETPARAM, 64, &user)
                .unwrap()
                .map_err(|_| "getparam without OA")?;
            let val = i32::from_le_bytes(user.load(1024, 4).try_into().unwrap());
            if val != 0 {
                return Err("PARAM_PERF_REVISION must be 0 when no OA unit is published");
            }

            // Backend with an OA device
            struct OaBackend {
                device: crate::intel_gpu_oa::Device,
            }
            impl core::fmt::Debug for OaBackend {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str("OaBackend")
                }
            }
            impl crate::intel_gpu_user::UserBackend for OaBackend {
                fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
                    None
                }
                fn oa_device(&self) -> Option<crate::intel_gpu_oa::Device> {
                    Some(self.device)
                }
                fn submit<'a>(
                    &'a self,
                    _: Arc<crate::intel_gpu_user::UserContext>,
                    _: crate::intel_gpu_user::UserBatch,
                ) -> narf_filesystem::FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>>
                {
                    alloc::boxed::Box::pin(async { Err(FsError::Unsupported) })
                }
            }

            let oa_dev = crate::intel_gpu_oa::Device {
                card: 60,
                platform: GtPlatform::Integrated(Generation::MeteorLake),
                graphics: 1270,
                timestamp: 19_200_000,
                engines: crate::intel_gpu_engine::EngineSet::of(&[
                    crate::intel_gpu_engine::Engine::Rcs0,
                ]),
                reserve: 16 * 1024 * 1024,
                media_engines: None,
                media_timestamp: None,
            };
            let mut info_oa = info(Generation::MeteorLake);
            info_oa.backend = Some(Arc::new(OaBackend { device: oa_dev }));

            // GETPARAM 54 with OA published -> returns 1
            file.dispatch(&info_oa, abi::GETPARAM, 64, &user)
                .unwrap()
                .map_err(|_| "getparam with OA")?;
            let val = i32::from_le_bytes(user.load(1024, 4).try_into().unwrap());
            if val != 1 {
                return Err("PARAM_PERF_REVISION must be 1 when OA unit is published");
            }

            // 2. QUERY item 3 (DRM_I915_QUERY_PERF_CONFIG)
            let run_query = |file: &RenderFile,
                             info: &DeviceInfo,
                             user: &User,
                             subcmd: u32,
                             capacity: i32,
                             data_ptr: u64|
             -> Result<i32, FsError> {
                let mut req = [0u8; 16];
                put32(&mut req, 0, 1);
                put32(&mut req, 4, 0);
                put64(&mut req, 8, 256);
                user.store(64, &req);

                let mut item = [0u8; 24];
                put64(&mut item, 0, abi::QUERY_PERF_CONFIG);
                put32(&mut item, 8, capacity as u32);
                put32(&mut item, 12, subcmd);
                put64(&mut item, 16, data_ptr);
                user.store(256, &item);

                file.dispatch(info, abi::QUERY, 64, user).unwrap()?;
                let out_item = user.load(256, 24);
                let out_length = u32_at(&out_item, 8) as i32;
                Ok(out_length)
            };

            // 2a. QUERY_PERF_CONFIG_LIST (subcmd 1) with 0 configs
            let len = run_query(&file, &info_oa, &user, abi::QUERY_PERF_CONFIG_LIST, 0, 0)
                .map_err(|_| "probe list 0")?;
            if len != 48 {
                return Err("expected list length 48 with 0 configs");
            }

            let mut query_buf = [0u8; 48];
            user.store(1024, &query_buf);
            let len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_LIST,
                48,
                1024,
            )
            .map_err(|_| "query list 0")?;
            if len != 48 {
                return Err("expected returned length 48");
            }
            let n_configs = u64_at(&user.load(1024, 8), 0);
            if n_configs != 0 {
                return Err("expected 0 configs initially");
            }

            // Flags validation: flags at offset 40 MBZ
            put32(&mut query_buf, 40, 1);
            user.store(1024, &query_buf);
            let err_len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_LIST,
                48,
                1024,
            )
            .map_err(|_| "query list bad flags")?;
            if err_len != -22 {
                return Err("expected -22 (EINVAL) for invalid query flags");
            }
            put32(&mut query_buf, 40, 0);

            // 2b. Add config via PERF_ADD_CONFIG
            let mut cfg_raw = [0u8; 72];
            let u1 = *b"12345678-1234-1234-1234-123456789abc";
            cfg_raw[..36].copy_from_slice(&u1);
            put32(&mut cfg_raw, 36, 1); // 1 mux reg
            put32(&mut cfg_raw, 40, 1); // 1 bool reg
            put32(&mut cfg_raw, 44, 0); // 0 flex regs
            put64(&mut cfg_raw, 48, 2048); // mux reg ptr
            put64(&mut cfg_raw, 56, 2080); // bool reg ptr
            put64(&mut cfg_raw, 64, 0); // flex reg ptr
            user.store(1500, &cfg_raw);

            // Mux reg: addr = 0x9888, val = 0x1111
            user.store(2048, &0x9888u32.to_le_bytes());
            user.store(2052, &0x1111u32.to_le_bytes());
            // Bool reg: addr = 0x9888, val = 0x2222
            user.store(2080, &0x9888u32.to_le_bytes());
            user.store(2084, &0x2222u32.to_le_bytes());

            let cfg_id = file
                .dispatch(&info_oa, abi::PERF_ADD_CONFIG, 1500, &user)
                .unwrap()
                .map_err(|_| "PERF_ADD_CONFIG")?;
            if cfg_id < 1 {
                return Err("expected positive config id");
            }

            // 2c. QUERY_PERF_CONFIG_LIST after adding config
            let len = run_query(&file, &info_oa, &user, abi::QUERY_PERF_CONFIG_LIST, 0, 0)
                .map_err(|_| "probe list 1")?;
            if len != 56 {
                return Err("expected list length 56 with 1 config");
            }
            let list_buf = [0u8; 56];
            user.store(1024, &list_buf);
            let len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_LIST,
                56,
                1024,
            )
            .map_err(|_| "query list 1")?;
            if len != 56 {
                return Err("expected returned length 56");
            }
            let out_data = user.load(1024, 56);
            let n_configs = u64_at(&out_data, 0);
            let returned_id = u64_at(&out_data, 48);
            if n_configs != 1 || returned_id != cfg_id {
                return Err("expected 1 config matching cfg_id");
            }

            // 2d. QUERY_PERF_CONFIG_DATA_FOR_ID (subcmd 3)
            let len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_DATA_FOR_ID,
                0,
                0,
            )
            .map_err(|_| "probe data for id")?;
            if len != 120 {
                return Err("expected data length 120 (48 + 72)");
            }

            let mut data_buf = [0u8; 120];
            put64(&mut data_buf, 0, cfg_id);
            put32(&mut data_buf, 48 + 36, 1);
            put32(&mut data_buf, 48 + 40, 1);
            put32(&mut data_buf, 48 + 44, 0);
            put64(&mut data_buf, 48 + 48, 3000);
            put64(&mut data_buf, 48 + 56, 3016);
            user.store(1024, &data_buf);

            let len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_DATA_FOR_ID,
                120,
                1024,
            )
            .map_err(|_| "query data for id")?;
            if len != 120 {
                return Err("expected returned length 120");
            }
            let out_data = user.load(1024, 120);
            if out_data[48..48 + 36] != u1 {
                return Err("config uuid mismatch in query output");
            }
            let mux_out_addr = u32_at(&user.load(3000, 8), 0);
            let mux_out_val = u32_at(&user.load(3000, 8), 4);
            if mux_out_addr != 0x9888 || mux_out_val != 0x1111 {
                return Err("mux register mismatch in query output");
            }

            // Bad ID: returns -2 (ENOENT)
            put64(&mut data_buf, 0, 999999);
            user.store(1024, &data_buf);
            let err_len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_DATA_FOR_ID,
                120,
                1024,
            )
            .map_err(|_| "query bad id")?;
            if err_len != -2 {
                return Err("expected -2 (ENOENT) for invalid config id");
            }

            // 2e. QUERY_PERF_CONFIG_DATA_FOR_UUID (subcmd 2)
            let mut uuid_buf = [0u8; 120];
            uuid_buf[..36].copy_from_slice(&u1);
            put32(&mut uuid_buf, 48 + 36, 1);
            put32(&mut uuid_buf, 48 + 40, 1);
            put64(&mut uuid_buf, 48 + 48, 3000);
            put64(&mut uuid_buf, 48 + 56, 3016);
            user.store(1024, &uuid_buf);

            let len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_DATA_FOR_UUID,
                120,
                1024,
            )
            .map_err(|_| "query data for uuid")?;
            if len != 120 {
                return Err("expected returned length 120 for uuid query");
            }

            // Bad UUID: returns -2 (ENOENT)
            uuid_buf[..36].copy_from_slice(b"00000000-0000-0000-0000-000000000000");
            user.store(1024, &uuid_buf);
            let err_len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_DATA_FOR_UUID,
                120,
                1024,
            )
            .map_err(|_| "query bad uuid")?;
            if err_len != -2 {
                return Err("expected -2 (ENOENT) for invalid config uuid");
            }

            // 2f. PERF_REMOVE_CONFIG
            user.store(1600, &cfg_id.to_le_bytes());
            file.dispatch(&info_oa, abi::PERF_REMOVE_CONFIG, 1600, &user)
                .unwrap()
                .map_err(|_| "PERF_REMOVE_CONFIG")?;

            let len = run_query(&file, &info_oa, &user, abi::QUERY_PERF_CONFIG_LIST, 0, 0)
                .map_err(|_| "probe list after remove")?;
            if len != 48 {
                return Err("expected list length 48 after remove");
            }
            put64(&mut data_buf, 0, cfg_id);
            user.store(1024, &data_buf);
            let err_len = run_query(
                &file,
                &info_oa,
                &user,
                abi::QUERY_PERF_CONFIG_DATA_FOR_ID,
                120,
                1024,
            )
            .map_err(|_| "query removed id")?;
            if err_len != -2 {
                return Err("expected -2 (ENOENT) for removed config id");
            }

            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_i915_perf_getparam_and_query_config
    );

    /// HOLD_PREEMPTION refcount: two hold streams pinning one context
    /// must not drop each other's hold when the first stream closes.
    /// A non-hold pin records nothing for the execbuffer path, and
    /// releasing a non-held id is a no-op, not an underflow.
    fn smoke_oa_hold_preemption_refcount() -> TestResult {
        let mut namespaces = Namespaces::new();
        assert!(!namespaces.oa_pin(0, true));
        assert!(!namespaces.oa_pin(7, true));
        assert!(!namespaces.oa_holds_preemption(7));
        namespaces
            .contexts
            .insert(7, Context::new(Arc::new(Vm { _identity: 0 }), true));
        assert!(namespaces.oa_pin(7, false));
        assert!(!namespaces.oa_holds_preemption(7));
        assert!(namespaces.oa_pin(7, true));
        assert!(namespaces.oa_pin(7, true));
        assert!(namespaces.oa_holds_preemption(7));
        namespaces.oa_unpin_hold(7);
        assert!(namespaces.oa_holds_preemption(7));
        namespaces.oa_unpin_hold(7);
        assert!(!namespaces.oa_holds_preemption(7));
        namespaces.oa_unpin_hold(7);
        assert!(!namespaces.oa_holds_preemption(7));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_oa_hold_preemption_refcount
    );

    include!("intel_gpu_sync_tests.rs");
    mod discovery {
        include!("intel_gpu_i915_info_tests.rs");
    }
}
