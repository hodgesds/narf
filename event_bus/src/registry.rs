//! Topic registry. Stores `(name_hash, TopicEntry)` and mints the
//! per-topic `(Cap<EventPublisher>, Cap<EventSubscriber>)` pair on
//! `create_topic`. Indexed by name hash so lookup is O(N) over a
//! small N for Phase 1 — every topic carries the full name so
//! collisions are detectable. Phase 3 swaps to a real hash table.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::TypeId;

use narf_capabilities::{
    object_table, Cap, CapKind, CapSlot, Invoke, Read, Rights, Write,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::audit::{publish_audit_mint, AuditOp};
use crate::cap::{Publisher as PublisherCap, Subscriber as SubscriberCap, TopicRegistry};
use crate::engine::Ring;
use crate::payload::{Arena, Event};
use crate::publisher::Publisher;
use crate::subscriber::Subscriber;
use crate::topic::TopicName;

/// Topic identifier — a stable handle returned by `create_topic` and
/// usable for diagnostics. Internally an index into the topics vec.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TopicId(pub u32);

/// Errors from `create_topic`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CreateError {
    /// The cap presented is not live.
    CapRevoked,
    /// A topic with this name already exists.
    NameTaken,
    /// Name failed validation (see `topic::NameError`).
    InvalidName,
    /// Reserved-root prefix can't be minted by a non-kernel cap.
    Reserved,
    /// Capacity not a power of two, or zero.
    BadCapacity,
    /// Payload type mismatch — caller asked for `T` but an existing
    /// topic of this name was minted with a different `T`.
    PayloadMismatch,
}

/// Errors from `lookup_topic`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LookupError {
    CapRevoked,
    NotFound,
    PayloadMismatch,
    /// Subscription to `system.security.audit` requires
    /// `audit_subscribe_kernel`; userspace cap is rejected.
    AdminOnly,
}

/// One topic entry. The `ring` is a type-erased `Arc<dyn Any>` so we
/// can store heterogenous topics in one Vec; the typed `Publisher` /
/// `Subscriber` recover the concrete `Arc<Ring<T>>` via `TypeId`
/// matching.
pub(crate) struct TopicEntry {
    pub name: TopicName,
    pub name_hash: u64,
    pub payload_type: TypeId,
    /// Ring as a type-erased Arc. Concrete type is `Arc<Ring<T>>`
    /// for the topic's payload `T`; the constructor checks via the
    /// stored `payload_type`.
    pub ring_any: Arc<dyn core::any::Any + Send + Sync>,
    /// Per-topic arena for variable payloads. Optional — topics that
    /// only carry fixed-size events never allocate one.
    pub arena: Option<Arc<Arena>>,
    /// Index in the object table for the publisher cap.
    pub pub_index: u32,
    /// Index in the object table for the subscriber cap (template;
    /// each subscribe call bootstraps its own subscriber cap, so
    /// this is the audit-target for revocation policy).
    pub sub_index: u32,
    /// `true` if the topic name's root is in `RESERVED_ROOTS`.
    pub is_privileged: bool,
    /// `true` if this is the audit topic itself — gates subscribe.
    pub is_audit: bool,
}

impl core::fmt::Debug for TopicEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TopicEntry")
            .field("name", &self.name)
            .field("payload_type", &self.payload_type)
            .field("is_privileged", &self.is_privileged)
            .field("is_audit", &self.is_audit)
            .finish_non_exhaustive()
    }
}

struct Registry {
    topics: Vec<Arc<TopicEntry>>,
    /// Publisher cap for the audit topic (if init has run). Held by
    /// the registry itself; never handed out.
    audit_pub: Option<Publisher<crate::audit::AuditEvent>>,
    /// Subscriber-cap-index of the audit topic — used to gate
    /// `audit_subscribe_kernel`.
    audit_sub_index: Option<u32>,
    /// Set after `init()` runs so re-entrant boot paths don't
    /// double-create the audit topic.
    inited: bool,
}

impl Registry {
    const fn new() -> Self {
        Self {
            topics: Vec::new(),
            audit_pub: None,
            audit_sub_index: None,
            inited: false,
        }
    }
}

static REG: IrqSafeSpinLock<Registry> = IrqSafeSpinLock::new(Registry::new());

/// Initialise the bus. Creates the audit topic and parks its
/// publisher in the registry. Idempotent.
pub fn init() {
    let mut g = REG.lock();
    if g.inited {
        return;
    }
    g.inited = true;
    // Drop the guard so the recursive create_topic / mint paths can
    // re-take the lock cleanly.
    drop(g);

    // The audit topic is kernel-minted with reserved-root authority.
    // We bypass the create_topic privilege check by manufacturing a
    // synthetic kernel registry cap with `Write` rights.
    let reg_cap: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let res = create_topic_inner::<crate::audit::AuditEvent>(
        &reg_cap.slot(),
        Write::BITS,
        "system.security.audit",
        256,
        None,
        /*is_audit=*/ true,
    );
    match res {
        Ok((publisher, sub_index)) => {
            let mut g = REG.lock();
            g.audit_pub = Some(publisher);
            g.audit_sub_index = Some(sub_index);
        }
        Err(_) => {
            // Init failure is a bus bring-up bug; leaving the bus
            // uninited so subsequent `init()` calls retry is the
            // safest fallback.
            let mut g = REG.lock();
            g.inited = false;
        }
    }
}

/// `Cap<TopicRegistry, Write>` authority — mint a new topic with
/// payload type `T` and ring capacity `capacity` (power of two).
///
/// Reserved-root names (`kernel.`, `system.`, …) require the cap to
/// be a kernel-minted cap. Phase 1 cheats: any holder of
/// `Cap<TopicRegistry, Write>` is treated as kernel for prefix
/// purposes since the registry-write cap is itself bootstrapped only
/// during boot — a follow-up phase will tag caps with their minting
/// domain.
///
/// Returns a `Publisher<T>` handle (single-owner) — the matching
/// `Subscriber<T>` is obtained via `lookup_topic`.
pub fn create_topic<T: Event>(
    cap: &Cap<TopicRegistry, Write>,
    name: &str,
    capacity: usize,
) -> Result<(TopicId, Publisher<T>), CreateError> {
    if cap.check_live().is_err() {
        return Err(CreateError::CapRevoked);
    }
    let (publisher, _sub_idx) =
        create_topic_inner::<T>(&cap.slot(), Write::BITS, name, capacity, None, false)?;
    let id = publisher.topic_id();
    Ok((id, publisher))
}

/// Same as `create_topic`, but the topic also gets an arena for
/// variable-size payloads. `arena_slot_bytes` is the per-slot
/// capacity; the arena gets `capacity` slots in step with the ring.
pub fn create_topic_with_arena<T: Event>(
    cap: &Cap<TopicRegistry, Write>,
    name: &str,
    capacity: usize,
    arena_slot_bytes: usize,
) -> Result<(TopicId, Publisher<T>), CreateError> {
    if cap.check_live().is_err() {
        return Err(CreateError::CapRevoked);
    }
    let (publisher, _sub_idx) = create_topic_inner::<T>(
        &cap.slot(),
        Write::BITS,
        name,
        capacity,
        Some(arena_slot_bytes),
        false,
    )?;
    let id = publisher.topic_id();
    Ok((id, publisher))
}

fn create_topic_inner<T: Event>(
    _cap_slot: &CapSlot,
    rights_bits: u32,
    name: &str,
    capacity: usize,
    arena_slot_bytes: Option<usize>,
    is_audit: bool,
) -> Result<(Publisher<T>, u32), CreateError> {
    let parsed = TopicName::parse(name).map_err(|_| CreateError::InvalidName)?;
    if !capacity.is_power_of_two() || capacity == 0 {
        return Err(CreateError::BadCapacity);
    }
    let hash = parsed.hash();
    let is_privileged = parsed.is_reserved();
    if is_privileged && rights_bits != Write::BITS {
        // Reserved roots need Write authority (the kernel-minted
        // registry cap). Read-only cap can lookup but not mint.
        return Err(CreateError::Reserved);
    }
    if !is_privileged && !parsed.is_user() {
        // Neither reserved nor user prefix — reject so we don't
        // accidentally allow arbitrary topic creation.
        return Err(CreateError::Reserved);
    }

    let payload_type = TypeId::of::<T>();
    let ring: Arc<Ring<T>> = Arc::new(Ring::new(capacity));
    let arena = arena_slot_bytes.map(|sb| Arc::new(Arena::new(capacity, sb)));

    // Mint publisher + subscriber object-table entries up front so
    // we record the indices for revocation tracking.
    let (pub_index, pub_gen) = object_table::register(CapKind::EventPublisher);
    let (sub_index, _sub_gen) = object_table::register(CapKind::EventSubscriber);

    let entry = Arc::new(TopicEntry {
        name: parsed,
        name_hash: hash,
        payload_type,
        ring_any: ring.clone() as Arc<dyn core::any::Any + Send + Sync>,
        arena: arena.clone(),
        pub_index,
        sub_index,
        is_privileged,
        is_audit,
    });

    let mut g = REG.lock();
    // Duplicate name check.
    for t in g.topics.iter() {
        if t.name_hash == hash && t.name == entry.name {
            return Err(CreateError::NameTaken);
        }
    }
    g.topics.push(entry.clone());
    let topic_id = TopicId((g.topics.len() - 1) as u32);
    drop(g);

    let publisher_cap_slot = CapSlot::new(
        pub_gen,
        pub_index,
        Invoke::BITS,
        CapKind::EventPublisher as u32,
    );
    // SAFETY: We just registered this slot in the object table;
    // type_tag matches CapKind::EventPublisher.
    let publisher_cap: Cap<PublisherCap, Invoke> = unsafe { Cap::mint(publisher_cap_slot) };
    let publisher = Publisher::new(publisher_cap, ring, arena, topic_id);

    // Audit topic creation. Suppress the audit emit when we're
    // creating the audit topic itself to avoid an init-time
    // self-publish before the publisher field is set.
    if is_privileged && !is_audit {
        publish_audit_mint(AuditOp::Mint, CapKind::EventPublisher, entry.name);
        publish_audit_mint(AuditOp::Mint, CapKind::EventSubscriber, entry.name);
    }

    Ok((publisher, sub_index))
}

/// Look up an existing topic by name and mint a fresh
/// `Subscriber<T>`. Cap-gated: `Cap<TopicRegistry, Read>` is the
/// minimal required authority. Subscribing to
/// `system.security.audit` is forbidden through this path; use
/// `audit_subscribe_kernel` instead.
pub fn lookup_topic<T: Event>(
    cap: &Cap<TopicRegistry, Read>,
    name: &str,
) -> Result<Subscriber<T>, LookupError> {
    if cap.check_live().is_err() {
        return Err(LookupError::CapRevoked);
    }
    let parsed = TopicName::parse(name).map_err(|_| LookupError::NotFound)?;
    let hash = parsed.hash();
    let entry = find_entry(hash, &parsed).ok_or(LookupError::NotFound)?;
    if entry.is_audit {
        return Err(LookupError::AdminOnly);
    }
    if entry.payload_type != TypeId::of::<T>() {
        return Err(LookupError::PayloadMismatch);
    }
    let ring = entry
        .ring_any
        .clone()
        .downcast::<Ring<T>>()
        .map_err(|_| LookupError::PayloadMismatch)?;
    let cursor = ring.attach_cursor();
    let (sub_idx, sub_gen) = object_table::register(CapKind::EventSubscriber);
    let sub_cap_slot = CapSlot::new(
        sub_gen,
        sub_idx,
        Invoke::BITS,
        CapKind::EventSubscriber as u32,
    );
    // SAFETY: just minted the slot.
    let sub_cap: Cap<SubscriberCap, Invoke> = unsafe { Cap::mint(sub_cap_slot) };
    Ok(Subscriber::new(sub_cap, ring, entry.arena.clone(), cursor))
}

/// Kernel-only path to subscribe to `system.security.audit`. The
/// `cap` must be a `Cap<TopicRegistry, Write>` — same authority that
/// minted privileged topics — so userspace subscribe is rejected at
/// the type level (userspace holds `Cap<TopicRegistry, Read>` only).
pub fn audit_subscribe_kernel(
    cap: &Cap<TopicRegistry, Write>,
) -> Result<Subscriber<crate::audit::AuditEvent>, LookupError> {
    if cap.check_live().is_err() {
        return Err(LookupError::CapRevoked);
    }
    let g = REG.lock();
    let audit_idx = g.audit_sub_index.ok_or(LookupError::NotFound)?;
    // Find the audit topic entry.
    let entry = g
        .topics
        .iter()
        .find(|e| e.sub_index == audit_idx)
        .cloned()
        .ok_or(LookupError::NotFound)?;
    drop(g);
    let ring = entry
        .ring_any
        .clone()
        .downcast::<Ring<crate::audit::AuditEvent>>()
        .map_err(|_| LookupError::PayloadMismatch)?;
    let cursor = ring.attach_cursor();
    let (sub_idx, sub_gen) = object_table::register(CapKind::EventSubscriber);
    let sub_cap_slot = CapSlot::new(
        sub_gen,
        sub_idx,
        Invoke::BITS,
        CapKind::EventSubscriber as u32,
    );
    // SAFETY: just minted the slot.
    let sub_cap: Cap<SubscriberCap, Invoke> = unsafe { Cap::mint(sub_cap_slot) };
    Ok(Subscriber::new(sub_cap, ring, entry.arena.clone(), cursor))
}

/// Internal: borrow the audit publisher. Returns `None` until
/// `init()` has run. Used by `audit::publish_audit_mint`.
pub(crate) fn audit_publisher() -> Option<Publisher<crate::audit::AuditEvent>> {
    REG.lock().audit_pub.clone()
}

fn find_entry(hash: u64, name: &TopicName) -> Option<Arc<TopicEntry>> {
    let g = REG.lock();
    g.topics
        .iter()
        .find(|e| e.name_hash == hash && &e.name == name)
        .cloned()
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut g = REG.lock();
    g.topics.clear();
    g.audit_pub = None;
    g.audit_sub_index = None;
    g.inited = false;
}
