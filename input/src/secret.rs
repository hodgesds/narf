//! Secret key entry: keystrokes that only a boot-time credential prompt
//! may see.
//!
//! A LUKS passphrase typed at the boot prompt must not reach anything
//! else: not the console key ring the VT line discipline reads, and not
//! any evdev node, whose ring keeps events with or without a reader. A
//! later `/dev/input/event*` reader could otherwise replay the
//! passphrase. While a [`SecretEntry`] is held:
//!
//! - every `InputEvent::Key` that reaches [`crate::push_global`] (each
//!   keyboard driver's single entry, via [`crate::push_key`]) goes into
//!   a small private queue instead of `KEY_RING`;
//! - [`crate::evdev::DeviceNode::dispatch`] drops keyboard `EV_KEY`
//!   codes and `EV_MSC` scan codes. Pointer buttons (`BTN_*`, 0x100 to
//!   0x15f) and every other event class still pass, so a mouse keeps
//!   working.
//!
//! Dropping the guard clears the queue and ends the mode. Queue slots
//! are overwritten with volatile stores when they are popped and when
//! the guard drops, so no keystroke stays in the static after the
//! prompt.
//!
//! Linux has no in-kernel equivalent: its passphrase prompts
//! (`systemd-ask-password`, cryptsetup) run in an initramfs userspace
//! that owns the tty. NARF unlocks the root in the kernel, before PID 1,
//! so the kernel supplies the isolation.

use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{KeyCode, KeyEvent, Modifiers};

/// Queue depth. A prompt drains the queue on every poll, so this only has
/// to absorb the keys one poll interval can deliver.
const QUEUE_LEN: usize = 64;

const BLANK: KeyEvent = KeyEvent {
    code: KeyCode::Reserved,
    pressed: false,
    modifiers: Modifiers::from_bits_truncate(0),
};

struct Queue {
    slots: [KeyEvent; QUEUE_LEN],
    head: usize,
    len: usize,
}

impl Queue {
    const fn new() -> Self {
        Self {
            slots: [BLANK; QUEUE_LEN],
            head: 0,
            len: 0,
        }
    }

    fn push(&mut self, ev: KeyEvent) -> bool {
        if self.len == QUEUE_LEN {
            return false;
        }
        let at = (self.head + self.len) % QUEUE_LEN;
        self.slots[at] = ev;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<KeyEvent> {
        if self.len == 0 {
            return None;
        }
        let slot = &mut self.slots[self.head];
        let ev = *slot;
        wipe(slot);
        self.head = (self.head + 1) % QUEUE_LEN;
        self.len -= 1;
        Some(ev)
    }

    fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            wipe(slot);
        }
        self.head = 0;
        self.len = 0;
    }
}

fn wipe(slot: &mut KeyEvent) {
    // SAFETY: `slot` is a valid, aligned, exclusive reference; the
    // volatile store only keeps the compiler from eliding the overwrite
    // of a slot nothing reads again.
    unsafe { core::ptr::write_volatile(slot, BLANK) };
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static QUEUE: IrqSafeSpinLock<Queue> = IrqSafeSpinLock::new(Queue::new());
static DROPPED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Proof that secret key entry is active. Dropping it clears every
/// queued keystroke and returns keyboards to their normal consumers.
#[derive(Debug)]
pub struct SecretEntry {
    _private: (),
}

impl Drop for SecretEntry {
    fn drop(&mut self) {
        // Leave the mode before wiping. A key arriving after the store goes
        // to the public ring (it was typed after the prompt ended), and a
        // `divert` racing the drop re-checks the mode under the queue lock,
        // so nothing can land in the queue after the wipe below.
        ACTIVE.store(false, Ordering::Release);
        QUEUE.lock().clear();
    }
}

/// Begin secret key entry. `None` if another prompt already holds it;
/// there is one console, so prompts take turns.
pub fn begin_secret_entry() -> Option<SecretEntry> {
    if ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    QUEUE.lock().clear();
    Some(SecretEntry { _private: () })
}

/// Whether secret key entry is active.
pub fn secret_entry_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Pop the oldest secret keystroke. The slot is wiped as it is read.
pub fn pop_secret_key() -> Option<KeyEvent> {
    QUEUE.lock().pop()
}

/// Keystrokes lost to a full queue during secret entry, for diagnostics
/// that must not reveal which keys they were.
pub fn secret_keys_dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Divert one key event into the secret queue. Returns `false` when the
/// mode is off, so the caller routes the event normally. A full queue
/// drops the key (counted): it must not fall through to the public ring.
pub(crate) fn divert(ev: KeyEvent) -> bool {
    if !secret_entry_active() {
        return false;
    }
    let mut q = QUEUE.lock();
    // Re-check under the lock: the guard's drop clears the queue only
    // after turning the mode off.
    if !secret_entry_active() {
        return false;
    }
    if !q.push(ev) {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    true
}

/// Whether an evdev event must be withheld from evdev nodes while secret
/// entry is active: keyboard key codes (below `BTN_MISC`, or from
/// `KEY_OK` up) and `EV_MSC` events, which carry the HID usage or
/// scancode of a key.
pub(crate) fn withhold_evdev(type_: crate::evdev::EventType, code: u16) -> bool {
    use crate::evdev::EventType;
    if !secret_entry_active() {
        return false;
    }
    match type_ {
        EventType::Key => !(0x100..0x160).contains(&code),
        EventType::Msc => true,
        _ => false,
    }
}

// ── Polled keyboards ─────────────────────────────────────────────────

const MAX_POLLERS: usize = 4;

/// The registered keyboard poll functions, in registration order.
pub type KeyboardPollers = [Option<fn()>; MAX_POLLERS];

static POLLERS: IrqSafeSpinLock<KeyboardPollers> = IrqSafeSpinLock::new([None; MAX_POLLERS]);

/// Register a keyboard controller's poll function: it moves whatever
/// bytes the controller holds through the driver's normal decoder, which
/// ends in [`crate::push_key`]. A boot-time prompt calls
/// [`poll_keyboards`] while interrupts are masked (the initcalls run with
/// the BSP's IRQs off), when no IRQ handler would ever see the keys.
/// Registering the same function twice is a no-op. Returns `false` when
/// every slot is taken.
pub fn register_keyboard_poller(poll: fn()) -> bool {
    let mut slots = POLLERS.lock();
    if slots
        .iter()
        .flatten()
        .any(|p| core::ptr::fn_addr_eq(*p, poll))
    {
        return true;
    }
    match slots.iter_mut().find(|s| s.is_none()) {
        Some(slot) => {
            *slot = Some(poll);
            true
        }
        None => false,
    }
}

/// Run every registered keyboard poller once. The poll functions run
/// without the registry lock held.
pub fn poll_keyboards() {
    let pollers = *POLLERS.lock();
    for poll in pollers.iter().flatten() {
        poll();
    }
}

/// Test-only: empty the poller registry, returning what it held so the
/// test can put the production pollers back.
#[doc(hidden)]
pub fn __take_keyboard_pollers_for_test() -> KeyboardPollers {
    core::mem::replace(&mut *POLLERS.lock(), [None; MAX_POLLERS])
}

/// Test-only: restore a registry saved by
/// [`__take_keyboard_pollers_for_test`].
#[doc(hidden)]
pub fn __restore_keyboard_pollers_for_test(saved: KeyboardPollers) {
    *POLLERS.lock() = saved;
}
