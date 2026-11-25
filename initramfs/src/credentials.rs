//! Bounded, opt-in early-boot passphrase prompts (`rd.luks.prompt=`).
//!
//! These run inside the Late `root-mount-auto` initcall: no userspace or
//! USB task runs yet and the BSP's interrupts are still masked, so the
//! prompt polls its inputs instead of waiting for an IRQ.
//!
//! - `serial`: bytes from the serial console only.
//! - `console`: the keyboard as well. The prompt holds
//!   [`narf_input::SecretEntry`] while it reads, so each keystroke reaches
//!   only this prompt: not the console key ring, not any evdev node. It
//!   polls the keyboard controllers itself
//!   ([`narf_input::poll_keyboards`]) and translates keys with the US
//!   layout ([`narf_input::key_to_ascii`]), GRUB's default keymap.
//!
//! Neither mode echoes. Enter submits a non-empty line, Backspace deletes
//! one byte, Ctrl-U clears the line, Escape or Ctrl-C cancels. The entered
//! bytes live in one preallocated, zeroized buffer that never grows.

use alloc::vec::Vec;
use core::{fmt::Write, task::Poll};
use narf_block::encrypted::{LuksCredentialError as Error, LuksVolumeInfo};
use narf_input::{KeyCode, KeyEvent, Modifiers};
use zeroize::Zeroizing;

const MAX_PASSPHRASE: usize = 512;

/// Console level of the prompt: KERN_ALERT, "action must be taken
/// immediately". The user has to type, so the prompt must stay visible
/// under `quiet` (console level 4) and the common `quiet loglevel=3`.
const PROMPT_LEVEL: u32 = 1;
type PromptWriter = narf_console::PriorityWriter<PROMPT_LEVEL>;

/// Where a prompt reads keystrokes from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Serial,
    Console,
}

impl Source {
    /// The `rd.luks.prompt=` value naming this source.
    pub(super) fn from_arg(value: &str) -> Option<Self> {
        match value {
            "serial" => Some(Self::Serial),
            "console" => Some(Self::Console),
            _ => None,
        }
    }
}

pub(super) fn serial_provider(volume: &LuksVolumeInfo) -> Result<Zeroizing<Vec<u8>>, Error> {
    prompt(volume, Source::Serial)
}

pub(super) fn console_provider(volume: &LuksVolumeInfo) -> Result<Zeroizing<Vec<u8>>, Error> {
    prompt(volume, Source::Console)
}

/// What one input byte did to the line.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    More,
    Done,
    Cancelled,
    TooLarge,
}

/// The prompt's line editor over input bytes (serial bytes, or keys
/// translated by [`key_byte`]).
pub(crate) struct LineEditor {
    // Preallocated once and never grown: growing a Vec could leave an
    // unzeroized copy of the secret in a freed allocation.
    line: Zeroizing<Vec<u8>>,
}

impl LineEditor {
    pub(crate) fn new() -> Self {
        Self {
            line: Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE)),
        }
    }

    pub(crate) fn feed(&mut self, byte: u8) -> Step {
        match byte {
            3 | 27 => Step::Cancelled,
            b'\r' | b'\n' if !self.line.is_empty() => Step::Done,
            8 | 127 => {
                if let Some(last) = self.line.last_mut() {
                    *last = 0;
                }
                self.line.pop();
                Step::More
            }
            // Ctrl-U, the tty kill character: clear the whole line.
            0x15 => {
                self.line.iter_mut().for_each(|b| *b = 0);
                self.line.clear();
                Step::More
            }
            0x20..=0x7e => {
                if self.line.len() == MAX_PASSPHRASE {
                    return Step::TooLarge;
                }
                self.line.push(byte);
                Step::More
            }
            _ => Step::More,
        }
    }

    pub(crate) fn into_secret(self) -> Zeroizing<Vec<u8>> {
        self.line
    }
}

/// The line-editor byte a key press stands for. Releases, modifier keys
/// and chords with Alt or Meta give nothing. With Ctrl, only C (cancel)
/// and U (clear) mean anything: a Ctrl chord never inserts its letter.
pub(crate) fn key_byte(key: KeyEvent) -> Option<u8> {
    if !key.pressed
        || key.modifiers.contains(Modifiers::ALT)
        || key.modifiers.contains(Modifiers::META)
    {
        return None;
    }
    if key.modifiers.contains(Modifiers::CTRL) {
        return match key.code {
            KeyCode::C => Some(3),
            KeyCode::U => Some(0x15),
            _ => None,
        };
    }
    narf_input::key_to_ascii(key.code, key.modifiers)
}

fn prompt(volume: &LuksVolumeInfo, source: Source) -> Result<Zeroizing<Vec<u8>>, Error> {
    let args = narf_boot::args();
    let selected = args.value("rd.luks.uuid").ok_or(Error::Unavailable)?;
    let timeout_ms = args
        .value("rd.luks.timeout")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(90)
        .clamp(1, 300)
        * 1000;
    read_passphrase(volume, source, selected, timeout_ms)
}

/// The prompt for `volume` when `rd.luks.uuid=` is `selected` (with or
/// without its `luks-` prefix): `Declined` for any other container.
pub(crate) fn read_passphrase(
    volume: &LuksVolumeInfo,
    source: Source,
    selected: &str,
    timeout_ms: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let selected = selected.strip_prefix("luks-").unwrap_or(selected);
    if narf_block::partition::parse_uuid(selected).is_none()
        || !selected.eq_ignore_ascii_case(&volume.uuid)
    {
        return Err(Error::Declined);
    }
    // One prompt owns the keyboard at a time.
    let secret_entry = match source {
        Source::Console => Some(narf_input::begin_secret_entry().ok_or(Error::Unavailable)?),
        Source::Serial => None,
    };
    let deadline = narf_time::Deadline::after_ms(timeout_ms);
    let how = match source {
        Source::Serial => "serial; no echo",
        Source::Console => "no echo",
    };
    let _ = write!(
        PromptWriter {},
        "\nLUKS {} passphrase ({how}): ",
        volume.uuid
    );
    let mut editor = LineEditor::new();
    let result = narf_scheduler::block_on_spin(core::future::poll_fn(|cx| {
        if deadline.expired() {
            return Poll::Ready(Err(Error::TimedOut));
        }
        let finish = |step| match step {
            Step::More => None,
            Step::Done => Some(Ok(())),
            Step::Cancelled => Some(Err(Error::Cancelled)),
            Step::TooLarge => Some(Err(Error::TooLarge)),
        };
        // Use the IRQ handler's producer lock as well: independently reading
        // the UART after an empty-ring check could reorder bytes if an IRQ
        // enqueues an earlier byte between those operations. Subsys has
        // initialized the ring before root mounting enters this Late path.
        narf_input::fill_byte_ring(narf_console::try_read_byte, 256);
        while let Some(byte) = narf_input::pop_ascii_byte() {
            if let Some(done) = finish(editor.feed(byte)) {
                return Poll::Ready(done);
            }
        }
        if source == Source::Console {
            narf_input::poll_keyboards();
            while let Some(key) = narf_input::pop_secret_key() {
                if let Some(done) = key_byte(key).and_then(|byte| finish(editor.feed(byte))) {
                    return Poll::Ready(done);
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }));
    if let Some(entry) = secret_entry {
        // Drain what the controllers still hold (the Enter release, keys
        // typed past Enter) while the keys still go to the secret queue,
        // which dropping the guard wipes. A byte left in the controller
        // would reach the IRQ handler once interrupts are on.
        narf_input::poll_keyboards();
        drop(entry);
    }
    let _ = writeln!(PromptWriter {});
    result?;
    Ok(editor.into_secret())
}
