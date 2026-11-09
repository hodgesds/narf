//! Bounded, opt-in early-boot serial credentials. No userspace/USB task is
//! running at this point; the future polls hardware without holding a lock.
use alloc::vec::Vec;
use core::{fmt::Write, task::Poll};
use narf_block::encrypted::{LuksCredentialError as Error, LuksVolumeInfo};
use zeroize::Zeroizing;

const MAX_PASSPHRASE: usize = 512;

pub(super) fn serial_provider(volume: &LuksVolumeInfo) -> Result<Zeroizing<Vec<u8>>, Error> {
    let args = narf_boot::args();
    let selected = args.value("rd.luks.uuid").ok_or(Error::Unavailable)?;
    let selected = selected.strip_prefix("luks-").unwrap_or(selected);
    if narf_block::partition::parse_uuid(selected).is_none()
        || !selected.eq_ignore_ascii_case(&volume.uuid)
    {
        return Err(Error::Declined);
    }
    let timeout_ms = args
        .value("rd.luks.timeout")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(90)
        .clamp(1, 300)
        * 1000;
    let deadline = narf_time::Deadline::after_ms(timeout_ms);
    let _ = write!(
        narf_console::Writer,
        "\nLUKS {} passphrase (serial; no echo): ",
        volume.uuid
    );
    // Preallocate once: growing a Vec could leave unzeroized copies of an
    // entered secret in freed allocations. Backspace clears before truncating.
    let mut secret = Zeroizing::new(Vec::with_capacity(MAX_PASSPHRASE));
    let result = narf_scheduler::block_on_spin(core::future::poll_fn(|cx| {
        if deadline.expired() {
            return Poll::Ready(Err(Error::TimedOut));
        }
        // Use the IRQ handler's producer lock as well: independently reading
        // the UART after an empty-ring check could reorder bytes if an IRQ
        // enqueues an earlier byte between those operations. Subsys has
        // initialized the ring before root mounting enters this Late path.
        narf_input::fill_byte_ring(narf_console::try_read_byte, 256);
        if let Some(byte) = narf_input::pop_ascii_byte() {
            match byte {
                3 | 27 => return Poll::Ready(Err(Error::Cancelled)),
                b'\r' | b'\n' if !secret.is_empty() => return Poll::Ready(Ok(())),
                8 | 127 => {
                    if let Some(last) = secret.last_mut() {
                        *last = 0;
                    }
                    secret.pop();
                }
                0x20..=0x7e => {
                    if secret.len() == MAX_PASSPHRASE {
                        return Poll::Ready(Err(Error::TooLarge));
                    }
                    secret.push(byte);
                }
                _ => {}
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }));
    let _ = writeln!(narf_console::Writer);
    result?;
    Ok(secret)
}
