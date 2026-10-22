//! Transactional unpublished media-arena admission. DMA retirement remains
//! owned by each engine; this helper never publishes, releases or recycles it.
use crate::amdgpu_vram::{Error, Pool, Reservation};

pub(crate) fn reserve<const N: usize>(
    pool: &Pool,
    requests: [(&mut Option<Reservation>, u64, bool); N],
) -> Result<(), Error> {
    // New slots stay local until the complete requested set fits. Failure
    // drops only unpublished new reservations; existing owner pins survive.
    let mut fresh: [Option<Reservation>; N] = core::array::from_fn(|_| None);
    for (index, (slot, bytes, needed)) in requests.iter().enumerate() {
        if *needed && slot.is_none() {
            let memory = pool.reserve(*bytes)?;
            if memory.address() & 4095 != 0
                || memory
                    .address()
                    .checked_add(memory.size())
                    .is_none_or(|end| end > 1 << 48)
            {
                return Err(Error::Invalid);
            }
            fresh[index] = Some(memory);
        }
    }
    for ((slot, _, _), new) in requests.into_iter().zip(fresh) {
        if let Some(new) = new {
            *slot = Some(new);
        }
    }
    Ok(())
}
