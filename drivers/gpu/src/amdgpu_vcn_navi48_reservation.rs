//! Exact transactional admission for requested retained native proof arenas.
use super::*;
pub(crate) const fn proof_bytes(ibs: bool, decode: bool, encode: bool) -> u64 {
    BYTES
        + if ibs || decode || encode {
            ib_words::IB_BYTES
        } else {
            0
        }
        + if decode {
            decode_words::BYTES
                + hevc_words::BYTES
                + hevc10_words::BYTES
                + vp9_words::BYTES
                + vp9_10_words::BYTES
                + av1_words::BYTES
                + av1_10_words::BYTES
        } else {
            0
        }
        + if encode {
            encode_words::BYTES
                + hevc_encode_words::BYTES
                + hevc_roundtrip_words::BYTES
                + av1_encode_words::BYTES
                + av1_320_words::BYTES
        } else {
            0
        }
}
impl<I: Io> Engine<I> {
    pub(super) fn reserve_proofs(
        &mut self,
        ibs: bool,
        decode: bool,
        encode: bool,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        if encode && self.encode_interface.is_none() {
            return Err(Error::Unsupported);
        }
        crate::amdgpu_media_reservation::reserve(
            &self.ib_pool,
            [
                (
                    &mut self.ib_memory,
                    ib_words::IB_BYTES,
                    ibs || decode || encode,
                ),
                (&mut self.decode_memory, decode_words::BYTES, decode),
                (&mut self.hevc_memory, hevc_words::BYTES, decode),
                (&mut self.hevc10_memory, hevc10_words::BYTES, decode),
                (&mut self.vp9_memory, vp9_words::BYTES, decode),
                (&mut self.vp9_10_memory, vp9_10_words::BYTES, decode),
                (&mut self.av1_memory, av1_words::BYTES, decode),
                (&mut self.av1_10_memory, av1_10_words::BYTES, decode),
                (&mut self.encode_memory, encode_words::BYTES, encode),
                (
                    &mut self.hevc_encode_memory,
                    hevc_encode_words::BYTES,
                    encode,
                ),
                (
                    &mut self.hevc_roundtrip_memory,
                    hevc_roundtrip_words::BYTES,
                    encode,
                ),
                (&mut self.av1_encode_memory, av1_encode_words::BYTES, encode),
                (&mut self.av1_roundtrip_memory, av1_320_words::BYTES, encode),
            ],
        )
        .map_err(|_| Error::Allocation)
    }
}
