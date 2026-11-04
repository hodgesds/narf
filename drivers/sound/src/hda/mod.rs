//! HDA shared types.
//!
//! The native HDA controller engine lives in `narf-audio`
//! (`narf_audio::hda`); this module keeps only the stream-descriptor
//! and Buffer Descriptor List entry types that the crate's PCM
//! substream model (`crate::pcm`) is built on. The legacy in-crate
//! controller/CORB/RIRB/widget models were excised in #783.

pub mod streams;
