//! Command Output Ring Buffer (CORB) — the verb send path.
//!
//! HDA §3.3.21 — §3.3.27. The CORB is a circular buffer of 32-bit
//! verb words sitting in main memory. The controller's CORB DMA
//! engine fetches entries starting at `CORBRP+1` and stops at
//! `CORBWP`. Software writes `CORBWP` to publish new verbs.
//!
//! Layout:
//!
//! ```text
//!   Entry 0   [verb 0]   ← CORBRP (controller's last-read pointer)
//!   Entry 1   [verb 1]
//!   ...
//!   Entry N   [verb N]   ← CORBWP (software's write pointer)
//!   ...
//!   Entry 255 [verb 0]   (wraps)
//! ```
//!
//! Linux references:
//! - `sound/hda/core/controller.c::snd_hdac_bus_init_cmd_io` —
//!   register setup.
//! - `sound/hda/core/controller.c::snd_hdac_bus_send_cmd` —
//!   atomic publish via CORBWP.

/// Number of 4-byte entries in the CORB. The HDA spec lets a chip
/// advertise smaller rings via CORBSIZE.SZCAP, but every modern
/// controller supports 256 entries — we always use that.
pub const CORB_ENTRIES: usize = 256;

/// CORB total byte size (256 × 4 = 1024 bytes).
pub const CORB_BYTES: usize = CORB_ENTRIES * 4;

/// HDA verb word (HDA §7.3.1).
///
/// Layout:
///
/// ```text
///   bits 31:28  Codec Address (CAd) — typically 0..7
///   bits 27:20  Node ID (NID)
///   bits 19:8   12-bit verb ID
///   bits  7:0   8-bit payload
/// ```
///
/// For 4-bit major opcodes (e.g. Set Amp Gain/Mute = 0x3), callers
/// encode the 12-bit `verb_id` as `(major << 8) | high_payload_byte`
/// and put the low payload byte in `payload`. See
/// `codec::generic::amp_gain_mute_payload` for the helper.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Verb(pub u32);

impl Verb {
    /// Pack a verb word.
    pub const fn new(cad: u8, nid: u8, verb_id: u16, payload: u8) -> Self {
        let w = ((cad as u32 & 0xF) << 28)
            | ((nid as u32) << 20)
            | (((verb_id as u32) & 0x0FFF) << 8)
            | (payload as u32);
        Verb(w)
    }

    pub const fn cad(self) -> u8 {
        ((self.0 >> 28) & 0xF) as u8
    }

    pub const fn nid(self) -> u8 {
        ((self.0 >> 20) & 0xFF) as u8
    }

    pub const fn verb_id(self) -> u16 {
        ((self.0 >> 8) & 0x0FFF) as u16
    }

    pub const fn payload(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

/// CORB ring state. Backing storage is a DMA-coherent buffer owned
/// by the controller; we keep the indices here in the controller
/// struct.
#[derive(Debug)]
pub struct Corb {
    /// Physical address of the ring buffer.
    pub phys: u64,
    /// Software-side mirror of CORBWP. Modulo `CORB_ENTRIES`.
    pub wp: u16,
}

impl Corb {
    /// Publish a verb at the next write position. Returns the new
    /// CORBWP value the controller should see. Does not touch MMIO —
    /// the controller's CORBWP register is updated by
    /// `commit_publish` after possibly batching multiple verbs.
    pub fn enqueue(&mut self, slot: &mut [u32; CORB_ENTRIES], verb: Verb) -> u16 {
        self.wp = (self.wp + 1) % CORB_ENTRIES as u16;
        slot[self.wp as usize] = verb.0;
        self.wp
    }

    /// Reset the ring software-side. The controller's CORBRP starts
    /// at 0 after reset; software then writes CORBWP = 0.
    pub fn reset(&mut self) {
        self.wp = 0;
    }
}
