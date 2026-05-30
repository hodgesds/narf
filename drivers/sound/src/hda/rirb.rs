//! Response Input Ring Buffer (RIRB) — verb-response path.
//!
//! HDA §3.3.28 — §3.3.34. The RIRB is a circular buffer of 8-byte
//! response entries written by the controller as codec responses
//! arrive. Software polls (or wakes on RINTFL via INTSTS.CIS) and
//! advances its read pointer.
//!
//! Each response entry is:
//!
//! ```text
//!   bits 31:0   response data (12-bit or 32-bit per verb)
//!   bits 35:32  caddr — which codec sent it (low 4 bits)
//!   bit  36     SOLAC — unsolicited response flag (1) or solicited (0)
//!   bits 39:37  reserved
//!   bits 63:40  reserved
//! ```
//!
//! Linux references:
//! - `sound/hda/core/controller.c::snd_hdac_bus_handle_stream_irq`
//!   for the RIRB interrupt path.
//! - `sound/hda/core/controller.c::snd_hdac_bus_init_cmd_io` for
//!   register setup.

/// Number of 8-byte entries in the RIRB.
pub const RIRB_ENTRIES: usize = 256;

/// RIRB total byte size.
pub const RIRB_BYTES: usize = RIRB_ENTRIES * 8;

/// One decoded RIRB response.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Response {
    /// 32-bit response payload (codec-specific).
    pub data: u32,
    /// Codec address that issued the response (low 4 bits of `ex`).
    pub caddr: u8,
    /// True if this was an unsolicited response (pin sense, codec
    /// change, etc).
    pub unsolicited: bool,
}

impl Response {
    /// Decode a raw 8-byte RIRB entry.
    pub const fn decode(raw: u64) -> Self {
        let data = (raw & 0xFFFF_FFFF) as u32;
        let ex = ((raw >> 32) & 0xFFFF_FFFF) as u32;
        Response {
            data,
            caddr: (ex & 0xF) as u8,
            unsolicited: (ex & (1 << 4)) != 0,
        }
    }

    /// Encode for round-tripping in tests.
    pub const fn encode(self) -> u64 {
        let ex = (self.caddr as u64) | (if self.unsolicited { 1 << 4 } else { 0 });
        (self.data as u64) | (ex << 32)
    }
}

/// RIRB ring state.
#[derive(Debug)]
pub struct Rirb {
    /// Physical address of the ring buffer.
    pub phys: u64,
    /// Software-side read pointer. Modulo `RIRB_ENTRIES`. The
    /// hardware maintains CORBWP-style RIRBWP at register 0x58.
    pub rp: u16,
}

impl Rirb {
    /// Drain `[rp+1 .. RIRBWP]` into `dst`, advancing `rp`. Returns
    /// the number of responses copied out.
    pub fn drain(&mut self,
                 ring: &[u64; RIRB_ENTRIES],
                 hw_wp: u16,
                 dst: &mut alloc::vec::Vec<Response>) -> usize {
        let mut count = 0;
        while self.rp != hw_wp {
            self.rp = (self.rp + 1) % RIRB_ENTRIES as u16;
            dst.push(Response::decode(ring[self.rp as usize]));
            count += 1;
        }
        count
    }

    /// Reset software-side. The controller's RIRBWP starts at 0
    /// after reset.
    pub fn reset(&mut self) {
        self.rp = 0;
    }
}
