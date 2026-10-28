//! Platform-wide native USB4 ownership, following Linux drivers/acpi/bus.c.
use alloc::vec::Vec;
use narf_aml::Value;

/// USB4 `_OSC` control bits, in capabilities DWORD 2 of the USB4
/// `_OSC` handshake (ACPI specification, USB4 `_OSC`): bit 0 is USB3
/// tunnelling, bit 1 DisplayPort tunnelling, bit 2 PCIe tunnelling,
/// bit 3 XDomain connections. The CM proceeds per-protocol on the
/// bits firmware actually grants; a protocol whose bit comes back
/// clear is never programmed, and the shortfall stays visible in the
/// returned mask rather than being assumed away.
pub(crate) const CONTROL_USB3: u32 = 1 << 0;
pub(crate) const CONTROL_DP: u32 = 1 << 1;
pub(crate) const CONTROL_PCIE: u32 = 1 << 2;
pub(crate) const CONTROL_XDOMAIN: u32 = 1 << 3;

/// What this CM requests from firmware: USB3, DisplayPort and PCIe
/// tunnelling, plus XDomain connections (bit 3, requested since
/// the XDomain engine landed; the grant still decides — the engine
/// stays inert on domains where the bit comes back clear).
pub(crate) const CONTROL_REQUEST: u32 = CONTROL_USB3 | CONTROL_DP | CONTROL_PCIE | CONTROL_XDOMAIN;

fn handshake(uuid: [u8; 16], caps: &[u32]) -> Option<Vec<u32>> {
    let mut input = caps.to_vec();
    for query in [true, false] {
        input[0] = u32::from(query);
        let bytes: Vec<u8> = input.iter().flat_map(|v| v.to_le_bytes()).collect();
        let value = narf_aml::eval::evaluate_method(
            "\\_SB._OSC",
            &[
                Value::Buffer(uuid.to_vec()),
                Value::Integer(1),
                Value::Integer(caps.len() as u64),
                Value::Buffer(bytes),
            ],
        )
        .ok()?;
        let Value::Buffer(bytes) = value else {
            return None;
        };
        if bytes.len() != caps.len() * 4 {
            return None;
        }
        let output: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        if output[0] & 0x0e != 0 || (!query && output[0] & 0x10 != 0) {
            return None;
        }
        for i in 1..input.len() {
            input[i] &= output[i];
        }
    }
    Some(input)
}
pub(crate) fn native_control() -> Option<u32> {
    let platform = handshake(
        [
            0x6e, 0xb0, 0x11, 0x08, 0x27, 0x4a, 0xf9, 0x44, 0x8d, 0x60, 0x3c, 0xbb, 0xc2, 0x2e,
            0x7b, 0x48,
        ],
        &[0, 1 << 18],
    )?;
    if platform[1] & (1 << 18) == 0 {
        return None;
    }
    // This CM manages display, USB3 and PCIe tunnelling and
    // XDomain connections. The handshake ANDs the request with the
    // firmware reply, so the returned mask is exactly the granted
    // subset of CONTROL_REQUEST — callers gate each protocol on its
    // own bit.
    let usb = handshake(
        [
            0x3a, 0xd1, 0xa0, 0x23, 0xab, 0x26, 0x6c, 0x48, 0x9c, 0x5f, 0x0f, 0xfa, 0x52, 0x5a,
            0x57, 0x5a,
        ],
        &[0, 0, CONTROL_REQUEST],
    )?;
    (usb[2] != 0).then_some(usb[2])
}
