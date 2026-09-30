//! Platform-wide native USB4 ownership, following Linux drivers/acpi/bus.c.
use alloc::vec::Vec;
use narf_aml::Value;

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
    // This CM manages display and USB3; it does not request PCIe or XDomain.
    let usb = handshake(
        [
            0x3a, 0xd1, 0xa0, 0x23, 0xab, 0x26, 0x6c, 0x48, 0x9c, 0x5f, 0x0f, 0xfa, 0x52, 0x5a,
            0x57, 0x5a,
        ],
        &[0, 0, 3],
    )?;
    (usb[2] != 0).then_some(usb[2])
}
