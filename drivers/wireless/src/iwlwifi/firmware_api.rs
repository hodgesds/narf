//! Firmware TLVs needed by the runtime transport. Values and layouts
//! follow `fw/file.h` in the local Linux iwlwifi source.

/// Metadata borrowed from the firmware image; command versions are
/// negotiated from the image rather than inferred from its filename.
#[derive(Clone, Debug, Default)]
pub struct FirmwareApi<'a> {
    pub iml: Option<&'a [u8]>,
    pub pnvm: Option<&'a [u8]>,
    pub commands: &'a [u8],
    pub capabilities: [u32; 8],
    pub api_changes: [u32; 8],
    pub phy_config: u32,
    pub calibration: [u32; 2],
}

impl<'a> FirmwareApi<'a> {
    /// Parse metadata, returning false for TLVs owned by another parser.
    /// Known malformed TLVs are errors, not silently absent features.
    pub fn consume(&mut self, tag: u32, data: &'a [u8]) -> Result<bool, &'static str> {
        match tag {
            22 if data.len() == 12 => {
                // iwl_tlv_calib_data: ucode type, flow, event. Regular=0.
                if data[..4] == [0; 4] {
                    self.calibration = [
                        u32::from_le_bytes(data[4..8].try_into().unwrap()),
                        u32::from_le_bytes(data[8..12].try_into().unwrap()),
                    ];
                }
            }
            23 if data.len() >= 4 => {
                self.phy_config = u32::from_le_bytes(data[..4].try_into().unwrap());
            }
            29 | 30 if data.len() == 8 => {
                let index = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                let bits = u32::from_le_bytes(data[4..8].try_into().unwrap());
                let map = if tag == 29 {
                    &mut self.api_changes
                } else {
                    &mut self.capabilities
                };
                // Future words outside our known capability namespace
                // are ignored without indexing past the fixed map.
                if let Some(word) = map.get_mut(index) {
                    *word |= bits;
                }
            }
            48 if data.len() % 4 == 0 => self.commands = data,
            52 if !data.is_empty() => self.iml = Some(data),
            74 if !data.is_empty() => self.pnvm = Some(data),
            22 | 23 | 29 | 30 | 48 | 52 | 74 => return Err("malformed firmware API TLV"),
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn has_capability(&self, bit: usize) -> bool {
        self.capabilities
            .get(bit / 32)
            .is_some_and(|word| word & (1 << (bit % 32)) != 0)
    }

    /// `(command version, notification version)`; 99 means unknown.
    pub fn versions(&self, group: u8, command: u8) -> Option<(u8, u8)> {
        self.commands
            .chunks_exact(4)
            .find(|entry| entry[0] == command && entry[1] == group)
            .map(|entry| (entry[2], entry[3]))
    }
}
