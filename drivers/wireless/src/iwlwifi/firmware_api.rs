//! Firmware TLVs needed by the runtime transport. Values and layouts
//! follow `fw/file.h` in the local Linux iwlwifi source.

/// Metadata borrowed from the firmware image; command versions are
/// negotiated from the image rather than inferred from its filename.
#[derive(Clone, Debug, Default)]
pub struct FirmwareApi<'a> {
    /// TLV18 first word, as Linux iwl-drv.c consumes it. Later complete
    /// words are reserved; SHORT_BL selects the actual scan blocklist ABI.
    pub flags: u32,
    pub iml: Option<&'a [u8]>,
    pub pnvm: Option<&'a [u8]>,
    pub commands: &'a [u8],
    pub bios_commands: Option<&'a [u8]>,
    pub capabilities: [u32; 8],
    pub api_changes: [u32; 8],
    pub phy_config: u32,
    pub calibration: [u32; 2],
    /// Actual CONST_BASE TLVs; absence preserves older protocol admission.
    /// Optional role consumers must separately require their needed slots.
    pub num_stations: Option<u8>,
    pub num_links: Option<u8>,
}

impl<'a> FirmwareApi<'a> {
    /// Parse metadata, returning false for TLVs owned by another parser.
    /// Known malformed TLVs are errors, not silently absent features.
    pub fn consume(&mut self, tag: u32, data: &'a [u8]) -> Result<bool, &'static str> {
        match tag {
            18 if data.len() >= 4 && data.len() % 4 == 0 => {
                self.flags = u32::from_le_bytes(data[..4].try_into().unwrap());
            }
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
            73 if data.len() % 4 == 0 => {
                if self.bios_commands.is_some() {
                    return Err("duplicate firmware BIOS command table");
                }
                self.bios_commands = Some(data);
            }
            74 if !data.is_empty() => self.pnvm = Some(data),
            0x100 | 0x101 if data.len() == 4 => {
                let value = u32::from_le_bytes(data.try_into().unwrap());
                // Linux fw/api/mac.h and mac-cfg.h: station count<=16,
                // firmware link IDs0..3. Zero is factual, not an absent TLV.
                let (target, maximum) = if tag == 0x100 {
                    (&mut self.num_stations, 16)
                } else {
                    (&mut self.num_links, 4)
                };
                if target.is_some() || value > maximum {
                    return Err("duplicate/out-of-range firmware resource count");
                }
                *target = Some(value as u8);
            }
            18 | 22 | 23 | 29 | 30 | 48 | 52 | 73 | 74 | 0x100 | 0x101 => {
                return Err("malformed firmware API TLV")
            }
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

    /// Linux fw/img.c::iwl_fw_lookup_cmd_ver uses LONG_GROUP for narrow
    /// command IDs. Notification metadata retains its actual group and
    /// continues using `versions`; this does not rewrite data TX headers.
    pub fn command_version(&self, group: u8, command: u8) -> Option<u8> {
        self.versions(if group == 0 { 1 } else { group }, command)
            .map(|entry| entry.0)
    }

    /// TLV73's source-specific supported BIOS revision. Missing metadata,
    /// command or source uses Linux's caller-provided revision fallback.
    pub fn bios_revision(&self, source: u8, group: u8, command: u8, default: u8) -> u8 {
        if !matches!(source, 1 | 2) {
            return default;
        }
        let group = if group == 0 { 1 } else { group };
        self.bios_commands
            .unwrap_or(&[])
            .chunks_exact(4)
            .find(|entry| entry[0] == command && entry[1] == group)
            .map_or(default, |entry| entry[usize::from(source) + 1])
    }
}
