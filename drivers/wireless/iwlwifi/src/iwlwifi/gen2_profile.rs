//! Exact 22000 firmware selection from discovered MAC/RF identity.
//! Linux cfg/22000.c and iwl-drv.c::iwl_drv_get_fwname_pre.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Pci,
    Gone,
    Mac,
    Rf,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub prefix: &'static str,
    pub integrated: bool,
    pub xtal_latency_us: u32,
    pub ltr_delay_us: u32,
}
pub const API: u32 = 77;
/// Linux iwl-drv.c: API_NEW_VERSION selects the full header word; older
/// firmware uses IWL_UCODE_API's bits8..15. FW_VERSION is display metadata.
pub fn firmware_api(parsed: &super::ParsedUcode<'_>) -> u32 {
    if parsed.api.api_changes[0] & (1 << 20) != 0 {
        parsed.header.version
    } else {
        (parsed.header.version >> 8) & 255
    }
}
pub fn select(did: u16, hw_rev: u32, hw_rf: u32) -> Result<Profile, Error> {
    if hw_rev == u32::MAX || hw_rf == u32::MAX {
        return Err(Error::Gone);
    }
    let mac_type = (hw_rev >> 4) & 0xfff;
    if did == 0x2723 {
        if mac_type != 0x34 {
            return Err(Error::Mac);
        }
        // Discrete CC is a special case: no RF suffix exists in its filename.
        return Ok(Profile {
            prefix: "iwlwifi-cc-a0",
            integrated: false,
            xtal_latency_us: 0,
            ltr_delay_us: 0,
        });
    }
    // Linux pcie/drv.c "Qu devices" binds each PCI ID to one cfg/22000.c
    // mac_cfg: iwl_qu_mac_cfg (xtal 500 µs, LTR 200 µs), the medium-latency
    // cfg (1820/1820 µs) or the long-latency cfg (12000/2500 µs).
    let (xtal_latency_us, ltr_delay_us) = match did {
        0x02f0 | 0x06f0 => (500, 200),
        0x34f0 | 0x3df0 | 0x4df0 => (1820, 1820),
        0x43f0 | 0xa0f0 => (12000, 2500),
        _ => return Err(Error::Pci),
    };
    let mac = match (mac_type, hw_rev & 15) {
        (0x33, 1) => 0,
        (0x33, 2) => 1,
        // Linux uses A0 firmware for every discovered QuZ stepping.
        (0x35, _) => 2,
        _ => return Err(Error::Mac),
    };
    let rf = match (hw_rf >> 12) & 0xfff {
        0x105 | 0x108 => 0,
        0x10a | 0x10c => 1,
        _ => return Err(Error::Rf),
    };
    let prefix = match (mac, rf) {
        (0, 0) => "iwlwifi-Qu-b0-jf-b0",
        (0, 1) => "iwlwifi-Qu-b0-hr-b0",
        (1, 0) => "iwlwifi-Qu-c0-jf-b0",
        (1, 1) => "iwlwifi-Qu-c0-hr-b0",
        (2, 0) => "iwlwifi-QuZ-a0-jf-b0",
        (2, 1) => "iwlwifi-QuZ-a0-hr-b0",
        _ => unreachable!(),
    };
    Ok(Profile {
        prefix,
        integrated: true,
        xtal_latency_us,
        ltr_delay_us,
    })
}
