//! `pmc-quirks.c`: the platform-firmware bugs `amd_pmc` works around,
//! found by `dmi_first_match` over `fwbug_list`.
//!
//! - **`s2idle_bug_mmio`:** at restore, clear bit 0 of the FCH PM scratch
//!   byte (`amd_pmc_skip_nvme_smi_handler`), which skips a firmware SMI
//!   that mishandles NVMe's D0 transition.
//! - **`spurious_8042`:** IRQ1 must not wake the system (`amd_pmc_wa_irq1`).
//!   NARF's s2idle park masks every discrete IRQ, IRQ1 included, and only
//!   SCI-funneled sources wake it, so nothing more is needed.
//! - **`need_suspend_delay`:** 2.5 s before each S0i3 entry.
use alloc::string::String;

/// `struct quirk_entry`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quirk {
    pub s2idle_bug_mmio: bool,
    pub spurious_8042: bool,
    pub need_suspend_delay: bool,
}
const S2IDLE_BUG: Quirk = Quirk {
    s2idle_bug_mmio: true,
    spurious_8042: false,
    need_suspend_delay: false,
};
const SPURIOUS_8042: Quirk = Quirk {
    s2idle_bug_mmio: false,
    spurious_8042: true,
    need_suspend_delay: false,
};
const S2IDLE_SPURIOUS_8042: Quirk = Quirk {
    s2idle_bug_mmio: true,
    spurious_8042: true,
    need_suspend_delay: false,
};
const NEED_SUSPEND_DELAY: Quirk = Quirk {
    s2idle_bug_mmio: false,
    spurious_8042: false,
    need_suspend_delay: true,
};
/// The FCH PM scratch byte (`FCH_PM_BASE + FCH_PM_SCRATCH`).
pub const FCH_PM_SCRATCH: u64 = 0xfed8_0300 + 0x80; // linux: FCH_PM_BASE + FCH_PM_SCRATCH

/// The SMBIOS strings `fwbug_list` matches on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dmi {
    pub sys_vendor: String,
    pub product_name: String,
    pub board_vendor: String,
    pub board_name: String,
    pub bios_version: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    SysVendor,
    ProductName,
    BoardVendor,
    BoardName,
    BiosVersion,
}
use Field::*;
impl Dmi {
    fn get(&self, field: Field) -> &str {
        match field {
            SysVendor => &self.sys_vendor,
            ProductName => &self.product_name,
            BoardVendor => &self.board_vendor,
            BoardName => &self.board_name,
            BiosVersion => &self.bios_version,
        }
    }
}
struct Entry {
    ident: &'static str,
    quirk: Quirk,
    /// Every pair must match: `DMI_MATCH`, a substring.
    matches: &'static [(Field, &'static str)],
}
/// `fwbug_list`, in its order.
static FWBUG_LIST: &[Entry] = &[
    Entry {
        ident: "L14 Gen2 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20X5")],
    },
    Entry {
        ident: "T14s Gen2 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20XF")],
    },
    Entry {
        ident: "X13 Gen2 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20XH")],
    },
    Entry {
        ident: "T14 Gen2 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20XK")],
    },
    Entry {
        ident: "T14 Gen2 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20XL")],
    },
    Entry {
        ident: "T14 Gen1 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20UD")],
    },
    Entry {
        ident: "T14 Gen1 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20UE")],
    },
    Entry {
        ident: "T14s Gen1 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20UH")],
    },
    Entry {
        ident: "T14s Gen1 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20UJ")],
    },
    Entry {
        ident: "P14s Gen1 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "20Y1")],
    },
    Entry {
        ident: "P14s Gen2 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "21A0")],
    },
    Entry {
        ident: "P14s Gen2 AMD",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "21A1")],
    },
    Entry {
        ident: "ROG Xbox Ally RC73YA",
        quirk: SPURIOUS_8042,
        matches: &[
            (BoardVendor, "ASUSTeK COMPUTER INC."),
            (BoardName, "RC73YA"),
        ],
    },
    Entry {
        ident: "V14 G4 AMN",
        quirk: S2IDLE_BUG,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82YT")],
    },
    Entry {
        ident: "V14 G4 AMN",
        quirk: S2IDLE_BUG,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "83GE")],
    },
    Entry {
        ident: "V15 G4 AMN",
        quirk: S2IDLE_BUG,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82YU")],
    },
    Entry {
        ident: "V15 G4 AMN",
        quirk: S2IDLE_BUG,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "83CQ")],
    },
    Entry {
        ident: "IdeaPad 1 14AMN7",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82VF")],
    },
    Entry {
        ident: "IdeaPad 1 15AMN7",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82VG")],
    },
    Entry {
        ident: "IdeaPad 1 15AMN7",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82X5")],
    },
    Entry {
        ident: "IdeaPad Slim 3 14AMN8",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82XN")],
    },
    Entry {
        ident: "IdeaPad Slim 3 15AMN8",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82XQ")],
    },
    Entry {
        ident: "Zen3-based IdeaPad Slim and similar",
        quirk: NEED_SUSPEND_DELAY,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82X")],
    },
    Entry {
        ident: "Zen3+-based IdeaPad Slim and similar",
        quirk: NEED_SUSPEND_DELAY,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "83K")],
    },
    Entry {
        ident: "IdeaPad Slim 3 15ARP10 (83MM)",
        quirk: NEED_SUSPEND_DELAY,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "83MM")],
    },
    Entry {
        ident: "Thinkpad L14 Gen3",
        quirk: S2IDLE_BUG,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "21C6")],
    },
    Entry {
        ident: "Lenovo Yoga 6 13ALC6",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "82ND")],
    },
    Entry {
        ident: "Lenovo Legion Go 2",
        quirk: S2IDLE_BUG,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "83N0")],
    },
    Entry {
        ident: "Lenovo Legion Go 2",
        quirk: S2IDLE_BUG,
        matches: &[(BoardVendor, "LENOVO"), (ProductName, "83N1")],
    },
    Entry {
        ident: "HP Laptop 15s-eq2xxx",
        quirk: S2IDLE_SPURIOUS_8042,
        matches: &[(SysVendor, "HP"), (ProductName, "HP Laptop 15s-eq2xxx")],
    },
    Entry {
        ident: "Framework Laptop 13 (Phoenix)",
        quirk: SPURIOUS_8042,
        matches: &[
            (SysVendor, "Framework"),
            (ProductName, "Laptop 13 (AMD Ryzen 7040Series)"),
            (BiosVersion, "03.03"),
        ],
    },
    Entry {
        ident: "Framework Laptop 13 (Phoenix)",
        quirk: SPURIOUS_8042,
        matches: &[
            (SysVendor, "Framework"),
            (ProductName, "Laptop 13 (AMD Ryzen 7040Series)"),
            (BiosVersion, "03.05"),
        ],
    },
    Entry {
        ident: "MECHREVO Wujie 14X (GX4HRXL)",
        quirk: SPURIOUS_8042,
        matches: &[(BoardName, "WUJIE14-GX4HRXL")],
    },
    Entry {
        ident: "MECHREVO Yilong15Pro Series GM5HG7A",
        quirk: SPURIOUS_8042,
        matches: &[
            (SysVendor, "MECHREVO"),
            (ProductName, "Yilong15Pro Series GM5HG7A"),
        ],
    },
    Entry {
        ident: "PCSpecialist Lafite Pro V 14M",
        quirk: SPURIOUS_8042,
        matches: &[
            (SysVendor, "PCSpecialist"),
            (ProductName, "Lafite Pro V 14M"),
        ],
    },
    Entry {
        ident: "TUXEDO Stellaris Slim 15 AMD Gen6",
        quirk: SPURIOUS_8042,
        matches: &[(BoardName, "GMxHGxx")],
    },
    Entry {
        ident: "TUXEDO InfinityBook Pro 14/15 AMD Gen10",
        quirk: SPURIOUS_8042,
        matches: &[(BoardName, "XxHP4NAx")],
    },
    Entry {
        ident: "TUXEDO InfinityBook Pro 14/15 AMD Gen10",
        quirk: SPURIOUS_8042,
        matches: &[(BoardName, "XxKK4NAx_XxSP4NAx")],
    },
    Entry {
        ident: "MECHREVO Wujie 15X Pro",
        quirk: SPURIOUS_8042,
        matches: &[(BoardName, "WUJIE Series-X5SP4NAG")],
    },
];

/// `dmi_first_match(fwbug_list)`: the first entry whose every field
/// contains its string, with its name.
pub fn lookup(dmi: &Dmi) -> Option<(&'static str, Quirk)> {
    FWBUG_LIST
        .iter()
        .find(|e| e.matches.iter().all(|&(f, v)| dmi.get(f).contains(v)))
        .map(|e| (e.ident, e.quirk))
}

/// The machine's strings, from SMBIOS types 0, 1 and 2.
pub fn read_dmi() -> Dmi {
    fn text(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).trim().into()
    }
    let mut dmi = Dmi::default();
    let mut sys = [narf_firmware_smbios::SmbiosSystem::ZERO];
    if narf_firmware_smbios::copy_system(&mut sys) > 0 {
        dmi.sys_vendor = text(&sys[0].manufacturer);
        dmi.product_name = text(&sys[0].product_name);
    }
    let mut board = [narf_firmware_smbios::SmbiosBaseboard::ZERO];
    if narf_firmware_smbios::copy_baseboard(&mut board) > 0 {
        dmi.board_vendor = text(&board[0].manufacturer);
        dmi.board_name = text(&board[0].product);
    }
    let mut bios = [narf_firmware_smbios::SmbiosBios::ZERO];
    if narf_firmware_smbios::copy_bios(&mut bios) > 0 {
        dmi.bios_version = text(&bios[0].version);
    }
    dmi
}
