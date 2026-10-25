// Frozen reference data; source provenance is recorded in this file and rtw89/REFERENCE_FIXTURES.md.
// Frozen Linux drivers/pci/pci.c pending/FLR timing reference vectors.
pub(super) const PENDING_READ_TIMES: &[&[u64]] = &[&[0], &[0, 100, 300], &[0, 100, 300, 700]];
pub(super) const SOURCE_QUIET_MS: u64 = 100;
