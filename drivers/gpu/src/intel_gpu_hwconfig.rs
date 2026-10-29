//! GuC HWCONFIG KLV table, not an active/fused topology description.
//!
//! Reference: ~/git/linux b90c984d615e8ce2af96f5b1411a962d83fed2ad,
//! MIT i915/gt/uc/intel_guc_hwconfig.c and xe/xe_guc_hwconfig.c.

use alloc::vec::Vec;
use core::ops::Range;

/// Admission limits, not hardware ABI maxima.
pub const MAX_BYTES: u32 = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwconfigError {
    Size,
    Layout,
    Duplicate,
    Allocation,
    NotScalar,
}

#[derive(Debug)]
struct Field {
    key: u32,
    bytes: Range<usize>,
}

/// Exact firmware bytes with a separately sorted, validated lookup index.
/// Unknown keys and vector values survive without renumbering or inference.
#[derive(Debug)]
pub struct HardwareConfig {
    bytes: Vec<u8>,
    fields: Vec<Field>,
}

pub(crate) fn validate_size(bytes: u32) -> Result<(), HwconfigError> {
    if !(12..=MAX_BYTES).contains(&bytes) || bytes % 4 != 0 {
        Err(HwconfigError::Size)
    } else {
        Ok(())
    }
}

impl HardwareConfig {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, HwconfigError> {
        validate_size(u32::try_from(bytes.len()).map_err(|_| HwconfigError::Size)?)?;
        let mut fields: Vec<Field> = Vec::new();
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            if bytes.len() - cursor < 12 || fields.len() == MAX_ENTRIES {
                return Err(HwconfigError::Layout);
            }
            let key = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().expect("key"));
            let words =
                u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().expect("length"));
            let start = cursor + 8;
            let end = usize::try_from(words)
                .ok()
                .and_then(|count| count.checked_mul(4))
                .and_then(|len| start.checked_add(len))
                .filter(|end| words != 0 && *end <= bytes.len())
                .ok_or(HwconfigError::Layout)?;
            fields
                .try_reserve(1)
                .map_err(|_| HwconfigError::Allocation)?;
            fields.push(Field {
                key,
                bytes: start..end,
            });
            cursor = end;
        }
        fields.sort_unstable_by_key(|field| field.key);
        if fields.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(HwconfigError::Duplicate);
        }
        Ok(Self { bytes, fields })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn value_bytes(&self, key: u32) -> Option<&[u8]> {
        let index = self
            .fields
            .binary_search_by_key(&key, |field| field.key)
            .ok()?;
        Some(&self.bytes[self.fields[index].bytes.clone()])
    }

    pub fn lookup_u32(&self, key: u32) -> Result<Option<u32>, HwconfigError> {
        match self.value_bytes(key) {
            None => Ok(None),
            Some(value) if value.len() == 4 => {
                Ok(Some(u32::from_le_bytes(value.try_into().expect("scalar"))))
            }
            Some(_) => Err(HwconfigError::NotScalar),
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn smoke_hwconfig_klv_bounds_and_unknown_values() -> TestResult {
        // Literal KLV vectors following intel_guc_hwconfig.c's documented
        // scalar/vector shape. Keys are opaque, not guessed hardware IDs.
        let bytes = words(&[0x9000, 3, 0x00ffffff, 0xffffffff, 0xff000000, 7, 1, 8]);
        let table = HardwareConfig::parse(bytes.clone()).unwrap();
        assert_eq!(table.as_bytes(), bytes);
        assert_eq!(table.lookup_u32(7), Ok(Some(8)));
        assert_eq!(table.lookup_u32(6), Ok(None));
        assert_eq!(table.lookup_u32(0x9000), Err(HwconfigError::NotScalar));
        assert_eq!(table.value_bytes(0x9000), Some(&bytes[8..20]));
        for bad in [
            alloc::vec![],
            alloc::vec![0; 11],
            words(&[1, 0, 4]),
            words(&[1, u32::MAX, 4]),
            words(&[1, 2, 4]),
            words(&[1, 1, 4, 2]),
            words(&[1, 1, 4, 2, 0]),
        ] {
            assert!(HardwareConfig::parse(bad).is_err());
        }
        assert!(matches!(
            HardwareConfig::parse(words(&[1, 1, 4, 1, 1, 5])),
            Err(HwconfigError::Duplicate)
        ));
        assert!(validate_size(0x100004).is_err());
        assert!(validate_size(14).is_err());
        assert!(validate_size(0x100000).is_ok());
        let mut too_many = Vec::new();
        for key in 0..4097 {
            too_many.extend_from_slice(&words(&[key, 1, 0]));
        }
        assert!(matches!(
            HardwareConfig::parse(too_many),
            Err(HwconfigError::Layout)
        ));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_hwconfig",
        smoke_hwconfig_klv_bounds_and_unknown_values
    );
}
