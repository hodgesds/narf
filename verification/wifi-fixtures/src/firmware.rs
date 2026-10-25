//! Sparse test images assembled from reviewed Rust literals.
//!
//! No binary fixture files or host extraction are involved. These inputs test
//! layout handling and must never enter a firmware registry or hardware loader.
use alloc::vec::Vec;

/// Match the firmware registry's current bounded source-image profile.
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    Size,
    MissingMetadata,
    EmptyFragment,
    Bounds,
    Overlap,
    Allocation,
}

/// Reconstruct an explicitly synthetic image, preserving only the supplied
/// metadata fragments. Every opaque gap is zeroed. Fragments must be nonempty,
/// ordered and nonoverlapping, with all bounds checked before allocation.
pub fn sparse_image(
    image_len: usize,
    fragments: &[(usize, &[u8])],
) -> Result<Vec<u8>, ReplayError> {
    if image_len == 0 || image_len > MAX_IMAGE_BYTES {
        return Err(ReplayError::Size);
    }
    if fragments.is_empty() {
        return Err(ReplayError::MissingMetadata);
    }
    let mut end = 0;
    for &(offset, bytes) in fragments {
        if bytes.is_empty() {
            return Err(ReplayError::EmptyFragment);
        }
        if offset < end {
            return Err(ReplayError::Overlap);
        }
        end = offset.checked_add(bytes.len()).ok_or(ReplayError::Bounds)?;
        if end > image_len {
            return Err(ReplayError::Bounds);
        }
    }
    let mut image = Vec::new();
    image
        .try_reserve_exact(image_len)
        .map_err(|_| ReplayError::Allocation)?;
    image.resize(image_len, 0);
    for &(offset, bytes) in fragments {
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    Ok(image)
}

fn firmware_sparse_image_preserves_only_recorded_bytes() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    match sparse_image(12, &[(0, &[1, 2]), (6, &[3, 4]), (11, &[5])]) {
        Ok(bytes) if bytes == [1, 2, 0, 0, 0, 0, 3, 4, 0, 0, 0, 5] => TestResult::Pass,
        _ => TestResult::Fail("metadata replay altered fragments or retained opaque bytes"),
    }
}
narf_kernel_test::kernel_test_in!(
    "verification/wifi-fixtures/firmware",
    firmware_sparse_image_preserves_only_recorded_bytes
);

fn firmware_sparse_image_rejects_invalid_geometry() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    for (len, fragments, expected) in [
        (0, &[(0, &[1][..])][..], ReplayError::Size),
        (MAX_IMAGE_BYTES + 1, &[(0, &[1][..])][..], ReplayError::Size),
        (8, &[][..], ReplayError::MissingMetadata),
        (8, &[(0, &[][..])][..], ReplayError::EmptyFragment),
        (8, &[(8, &[1][..])][..], ReplayError::Bounds),
        (8, &[(usize::MAX, &[1][..])][..], ReplayError::Bounds),
        (
            8,
            &[(2, &[1, 2][..]), (3, &[3][..])][..],
            ReplayError::Overlap,
        ),
        (8, &[(4, &[1][..]), (0, &[2][..])][..], ReplayError::Overlap),
    ] {
        if sparse_image(len, fragments) != Err(expected) {
            return TestResult::Fail("invalid metadata replay geometry accepted");
        }
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "verification/wifi-fixtures/firmware",
    firmware_sparse_image_rejects_invalid_geometry
);
