#[derive(Debug)]
pub(crate) struct TestRegions {
    regions: alloc::vec::Vec<super::OpRegionInfo>,
    fields: alloc::vec::Vec<super::FieldInfo>,
}

impl TestRegions {
    pub(crate) fn capture() -> Self {
        Self {
            regions: core::mem::take(&mut *super::REGIONS.lock()),
            fields: core::mem::take(&mut *super::FIELDS.lock()),
        }
    }
}

impl Drop for TestRegions {
    fn drop(&mut self) {
        core::mem::swap(&mut *super::REGIONS.lock(), &mut self.regions);
        core::mem::swap(&mut *super::FIELDS.lock(), &mut self.fields);
    }
}
