//! GuC firmware layout and coherent command-transport buffers for Xe-LPG.
//!
//! References: MIT i915 `intel_uc_fw_abi.h`,
//! `abi/guc_communication_ctb_abi.h` and `abi/guc_messages_abi.h`.
//! Parsing validates layout, not Intel's signature or NARF asset authority.
//! These primitives do not boot GuC or register a hardware queue by themselves.

use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};

use crate::intel_gpu_uapi::u32_at;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GuCError {
    FirmwareLayout,
    FirmwareVersion,
    RingSize,
    Full,
    Cursor,
    DescriptorStatus(u32),
    Message,
    Poisoned,
}

/// Validated CSS/uCode/signature ranges. The optional modulus/exponent
/// suffix may be omitted by the firmware distributor, as the ABI permits.
#[derive(Debug)]
pub struct CssImage<'a> {
    pub upload: &'a [u8],
    pub signature: &'a [u8],
    pub version: (u8, u8, u8),
    pub submission_version: (u8, u8, u8),
    pub private_data_bytes: u32,
}

impl<'a> CssImage<'a> {
    pub fn parse(blob: &'a [u8], required_major: u8) -> Result<Self, GuCError> {
        if blob.len() < 128 || blob.len() > 4 * 1024 * 1024 || blob.len() % 4 != 0 {
            return Err(GuCError::FirmwareLayout);
        }
        if u32_at(blob, 0) != 6 || u32_at(blob, 8) != 0x10000 || u32_at(blob, 16) != 0x8086 {
            return Err(GuCError::FirmwareLayout);
        }
        let header = u32_at(blob, 4) as usize;
        let total = u32_at(blob, 24) as usize;
        let key = u32_at(blob, 28) as usize;
        let modulus = u32_at(blob, 32) as usize;
        let exponent = u32_at(blob, 36) as usize;
        let components = key
            .checked_add(modulus)
            .and_then(|v| v.checked_add(exponent))
            .ok_or(GuCError::FirmwareLayout)?;
        if header.checked_sub(components) != Some(32) || total <= header || key == 0 {
            return Err(GuCError::FirmwareLayout);
        }
        let code_bytes = (total - header)
            .checked_mul(4)
            .ok_or(GuCError::FirmwareLayout)?;
        let upload_end = 128usize
            .checked_add(code_bytes)
            .ok_or(GuCError::FirmwareLayout)?;
        let signature_end = key
            .checked_mul(4)
            .and_then(|v| upload_end.checked_add(v))
            .ok_or(GuCError::FirmwareLayout)?;
        let full_end = total.checked_mul(4).ok_or(GuCError::FirmwareLayout)?;
        if signature_end > blob.len() || (blob.len() != signature_end && blob.len() != full_end) {
            return Err(GuCError::FirmwareLayout);
        }
        let version = u32_at(blob, 64);
        if version >> 24 != 0 || (version >> 16) as u8 != required_major {
            return Err(GuCError::FirmwareVersion);
        }
        let private_data_bytes = u32_at(blob, 120);
        let submission = u32_at(blob, 68);
        if submission >> 24 != 0 {
            return Err(GuCError::FirmwareVersion);
        }
        if private_data_bytes > 64 * 1024 * 1024 || private_data_bytes % 4096 != 0 {
            return Err(GuCError::FirmwareLayout);
        }
        Ok(Self {
            upload: &blob[..upload_end],
            signature: &blob[upload_end..signature_end],
            version: ((version >> 16) as u8, (version >> 8) as u8, version as u8),
            submission_version: (
                (submission >> 16) as u8,
                (submission >> 8) as u8,
                submission as u8,
            ),
            private_data_bytes,
        })
    }
}

/// Coherent, device-shared CTB memory. Accesses must be volatile (or atomic)
/// and bounds-checked by the implementation. Descriptor words are HEAD=0,
/// TAIL=1, STATUS=2, then thirteen reserved words. The owner retains memory
/// until GuC transport deregistration or a proven hardware reset is terminal.
pub trait CtMemory {
    fn capacity(&self) -> u32;
    fn descriptor(&self, word: usize) -> u32;
    fn set_descriptor(&self, word: usize, value: u32);
    fn data(&self, word: u32) -> u32;
    fn set_data(&self, word: u32, value: u32);
}

fn validate_capacity(memory: &impl CtMemory) -> Result<u32, GuCError> {
    let capacity = memory.capacity();
    if !(256..=16384).contains(&capacity) || !capacity.is_power_of_two() {
        return Err(GuCError::RingSize);
    }
    Ok(capacity)
}

fn descriptor(memory: &impl CtMemory, capacity: u32) -> Result<(u32, u32), GuCError> {
    let status = memory.descriptor(2);
    if status != 0 {
        return Err(GuCError::DescriptorStatus(status));
    }
    let head = memory.descriptor(0);
    let tail = memory.descriptor(1);
    if head >= capacity || tail >= capacity {
        return Err(GuCError::Cursor);
    }
    Ok((head, tail))
}

/// Host owns TAIL; GuC owns HEAD. One slot remains empty to distinguish full
/// from empty. No waiting, polling loop or IRQ-disabled sleep is hidden here.
#[derive(Debug)]
pub struct CtSender<M: CtMemory> {
    memory: M,
    capacity: u32,
    tail: u32,
    poisoned: bool,
}

impl<M: CtMemory> CtSender<M> {
    /// Attach to an initialized descriptor before transport registration.
    /// This never resets live firmware-owned head/tail state.
    pub fn new(memory: M) -> Result<Self, GuCError> {
        let capacity = validate_capacity(&memory)?;
        let (_, tail) = descriptor(&memory, capacity)?;
        Ok(Self {
            memory,
            capacity,
            tail,
            poisoned: false,
        })
    }

    /// Queue one HXG host request. The caller reserves the CT fence and the
    /// pending-reply owner before calling, and rings GuC only after success.
    pub fn request(
        &mut self,
        fence_id: u16,
        action: u16,
        data0: u16,
        payload: &[u32],
        fast: bool,
    ) -> Result<(), GuCError> {
        if self.poisoned {
            return Err(GuCError::Poisoned);
        }
        if payload.len() > 254 || data0 > 0xfff {
            return Err(GuCError::Message);
        }
        let (head, tail) = match descriptor(&self.memory, self.capacity) {
            Ok(pair) if pair.1 == self.tail => pair,
            Ok(_) => {
                self.poisoned = true;
                return Err(GuCError::Cursor);
            }
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        // Pair the peer's release of consumed slots before reusing them.
        fence(Ordering::Acquire);
        let length = payload.len() as u32 + 2;
        let free = (head.wrapping_sub(tail).wrapping_sub(1)) & (self.capacity - 1);
        if length > free {
            return Err(GuCError::Full);
        }
        let header = ((fence_id as u32) << 16) | (length - 1);
        let hxg = (u32::from(fast) << 29) | ((data0 as u32) << 16) | action as u32;
        let mut next = tail;
        for word in core::iter::once(header)
            .chain(core::iter::once(hxg))
            .chain(payload.iter().copied())
        {
            self.memory.set_data(next, word);
            next = (next + 1) & (self.capacity - 1);
        }
        // A hardware release barrier, not merely a compiler barrier: GuC may
        // consume every dword as soon as it observes the new tail.
        fence(Ordering::Release);
        self.memory.set_descriptor(1, next);
        self.tail = next;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GuCMessage {
    pub fence: u16,
    pub kind: u8,
    pub auxiliary: u32,
    pub payload: Vec<u32>,
}

/// Host owns HEAD; GuC owns TAIL. Corruption is terminal for this software
/// owner and does not advance HEAD or release any pending job resources.
#[derive(Debug)]
pub struct CtReceiver<M: CtMemory> {
    memory: M,
    capacity: u32,
    head: u32,
    poisoned: bool,
}

impl<M: CtMemory> CtReceiver<M> {
    pub fn new(memory: M) -> Result<Self, GuCError> {
        let capacity = validate_capacity(&memory)?;
        let (head, _) = descriptor(&memory, capacity)?;
        Ok(Self {
            memory,
            capacity,
            head,
            poisoned: false,
        })
    }

    pub fn receive(&mut self) -> Result<Option<GuCMessage>, GuCError> {
        if self.poisoned {
            return Err(GuCError::Poisoned);
        }
        match self.receive_inner() {
            Ok(message) => Ok(message),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn receive_inner(&mut self) -> Result<Option<GuCMessage>, GuCError> {
        let (head, tail) = descriptor(&self.memory, self.capacity)?;
        if head != self.head {
            return Err(GuCError::Cursor);
        }
        let available = tail.wrapping_sub(head) & (self.capacity - 1);
        if available == 0 {
            return Ok(None);
        }
        fence(Ordering::Acquire);
        let header = self.memory.data(head);
        let payload_length = header & 0xff;
        if header & 0xff00 != 0 || payload_length == 0 || payload_length + 1 > available {
            return Err(GuCError::Message);
        }
        let hxg = self.memory.data((head + 1) & (self.capacity - 1));
        let kind = ((hxg >> 28) & 7) as u8;
        if hxg & (1 << 31) == 0 || kind == 4 {
            return Err(GuCError::Message);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_length as usize - 1)
            .map_err(|_| GuCError::Message)?;
        for i in 2..=payload_length {
            payload.push(self.memory.data((head + i) & (self.capacity - 1)));
        }
        let next = (head + payload_length + 1) & (self.capacity - 1);
        fence(Ordering::Release);
        self.memory.set_descriptor(0, next);
        self.head = next;
        Ok(Some(GuCMessage {
            fence: (header >> 16) as u16,
            kind,
            auxiliary: hxg & 0x0fff_ffff,
            payload,
        }))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::intel_gpu_uapi::put32;
    use alloc::sync::Arc;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    fn image() -> Vec<u8> {
        // CSS 32dw + 4dw uCode + RSA96dw; modulus96dw/exponent1dw
        // are declared in header_size but omitted from the truncated blob.
        let mut blob = vec![0; 528];
        for (at, value) in [
            (0, 6),
            (4, 225),
            (8, 0x10000),
            (16, 0x8086),
            (24, 229),
            (28, 96),
            (32, 96),
            (36, 1),
            (64, 0x0046_3500),
            (120, 0x0080_1000),
        ] {
            put32(&mut blob, at, value);
        }
        blob[128..144].fill(0xa5);
        blob[144..].fill(0x5a);
        blob
    }

    fn smoke_guc_css_ranges_and_truncated_suffix() -> TestResult {
        let blob = image();
        let parsed = match CssImage::parse(&blob, 70) {
            Ok(parsed) => parsed,
            Err(_) => return TestResult::Fail("valid CSS layout"),
        };
        if parsed.upload.len() != 144
            || parsed.upload[128..] != [0xa5; 16]
            || parsed.signature != [0x5a; 384]
            || parsed.version != (70, 53, 0)
            || parsed.private_data_bytes != 0x0080_1000
        {
            return TestResult::Fail("CSS firmware component ranges/version");
        }
        let mut full = blob.clone();
        full.resize(916, 0xbb);
        if CssImage::parse(&full, 70).is_err() {
            return TestResult::Fail("full optional CSS suffix");
        }
        full.pop();
        if CssImage::parse(&full, 70).is_ok() {
            return TestResult::Fail("partial optional suffix admitted");
        }
        for end in 0..blob.len() {
            if CssImage::parse(&blob[..end], 70).is_ok() {
                return TestResult::Fail("truncated required firmware component");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc",
        smoke_guc_css_ranges_and_truncated_suffix
    );

    fn smoke_guc_css_rejects_bad_lengths_and_versions() -> TestResult {
        for (at, value) in [
            (0, 0),
            (4, 0),
            (8, 0x20000),
            (16, 0xffff),
            (24, 225),
            (28, 0),
            (28, u32::MAX),
            (32, u32::MAX),
            (36, u32::MAX),
            (120, 4097),
            (120, 0x0800_0000),
        ] {
            let mut blob = image();
            put32(&mut blob, at, value);
            if CssImage::parse(&blob, 70).is_ok() {
                return TestResult::Fail("malformed CSS header admitted");
            }
        }
        if CssImage::parse(&image(), 69).err() != Some(GuCError::FirmwareVersion) {
            return TestResult::Fail("firmware ABI major mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc",
        smoke_guc_css_rejects_bad_lengths_and_versions
    );

    #[derive(Clone)]
    struct Memory(Arc<IrqSafeSpinLock<Words>>);
    struct Words {
        descriptor: [u32; 16],
        data: Vec<u32>,
        writes: usize,
    }
    impl Memory {
        fn new(head: u32, tail: u32) -> Self {
            let mut descriptor = [0; 16];
            descriptor[0] = head;
            descriptor[1] = tail;
            Self(Arc::new(IrqSafeSpinLock::new(Words {
                descriptor,
                data: vec![0; 256],
                writes: 0,
            })))
        }
    }
    impl CtMemory for Memory {
        fn capacity(&self) -> u32 {
            self.0.lock().data.len() as u32
        }
        fn descriptor(&self, word: usize) -> u32 {
            self.0.lock().descriptor[word]
        }
        fn set_descriptor(&self, word: usize, value: u32) {
            let mut memory = self.0.lock();
            memory.descriptor[word] = value;
            memory.writes += 1;
        }
        fn data(&self, word: u32) -> u32 {
            self.0.lock().data[word as usize]
        }
        fn set_data(&self, word: u32, value: u32) {
            let mut memory = self.0.lock();
            memory.data[word as usize] = value;
            memory.writes += 1;
        }
    }

    fn smoke_guc_ct_request_wrap_full_and_owner_corruption() -> TestResult {
        let memory = Memory::new(254, 254);
        let mut sender = CtSender::new(memory.clone()).expect("sender");
        if sender
            .request(0x1234, 0x4502, 0, &[0x1122_3344, 0x5566_7788], true)
            .is_err()
        {
            return TestResult::Fail("CT wrapped request");
        }
        if memory.data(254) != 0x1234_0003
            || memory.data(255) != 0x2000_4502
            || memory.data(0) != 0x1122_3344
            || memory.data(1) != 0x5566_7788
            || memory.descriptor(1) != 2
            || memory.descriptor(0) != 254
        {
            return TestResult::Fail("CT request wire/header/publication");
        }
        memory.set_descriptor(0, 3); // no free slot
        let writes = memory.0.lock().writes;
        if sender.request(2, 0x1000, 0, &[], false) != Err(GuCError::Full)
            || memory.0.lock().writes != writes
        {
            return TestResult::Fail("full CT buffer mutated");
        }
        memory.set_descriptor(1, 5); // firmware must not write host tail
        if sender.request(2, 0x1000, 0, &[], false) != Err(GuCError::Cursor)
            || sender.request(2, 0x1000, 0, &[], false) != Err(GuCError::Poisoned)
        {
            return TestResult::Fail("foreign CT tail modification not terminal");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc",
        smoke_guc_ct_request_wrap_full_and_owner_corruption
    );

    fn smoke_guc_ct_receive_wrap_and_failure_retains_head() -> TestResult {
        let memory = Memory::new(254, 1);
        memory.set_data(254, 0x1234_0002);
        memory.set_data(255, 0xf000_0005);
        memory.set_data(0, 0xdead_beef);
        let mut receiver = CtReceiver::new(memory.clone()).expect("receiver");
        let expected = GuCMessage {
            fence: 0x1234,
            kind: 7,
            auxiliary: 5,
            payload: vec![0xdead_beef],
        };
        if receiver.receive() != Ok(Some(expected))
            || memory.descriptor(0) != 1
            || receiver.receive() != Ok(None)
        {
            return TestResult::Fail("CT receive wire/wrapped head");
        }
        for (header, hxg, tail) in [
            (3, 0xf000_0000, 2),
            (0x1002, 0xf000_0000, 4),
            (2, 0x7000_0000, 4),
            (2, 0xc000_0000, 4),
        ] {
            let memory = Memory::new(1, tail);
            memory.set_data(1, header);
            memory.set_data(2, hxg);
            let mut receiver = CtReceiver::new(memory.clone()).expect("receiver");
            let writes = memory.0.lock().writes;
            if receiver.receive() != Err(GuCError::Message)
                || memory.descriptor(0) != 1
                || memory.0.lock().writes != writes
                || receiver.receive() != Err(GuCError::Poisoned)
            {
                return TestResult::Fail(
                    "malformed CT message released head or recovered silently",
                );
            }
        }
        let memory = Memory::new(0, 0);
        memory.set_descriptor(2, 4);
        if !matches!(CtSender::new(memory), Err(GuCError::DescriptorStatus(4))) {
            return TestResult::Fail("CT descriptor error ignored");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_guc",
        smoke_guc_ct_receive_wrap_and_failure_retains_head
    );
}
