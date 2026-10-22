use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

pub(crate) struct Monitor {
    pub caps: Vec<u8>,
    pub value: u16,
    pub refuse_set: bool,
    pub reply: Vec<u8>,
    pub requests: Vec<Vec<u8>>,
    pub delays: Vec<u64>,
    pub fault: Option<Error>,
    pub corrupt: bool,
    pub wrong_offset: bool,
    pub wrong_code: bool,
    pub nulls: usize,
    pub stall_after: Option<usize>,
}
impl Default for Monitor {
    fn default() -> Self {
        Self {
            caps: b"(prot(monitor)type(lcd)vcp(10 12 E0(00 01))mccs_ver(2.2))".to_vec(),
            value: 1,
            refuse_set: false,
            reply: Vec::new(),
            requests: Vec::new(),
            delays: Vec::new(),
            fault: None,
            corrupt: false,
            wrong_offset: false,
            wrong_code: false,
            nulls: 0,
            stall_after: None,
        }
    }
}
pub(crate) fn response(payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x6e, 0x80 | payload.len() as u8];
    b.extend_from_slice(payload);
    b.push(b.iter().fold(0x50, |s, b| s ^ b));
    b
}
impl Monitor {
    pub fn write(&mut self, b: &[u8]) {
        assert_eq!(b[0], 0x51);
        assert_eq!(usize::from(b[1] & 0x7f) + 3, b.len());
        assert_eq!(b.iter().fold(0x6e, |s, b| s ^ b), 0);
        self.requests.push(b.to_vec());
        self.reply = match b[2] {
            0xf3 => {
                assert_eq!(b.len(), 6);
                let off = usize::from(u16::from_be_bytes([b[3], b[4]]));
                assert!(off <= self.caps.len());
                let n = (self.caps.len() - off).min(17);
                let mut p = vec![0xe3, b[3], b[4] ^ u8::from(self.wrong_offset)];
                p.extend_from_slice(&self.caps[off..off + n]);
                response(&p)
            }
            1 => {
                assert_eq!(b.len(), 5);
                let [h, l] = self.value.to_be_bytes();
                response(&[2, 0, b[3] ^ u8::from(self.wrong_code), 0, 0xff, 0xff, h, l])
            }
            3 => {
                assert_eq!(&b[2..6], &[3, 0xe0, 1, 1]);
                if !self.refuse_set {
                    self.value = 0x0101;
                }
                Vec::new()
            }
            _ => panic!("unexpected MCCS opcode"),
        };
        if self.corrupt && !self.reply.is_empty() {
            self.reply[2] ^= 1;
        }
    }
    pub fn read(&mut self, b: &mut [u8]) {
        b.fill(0xff);
        if self.nulls != 0 {
            self.nulls -= 1;
            b[..3].copy_from_slice(&[0x6e, 0x80, 0xbe]);
        } else {
            assert!(b.len() >= self.reply.len());
            b[..self.reply.len()].copy_from_slice(&self.reply);
        }
    }
}
impl Bus for Monitor {
    async fn write(&mut self, b: &mut [u8]) -> Result<(), Error> {
        if let Some(e) = self.fault {
            return Err(e);
        }
        self.write(b);
        Ok(())
    }
    async fn read(&mut self, b: &mut [u8]) -> Result<(), Error> {
        if let Some(e) = self.fault {
            return Err(e);
        }
        self.read(b);
        Ok(())
    }
    async fn delay(&mut self, us: u64) {
        self.delays.push(us);
        if self.stall_after.is_some_and(|n| self.requests.len() >= n) {
            core::future::pending::<()>().await;
        }
    }
}
pub(crate) fn metadata() -> AmdVsdb {
    AmdVsdb {
        version: 3,
        min_hz: 48,
        max_hz: 144,
        vcp_code: 0xe0,
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn ddcci_frames_offsets_and_verified_enable_are_exact() -> TestResult {
    let mut m = Monitor::default();
    let proof = run(negotiate(&mut m, 7, metadata())).unwrap();
    assert_eq!(
        proof.range(7, metadata()),
        Some(VrrRange {
            min_hz: 48,
            max_hz: 144
        })
    );
    assert!(proof.range(8, metadata()).is_none());
    assert!(proof
        .range(
            7,
            AmdVsdb {
                vcp_code: 0xe1,
                ..metadata()
            }
        )
        .is_none());
    assert_eq!(m.requests.last().unwrap()[2], 1);
    let set = m.requests.iter().find(|b| b[2] == 3).unwrap();
    assert_eq!(set, &vec![0x51, 0x84, 3, 0xe0, 1, 1, 0x58]);
    let offsets: Vec<_> = m
        .requests
        .iter()
        .filter(|b| b[2] == 0xf3)
        .map(|b| u16::from_be_bytes([b[3], b[4]]))
        .collect();
    assert_eq!(offsets, vec![0, 17, 34, 51, 57]);
    assert!(m.delays.iter().all(|&n| n == 40_000 || n == 50_000));
    assert_eq!(reply(&[0x6e, 0x80, 0xbe]), Ok(&[][..]));
    for b in [
        &[0x6f, 0x80, 0xbf][..],
        &[0x6e, 0, 0x3e],
        &[0x6e, 0xa4, 0],
        &[0x6e, 0x88, 2],
        &[0x6e, 0x80, 0],
    ] {
        assert_eq!(reply(b), Err(Error::InvalidMccs));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mccs",
    ddcci_frames_offsets_and_verified_enable_are_exact
);
fn ddcci_capability_grammar_never_infers_vendor_support() -> TestResult {
    for text in [
        b"(vcp(E0))".as_slice(),
        b"(VCP(10 E0(00 01) 12))",
        b"vcp(10 e0)prot(monitor)",
        b"(vcp(1012E0(0001)F7(01(02 03))))",
        b"(vcp(E0()))",
    ] {
        assert_eq!(advertises_vcp(text, 0xe0), Ok(true));
    }
    for text in [
        b"(vcp(10(00 E0) 12))".as_slice(),
        b"(model(vcp(E0))vcp(10))",
        b"(vcp(E1))",
    ] {
        assert_eq!(advertises_vcp(text, 0xe0), Ok(false));
    }
    for text in [
        b"(vcp(E0)".as_slice(),
        b"(vcp(E00))",
        b"(vcp(E0\0))",
        b"(vcp(E0))garbage",
    ] {
        assert_eq!(advertises_vcp(text, 0xe0), Err(Error::InvalidMccs));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mccs",
    ddcci_capability_grammar_never_infers_vendor_support
);
fn ddcci_refusals_and_retries_never_publish_an_enable_proof() -> TestResult {
    for case in 0..9 {
        let mut m = Monitor::default();
        let expected = match case {
            0 => {
                m.caps = b"(vcp(10))".to_vec();
                Error::MccsUnsupported
            }
            1 => {
                m.value = 0;
                Error::MccsUnsupported
            }
            2 => {
                m.refuse_set = true;
                Error::MccsUnsupported
            }
            3 => {
                m.corrupt = true;
                Error::InvalidMccs
            }
            4 => {
                m.wrong_offset = true;
                Error::InvalidMccs
            }
            5 => {
                m.wrong_code = true;
                Error::InvalidMccs
            }
            6 => {
                m.nulls = ATTEMPTS;
                Error::MccsUnsupported
            }
            7 => {
                m.fault = Some(Error::Timeout);
                Error::Timeout
            }
            _ => {
                m.caps = vec![b'x'; MAX_CAPS + 1];
                Error::InvalidMccs
            }
        };
        assert_eq!(run(negotiate(&mut m, 1, metadata())), Err(expected));
        assert!(m.requests.len() <= MAX_CAPS + 8);
        if case != 2 {
            assert!(!m.requests.iter().any(|b| b[2] == 3));
        }
        if case == 3 || case == 6 {
            assert_eq!(m.requests.len(), ATTEMPTS);
        }
        if case == 7 {
            assert!(m.requests.is_empty());
        }
    }
    let mut m = Monitor {
        nulls: 2,
        ..Default::default()
    };
    assert!(run(negotiate(&mut m, 9, metadata())).is_ok());
    // A final data fragment may contain a C terminator and padding. Its
    // full wire length still advances the next request's offset; only an
    // empty fragment terminates the transfer. Never accept interior NUL.
    for tail in [b"\0".as_slice(), b" \0\0 ", b"   "] {
        let mut m = Monitor::default();
        m.caps.extend_from_slice(tail);
        assert!(run(negotiate(&mut m, 10, metadata())).is_ok());
        let last_cap = m.requests.iter().rev().find(|b| b[2] == 0xf3).unwrap();
        assert_eq!(
            usize::from(u16::from_be_bytes([last_cap[3], last_cap[4]])),
            m.caps.len()
        );
    }
    let mut m = Monitor {
        caps: b"(vcp(E0))\0(vcp(E1))".to_vec(),
        ..Default::default()
    };
    assert_eq!(
        run(negotiate(&mut m, 11, metadata())),
        Err(Error::InvalidMccs)
    );
    assert!(!m.requests.iter().any(|b| b[2] == 3));

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mccs",
    ddcci_refusals_and_retries_never_publish_an_enable_proof
);
