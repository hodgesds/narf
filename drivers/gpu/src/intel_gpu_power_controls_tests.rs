use super::*;
use crate::intel_gpu_slpc::Limits;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Firmware {
    status: Status,
    state: SlpcState,
    requests: Vec<Change>,
    pending: Option<Change>,
    refuse: bool,
}
impl Firmware {
    fn new() -> Self {
        Self {
            status: Status {
                limits: Limits {
                    rpn_mhz: 300,
                    rpe_mhz: 600,
                    rp0_mhz: 1200,
                    min_mhz: 300,
                    max_mhz: 1200,
                },
                range: FrequencyRange {
                    min_mhz: 300,
                    max_mhz: 1200,
                },
                profile: PowerProfile::Base,
            },
            state: SlpcState::Running,
            requests: Vec::new(),
            pending: None,
            refuse: false,
        }
    }
    fn ack(&mut self) {
        match self.pending.take().expect("issued control") {
            Change::Range(range) => self.status.range = range,
            Change::Profile(profile) => self.status.profile = profile,
        }
        self.state = SlpcState::Running;
    }
}
impl Target for Firmware {
    fn state(&self) -> SlpcState {
        self.state
    }
    fn status(&self) -> Option<Status> {
        (self.state == SlpcState::Running).then_some(self.status)
    }
    fn begin(&mut self, change: Change, _: u64) -> Result<(), SlpcError> {
        if self.refuse {
            return Err(SlpcError::Busy);
        }
        assert!(self.pending.is_none());
        self.requests.push(change);
        self.pending = Some(change);
        self.state = SlpcState::Updating;
        Ok(())
    }
}
fn ready() -> (PowerControls, Firmware) {
    let control = PowerControls::new();
    let mut firmware = Firmware::new();
    control.activate(7);
    control.service_target(&mut firmware, 7, 0);
    (control, firmware)
}

fn slpc_policy_store_waits_for_owner_and_firmware_receipt() -> TestResult {
    let (control, mut firmware) = ready();
    assert_eq!(control.show("gt_min_freq_mhz"), "300\n");
    assert_eq!(control.store("slpc_frequency_range", b"400 1000\n"), Ok(()));
    assert!(firmware.requests.is_empty());
    assert!(control.confirmed().is_none());
    assert!(control.show("slpc_status").contains("Queued(1)"));
    assert_eq!(
        control.request_profile(PowerProfile::Base),
        Err(FsError::Busy)
    );
    control.service_target(&mut firmware, 7, 10);
    assert_eq!(
        firmware.requests,
        [Change::Range(FrequencyRange {
            min_mhz: 400,
            max_mhz: 1000
        })]
    );
    assert!(control.show("slpc_frequency_range").is_empty());
    control.service_target(&mut firmware, 7, 20);
    assert!(control.confirmed().is_none());
    firmware.ack();
    control.service_target(&mut firmware, 7, 30);
    assert_eq!(control.show("slpc_frequency_range"), "400 1000\n");
    assert!(control.show("slpc_status").contains("Applied(1)"));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    slpc_policy_store_waits_for_owner_and_firmware_receipt
);

fn slpc_policy_validates_userspace_and_fused_workaround_limits() -> TestResult {
    let (control, mut firmware) = ready();
    for (attribute, bytes) in [
        ("gt_min_freq_mhz", &b"-1"[..]),
        ("gt_max_freq_mhz", &b"4294967296"[..]),
        ("slpc_frequency_range", &b"400 900 extra"[..]),
        ("slpc_frequency_range", &b"400"[..]),
        ("slpc_frequency_range", &b"900 400"[..]),
        ("slpc_frequency_range", &b"0 1200"[..]),
        ("gt_max_freq_mhz", &b"1300"[..]),
        ("slpc_power_profile", &b"turbo"[..]),
        ("slpc_power_profile", &[0xff][..]),
    ] {
        assert_eq!(control.store(attribute, bytes), Err(FsError::InvalidData));
        assert!(control.confirmed().is_some());
    }
    firmware.status.limits = Limits {
        rpn_mhz: 300,
        rpe_mhz: 1500,
        rp0_mhz: 2850,
        min_mhz: 1200,
        max_mhz: 2133,
    };
    firmware.status.range = FrequencyRange {
        min_mhz: 1200,
        max_mhz: 2133,
    };
    control.service_target(&mut firmware, 7, 0);
    assert_eq!(
        control.request_range(FrequencyRange {
            min_mhz: 1199,
            max_mhz: 2100
        }),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        control.request_range(FrequencyRange {
            min_mhz: 1200,
            max_mhz: 2134
        }),
        Err(FsError::InvalidData)
    );
    assert_eq!(control.store("gt_min_freq_mhz", b"1250"), Ok(()));
    control.service_target(&mut firmware, 7, 1);
    firmware.ack();
    control.service_target(&mut firmware, 7, 2);
    assert_eq!(control.show("gt_min_freq_mhz"), "1250\n");
    assert_eq!(control.show("gt_RP0_freq_mhz"), "2850\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    slpc_policy_validates_userspace_and_fused_workaround_limits
);

fn slpc_policy_close_invalidates_queued_and_inflight_work() -> TestResult {
    for issued in [false, true] {
        let (control, mut firmware) = ready();
        control
            .store("slpc_power_profile", b"power-saving")
            .unwrap();
        if issued {
            control.service_target(&mut firmware, 7, 1);
        }
        control.close();
        if issued {
            firmware.ack();
        }
        control.service_target(&mut firmware, 7, 2);
        assert!(control.confirmed().is_none());
        assert_eq!(
            control.store("gt_min_freq_mhz", b"400"),
            Err(FsError::NoDevice)
        );
        assert_eq!(firmware.requests.len(), usize::from(issued));
        control.activate(8);
        control.service_target(&mut firmware, 7, 3);
        assert!(control.confirmed().is_none());
        control.service_target(&mut firmware, 8, 4);
        assert!(control.confirmed().is_some());
        assert!(control.state.lock().queued.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    slpc_policy_close_invalidates_queued_and_inflight_work
);

fn slpc_policy_failure_is_terminal_without_inventing_confirmation() -> TestResult {
    let (control, mut firmware) = ready();
    control.request_profile(PowerProfile::PowerSaving).unwrap();
    firmware.refuse = true;
    control.service_target(&mut firmware, 7, 0);
    assert!(control.show("slpc_status").contains("Failed(1, Busy)"));
    assert_eq!(control.show("slpc_power_profile"), "base\n");
    firmware.refuse = false;
    control.request_profile(PowerProfile::PowerSaving).unwrap();
    control.service_target(&mut firmware, 7, 1);
    firmware.state = SlpcState::Unavailable;
    control.service_target(&mut firmware, 7, 2);
    assert!(control.confirmed().is_none());
    assert!(control
        .show("slpc_status")
        .contains("Failed(2, Unavailable)"));
    assert!(control.show("slpc_power_profile").is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    slpc_policy_failure_is_terminal_without_inventing_confirmation
);

fn slpc_policy_replays_only_confirmed_policy_in_fresh_epoch() -> TestResult {
    let (control, mut firmware) = ready();
    control.store("slpc_frequency_range", b"400 1000").unwrap();
    control.service_target(&mut firmware, 7, 0);
    firmware.ack();
    control.service_target(&mut firmware, 7, 1);
    control
        .store("slpc_power_profile", b"power-saving")
        .unwrap();
    control.service_target(&mut firmware, 7, 2);
    firmware.ack();
    control.service_target(&mut firmware, 7, 3);
    control.close();
    let mut resumed = Firmware::new();
    control.activate(8);
    control.service_target(&mut resumed, 7, 4);
    assert!(resumed.requests.is_empty());
    control.service_target(&mut resumed, 8, 5);
    assert!(control.confirmed().is_none());
    control.service_target(&mut resumed, 8, 6);
    resumed.ack();
    control.service_target(&mut resumed, 8, 7);
    control.service_target(&mut resumed, 8, 8);
    control.service_target(&mut resumed, 8, 9);
    resumed.ack();
    control.service_target(&mut resumed, 8, 10);
    assert_eq!(
        resumed.requests,
        [
            Change::Range(FrequencyRange {
                min_mhz: 400,
                max_mhz: 1000
            }),
            Change::Profile(PowerProfile::PowerSaving),
        ]
    );
    assert_eq!(control.show("slpc_frequency_range"), "400 1000\n");
    assert_eq!(control.show("slpc_power_profile"), "power-saving\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_slpc",
    slpc_policy_replays_only_confirmed_policy_in_fresh_epoch
);
