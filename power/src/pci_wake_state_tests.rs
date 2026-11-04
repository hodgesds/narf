//! Exact endpoint D-state admission and non-executing power-method discovery.
use super::*;
use alloc::collections::BTreeMap;
use core::cell::Cell;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Objects {
    values: BTreeMap<String, Value>,
    power_method_evaluations: Cell<usize>,
}

impl Namespace for Objects {
    fn devices(&self) -> Vec<String> {
        Vec::new()
    }
    fn exists(&self, path: &str) -> bool {
        self.values.contains_key(path)
    }
    fn object(&self, path: &str) -> Result<Option<Value>, WakeError> {
        if path.ends_with("._PS3") {
            self.power_method_evaluations
                .set(self.power_method_evaluations.get() + 1);
        }
        Ok(self.values.get(path).cloned())
    }
}

fn endpoint_bounds() -> Result<(), &'static str> {
    let endpoint = "\\_SB.PCI0.RP01.EP00";
    let mut ns = Objects::default();
    ns.values
        .insert("\\_SB.PCI0.RP01._S0W".into(), Value::Integer(3));
    ns.values
        .insert(format!("{endpoint}._S0W"), Value::Integer(0));
    if admit(&ns, Some(endpoint), SleepState::S0Idle, WakeState::D3Hot)
        != Err(WakeError::Unsupported)
        || admit(&ns, Some(endpoint), SleepState::S0Idle, WakeState::D0) != Ok(())
    {
        return Err("ancestor wake route overrode the actual endpoint D-state ceiling");
    }
    ns.values
        .insert("\\_SB.PCI0.RP01._S0W".into(), Value::Integer(0));
    ns.values
        .insert(format!("{endpoint}._S0W"), Value::Integer(3));
    if admit(&ns, Some(endpoint), SleepState::S0Idle, WakeState::D3Hot) != Ok(())
        || admit(&ns, None, SleepState::S0Idle, WakeState::D3Hot) != Ok(())
    {
        return Err("a root-port D-state was assigned to its child function");
    }
    ns.values
        .insert(format!("{endpoint}._S3D"), Value::Integer(2));
    if admit(&ns, Some(endpoint), SleepState::S3, WakeState::D3Hot) != Err(WakeError::Unsupported) {
        return Err("absent _S3W ignored an actual _S3D wake ceiling");
    }
    ns.values
        .insert(format!("{endpoint}._S3W"), Value::Integer(3));
    if admit(&ns, Some(endpoint), SleepState::S3, WakeState::D3Hot) != Ok(()) {
        return Err("valid endpoint _S3D/_S3W interval was refused");
    }
    ns.values
        .insert(format!("{endpoint}._S3W"), Value::Integer(1));
    if admit(&ns, Some(endpoint), SleepState::S3, WakeState::D3Hot) != Err(WakeError::Unsupported) {
        return Err("contradictory firmware D-state bounds manufactured a permitted state");
    }
    Ok(())
}

fn pci_wake_endpoint_power_limits_are_distinct_from_ancestor_wake_routing() -> TestResult {
    endpoint_bounds().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "power/pci_wake",
    pci_wake_endpoint_power_limits_are_distinct_from_ancestor_wake_routing
);

fn pci_wake_power_method_discovery_never_executes_the_power_transition() -> TestResult {
    let endpoint = "\\_SB.PCI0.RP01.EP00";
    let mut ns = Objects::default();
    ns.values
        .insert(format!("{endpoint}._PS3"), Value::Integer(0));
    if admit(&ns, Some(endpoint), SleepState::S0Idle, WakeState::D3Hot)
        != Err(WakeError::Unsupported)
        || ns.power_method_evaluations.get() != 0
    {
        return TestResult::Fail(
            "probing a firmware power method executed it or bypassed its owner",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "power/pci_wake",
    pci_wake_power_method_discovery_never_executes_the_power_transition
);
