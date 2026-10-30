use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Firmware {
    devices: Vec<String>,
    objects: Vec<(String, Value)>,
}

impl Firmware {
    fn new() -> Self {
        Self {
            devices: Vec::new(),
            objects: Vec::new(),
        }
    }

    fn device(&mut self, path: &str) {
        self.devices.push(String::from(path));
    }

    fn set(&mut self, path: &str, name: &str, value: Value) {
        let key = format!("{path}.{name}");
        if let Some(slot) = self.objects.iter_mut().find(|(path, _)| *path == key) {
            slot.1 = value;
        } else {
            self.objects.push((key, value));
        }
    }

    fn root(&mut self, path: &str, segment: u64, bus: u64) {
        self.device(path);
        self.set(path, "_HID", Value::String(String::from("PNP0A08")));
        self.set(path, "_SEG", Value::Integer(segment));
        self.set(path, "_BBN", Value::Integer(bus));
    }

    fn prw(&mut self, path: &str, gpe: u64, deepest: u64) {
        self.set(
            path,
            "_PRW",
            Value::Package(alloc::vec![Value::Integer(gpe), Value::Integer(deepest)]),
        );
    }
}

impl Namespace for Firmware {
    fn devices(&self) -> Vec<String> {
        self.devices.clone()
    }

    fn object(&self, path: &str) -> Result<Option<Value>, WakeError> {
        Ok(self
            .objects
            .iter()
            .find(|(key, _)| key == path)
            .map(|(_, value)| value.clone()))
    }
}

fn actual_endpoint_and_ancestor_prw_are_bound_to_exact_pci_root() -> Result<(), &'static str> {
    let mut fw = Firmware::new();
    fw.root("\\_SB.PCI0", 0, 0);
    fw.root("\\_SB.PCI1", 1, 0x40);
    fw.device("\\_SB.PCI0.RP01");
    fw.set("\\_SB.PCI0.RP01", "_ADR", Value::Integer(1 << 16));
    fw.prw("\\_SB.PCI0.RP01", 0x6d, 3);
    fw.device("\\_SB.PCI0.RP01.WLAN");
    fw.set("\\_SB.PCI0.RP01.WLAN", "_ADR", Value::Integer(0));
    // A same-named firmware node in another real PCI segment must never
    // supply this endpoint's wake route by suffix matching.
    fw.device("\\_SB.PCI1.RP01");
    fw.set("\\_SB.PCI1.RP01", "_ADR", Value::Integer(1 << 16));
    fw.prw("\\_SB.PCI1.RP01", 0x45, 5);
    let route = discover_route(&fw, 0, 0, &[8, 0]).map_err(|_| "actual ancestor route rejected")?;
    if route.path != "\\_SB.PCI0.RP01" || route.gpe != 0x6d || route.deepest_sleep != 3 {
        return Err("route borrowed a different segment's firmware object");
    }
    fw.prw("\\_SB.PCI0.RP01.WLAN", 0x31, 4);
    let route = discover_route(&fw, 0, 0, &[8, 0]).map_err(|_| "endpoint route rejected")?;
    if route.path != "\\_SB.PCI0.RP01.WLAN" || route.gpe != 0x31 {
        return Err("nearest exact endpoint _PRW was not selected");
    }
    let other = discover_route(&fw, 1, 0x40, &[8, 0]).map_err(|_| "other actual root rejected")?;
    if other.gpe != 0x45 {
        return Err("_SEG/_BBN did not select the actual root");
    }
    if !matches!(
        discover_route(&fw, 0, 0x40, &[8, 0]),
        Err(WakeError::Unsupported)
    ) {
        return Err("a guessed root bus was accepted");
    }
    fw.set("\\_SB.PCI0.RP01.WLAN", "_STA", Value::Integer(0));
    let route =
        discover_route(&fw, 0, 0, &[8, 0]).map_err(|_| "present parent fallback rejected")?;
    if route.path != "\\_SB.PCI0.RP01" {
        return Err("absent endpoint supplied a wake route");
    }
    Ok(())
}

fn ambiguous_or_unsupported_acpi_wake_objects_never_make_routes() -> Result<(), &'static str> {
    let mut fw = Firmware::new();
    fw.root("\\_SB.PCI0", 0, 0);
    fw.device("\\_SB.PCI0.RP01");
    fw.set("\\_SB.PCI0.RP01", "_ADR", Value::Integer(1 << 16));
    fw.prw("\\_SB.PCI0.RP01", 0x6d, 3);
    for value in [
        Value::Package(alloc::vec![
            Value::Package(alloc::vec![Value::Integer(0), Value::Integer(0x6d)]),
            Value::Integer(3),
        ]),
        Value::Package(alloc::vec![
            Value::Integer(0x6d),
            Value::Integer(3),
            Value::Integer(0)
        ]),
        Value::Package(alloc::vec![
            Value::Integer(0x1_0000_006d),
            Value::Integer(3)
        ]),
        Value::Package(alloc::vec![Value::Integer(128), Value::Integer(3)]),
        Value::Package(alloc::vec![Value::Integer(0x6d), Value::Integer(6)]),
    ] {
        fw.set("\\_SB.PCI0.RP01", "_PRW", value);
        if !matches!(
            discover_route(&fw, 0, 0, &[8, 0]),
            Err(WakeError::Unsupported)
        ) {
            return Err("external-GPE, power-resource or out-of-range _PRW was accepted");
        }
    }
    fw.prw("\\_SB.PCI0.RP01", 0x6d, 3);
    fw.device("\\_SB.PCI0.RPXX");
    fw.set("\\_SB.PCI0.RPXX", "_ADR", Value::Integer(1 << 16));
    if !matches!(
        discover_route(&fw, 0, 0, &[8, 0]),
        Err(WakeError::Ambiguous)
    ) {
        return Err("duplicate actual PCI function aliases were accepted");
    }
    fw.set("\\_SB.PCI0.RPXX", "_ADR", Value::Integer(2 << 16));
    fw.root("\\_SB.OTHER", 0, 0);
    if !matches!(
        discover_route(&fw, 0, 0, &[8, 0]),
        Err(WakeError::Ambiguous)
    ) {
        return Err("ambiguous root identity was accepted");
    }
    // The real host bridge's _PRW can route an endpoint even when firmware
    // omits all PCI children, as acpi_pci_propagate_wakeup permits.
    let mut root_only = Firmware::new();
    root_only.root("\\_SB.PCI0", 0, 0);
    root_only.prw("\\_SB.PCI0", 0x11, 3);
    let route = discover_route(&root_only, 0, 0, &[8, 0])
        .map_err(|_| "actual host-bridge route rejected")?;
    if route.path != "\\_SB.PCI0" || route.gpe != 0x11 {
        return Err("host-bridge fallback used an invented child");
    }
    Ok(())
}

fn route_topology() -> TestResult {
    actual_endpoint_and_ancestor_prw_are_bound_to_exact_pci_root()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("power/pci_wake", route_topology);

fn route_ambiguity() -> TestResult {
    ambiguous_or_unsupported_acpi_wake_objects_never_make_routes()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!("power/pci_wake", route_ambiguity);
