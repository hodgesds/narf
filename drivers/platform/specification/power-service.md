# Platform power service and SCI wake

## 1. Purpose and scope

Compose actual platform event sources, existing Power authority, device
preparation and the SCI wake path for system sleep.

## 2. Assumptions

Platform initialization owns its explicit Power grant and installs the actual
SCI route. Firmware namespace discovery precedes wake-route resolution.

## 3. Public interface

`power_service::init` delegates its already-issued Power grant to
`power::pci_wake::install_authority`, alongside the existing service action
executor and state providers. Wireless drivers receive no ambient Power grant.

`ec::dispatch_sci` reads real fixed-FADT status and calls the allocation-free
`power::pci_wake::note_gpe_irq` for each observed GPE before W1C-clear/deferred
dispatch. Ordinary EC/AML/subscriber work retains its task-context path;
entering a parked CPU does not depend on that task being scheduled.

Platform suspend/freeze service actions schedule the corresponding async
power coordinator with the composition root's existing Invoke authority.
The coordinator passes S3 or S0Idle to target-aware driver preparation.
Callbacks never call `block_on` recursively from an executor poll.

A successful power-state store acknowledges submission to the service. It
does not claim the machine has suspended or resumed. `last_sleep_request()`
returns an `Arc<SleepRequest>` with its action and `result()`: `None` while queued or
running, `Some(Ok(()))` only after actual successful resume, or
`Some(Err(SuspendError))` for refusal/failure. Each task owns its exact Arc,
so a later request cannot replace the completion seen by an earlier reader.
Failures are also logged to the platform console. Current capability and
actual S3/s2idle support are validated before spawn; a refused request
completes immediately with its error and queues no task. The same captured
Invoke capability is rechecked by the coordinator across pending preparation.

## 4. Invariants

Hard-IRQ observation allocates nothing, evaluates no AML and awaits nothing.
Only a currently leased actual GPE can create a PCI device-wake record.
Existing shared GPE handlers and enable bits retain their ownership. Device
prepare failures abort entry and unwind already-prepared drivers.
Test isolation restores only the PM registration surfaces it owns. It drives
the actual spawned coordinator with bounded executor rounds, preserving
scheduler initialization and existing Stage::Late queued tasks.

## 5. Architecture

The current fixed-FADT byte-port SCI path is x86_64. This composition adds
no aarch64 deliverable wake source or production s2idle opt-in.

## 6. Dependencies

Power service/coordinators, scheduler, bus endpoint authority, ACPI FADT and
the existing AML/platform event owners.

## 7. Stage assignment

Stage5 platform sleep integration. Actual board wake remains physical
acceptance work.

## 8. Open questions

Native Root Port PME service, external-GPE blocks, MMIO wake registers and
additional platform wake lines need their own explicit route owners.
