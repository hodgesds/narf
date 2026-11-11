# Processor namespace identity

## 1. Purpose & scope

Preserve the identity declared by legacy AML Processor objects.

## 2. Assumptions

Namespace construction uses the existing bounded AML parser.

## 3. Public interface

`AmlNode::processor_id: Option<u8>` retains the ProcID byte of `Processor()`.
It is `None` for other nodes. It is a firmware identifier, not an APIC ID or
logical CPU number. ACPI0007 devices continue to expose identity through `_UID`.

## 4. Invariants

Truncated Processor objects do not create namespace nodes. Names and `_UID`
values are not inferred from namespace enumeration order or a CPU name suffix.

## 5. Architecture

The namespace representation is shared across architectures.

## 6. Dependencies

Existing namespace parser and node lookup APIs.

## 7. Stage assignment

Stage 5 CPU power management.

## 8. Open questions

Dynamic processor hot-add and namespace removal retain their existing scope.
