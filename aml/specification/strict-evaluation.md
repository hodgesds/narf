# Strict bounded firmware evaluation

## 1. Purpose and scope

Provide an opt-in method/data evaluator for callers, including device wake,
that need executed firmware operations and propagated failures as a receipt.
The compatibility evaluator retains its existing behavior.

## 2. Assumptions

The namespace and OpRegions come from actual loaded firmware. The subsystem
invoking a hardware method holds its current platform authority. The AML
interpreter does not mint, derive or replace that authority.

## 3. Public interface

`eval::strict::evaluate_object(absolute_path,args)` returns
`Result<Value, strict::Error>`. `evaluate_method` returns a distinct
`Completion::Void` or `Completion::Value(Value)`. A completed void `_DSW`
and a void helper statement are valid; using a void method as a data object,
predicate, Store source or returned expression fails `NoReturnValue`.
They resolve exact objects and single-NameSeg
scope walks; no global suffix fallback can supply an unrelated object.
Data objects support integers, strings, buffers and bounded packages.
Ordinary methods support integer arithmetic/bit operations, Store, Return,
If/Else, While/Break/Continue, locals/arguments, nested method calls and checked
plain Fields. Helpers share the outer execution budget and propagate errors
even when their return value is discarded. Unknown instructions, missing
names/arguments, unsupported method locking/region semantics and malformed
extents are failures. An executed Return or complete supported body supplies
a receipt; the interpreter never substitutes success for skipped operations.

Every outer evaluation has 8192 operation steps, a five-second monotonic
deadline and at most 16 nested execution/data frames. Individual method/data
byte streams are limited to 64 KiB and packages to 256 elements. Budget failure
is terminal for that evaluation. No implicit wait, serialized-method lock,
global-lock owner or unsupported opcode is synthesized.

Strict evaluation requires a known 64-bit Integer profile derived from the
actual DSDT revision 2 or later. Unknown and 32-bit profiles are refused; the
compatibility evaluator is unchanged. Logical TRUE is the actual AML
all-ones Integer. LEqual supports Integer/Integer, String/String and
Buffer/Buffer only; mixed and Package pairs are explicitly unsupported.
Locals start uninitialized and cannot be read before a real Store. Fixed
Name Store supports only Integer into an existing Integer Name; conversions,
type replacement and buffer-length semantics are refused rather than guessed.

`oregion::{read_field_checked,write_field_checked}` admit plain AnyAcc/ByteAcc
Fields of 1–64 bits, with known update rules, no LockRule and no bank/index
indirection. `FieldInfo::lock_rule` retains FieldFlags bit4 rather than losing
the firmware lock requirement. Extents and address arithmetic must fit the
actual declared region. Byte access supports mapped SystemMemory, x86
SystemIO and the actual configured EC transaction path. Checked EC admission
uses a nonblocking transaction-gate claim; contention is a failure rather
than an unbounded wait. The unchanged under-gate hardware transaction retains
its bounded scheduler-compatible waits. Mapping/EC failures
propagate; stub spaces, PCI-config resolution, bank/index fields, global-lock
requirements and other access widths are refused. A multi-byte write can
partially complete before an error; callers retain their operation and run
the matching firmware rollback.

The `kernel-test` feature provides `unsafe __test_namespace_scope`, an owned
namespace/bytecode/OpRegion-table scope restored on Drop. It must be serialized
against all real AML evaluation and does not isolate unrelated platform
registries. That scoped synthetic profile explicitly selects 64-bit Integers;
production can obtain the width only from the actual DSDT header. These
fixtures are absent from production.

## 4. Invariants

Unsupported operations and missing hardware handlers never become Integer0
or successful no-ops. Nested failures cannot be discarded. Bounds, budget,
name identity and actual Field receipts precede a success result. Existing
compatibility callers do not silently acquire the strict profile. Firmware
side effects are not atomic; a failure does not revoke completed writes.

## 5. Architecture

The evaluator's control/data paths are shared by x86_64 and aarch64. Checked
SystemIO/EC access is x86_64-only. SystemMemory uses actual Device mappings;
no raw physical-pointer or architectural fallback is assumed.

## 6. Dependencies

Loaded AML namespace/bytecode, exact name lookup, monotonic clock, checked
OpRegion accessors and the caller's explicit platform authority.

## 7. Stage assignment

Stage5 firmware-operation receipt infrastructure. Software fixtures do not
qualify a board's firmware methods, wake wiring or physical transition.

## 8. Open questions

Serialized methods, ACPI Global Lock, checked PCI-config/serial-bus handlers,
bank/index fields, additional AML operations and broader field access widths
require explicit bounded owners. Unsupported forms remain errors.
