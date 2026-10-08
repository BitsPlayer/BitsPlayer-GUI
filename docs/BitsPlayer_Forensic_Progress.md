# BitsPlayer Forensic Integrity Development Progress

## Purpose of this document

This document summarizes the forensic-integrity work implemented so far
in the **BitsPlayer-GUI** project. It is intended to help all team
members understand what has changed, why it was added, how the current
implementation works, and what remains to be implemented.

> **Current status:** Analyze and Extract still do the MP4 work. Each
> session now keeps a hash-chained audit, seals that chain when the
> window closes, and shows the chain in the Custody tab. Closing the
> window runs the same verifier as `bitsplayer-verify` and leaves the
> checklist on screen until the examiner exits.

------------------------------------------------------------------------

## 1. Original project context

BitsPlayer is a Rust/Iced desktop application for forensic MP4 analysis
and truncated H.264 video recovery.

The application has three main workflows:

-   **Analyze** --- inspect MP4 structure, metadata, file layout,
    GOP/frame information, and selected bytes through a hex viewer.
-   **Extract** --- recover/decode frames from damaged or truncated
    MP4/H.264 files and export recovered frames as PNG images.
-   **Custody** --- show the open case, the host and build that
    produced it, and the hash-chained audit of what this session did.

The GUI lives under `src/presentation/`. The forensic rules live under
`src/domain/`, `src/application/`, and `src/infrastructure/`. The
analysis and recovery engines are the vendored `video-analyzer` and
`iframe-extract` crates.

The new work described below focuses on making the tool more
**forensically defensible**, particularly around evidence integrity,
traceability, and reproducibility.

------------------------------------------------------------------------

## 2. New forensic module structure

Forensic bookkeeping is split into layers. `src/forensic/mod.rs` is a
facade the GUI and the verify command use. It does not own the types.

``` text
src/
├── domain/            entities and hash-chain math, no filesystem
│   ├── artifact.rs
│   ├── audit.rs
│   ├── case.rs
│   ├── closure.rs
│   ├── context.rs
│   ├── evidence.rs
│   ├── provenance.rs
│   └── signing.rs
├── application/       use cases
│   ├── seal.rs        write closure, signature, and CASE_CLOSED
│   ├── verify.rs      VerificationReport for a sealed case
│   └── ports.rs
├── infrastructure/    filesystem, hashing, keys, audit log
├── presentation/
│   ├── app.rs
│   ├── analyze.rs
│   ├── extract.rs
│   ├── custody.rs     chain of custody and the seal review
│   └── verify_cli.rs  bitsplayer-verify
└── forensic/mod.rs    re-exports the layers above
```

The domain layer does not read or write files. The application layer
calls ports. The GUI records audit entries but does not hash them
itself.

------------------------------------------------------------------------

## 3. SHA-256 evidence hashing

### What was implemented

`src/infrastructure/hashing.rs` contains a reusable SHA-256 file hashing
function.

The implementation reads files using a **1 MiB streaming buffer** rather
than loading the entire evidence file into RAM.

Conceptually:

``` text
Evidence MP4
    ↓
Read 1 MiB
    ↓
Update SHA-256
    ↓
Read next 1 MiB
    ↓
Update SHA-256
    ↓
...
    ↓
Final 256-bit digest
```

This is important because forensic video files may be very large.

### Dependencies added

The root `Cargo.toml` now includes:

``` toml
sha2 = "0.10"
hex = "0.4"
```

### Validation

A unit test checks the implementation against the known SHA-256 digest
for `abc`.

The application's calculated SHA-256 was also manually compared against
Linux:

``` bash
sha256sum "/path/to/video.mp4"
```

The BitsPlayer hash matched `sha256sum` exactly.

------------------------------------------------------------------------

## 4. EvidenceRecord

`src/domain/evidence.rs` introduces:

``` rust
pub struct EvidenceRecord {
    pub path: PathBuf,
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub registered_at: SystemTime,
    pub integrity_verified: bool,
}
```

### Purpose

An `EvidenceRecord` represents the source file being examined.

When created, it:

1.  verifies that the selected path is a regular file;
2.  records the source path;
3.  records the filename;
4.  records the file size;
5.  calculates SHA-256;
6.  records when the evidence was registered;
7.  initially marks integrity as unverified.

### Important design rule

The evidence registration code **reads the source evidence only**. It
does not write to the source MP4.

------------------------------------------------------------------------

## 5. Pre/post-analysis integrity verification

A `verify_integrity()` method was added to `EvidenceRecord`.

The Analyze workflow now performs:

``` text
Select MP4
    ↓
Calculate original SHA-256
    ↓
Run MP4 analysis
    ↓
Calculate SHA-256 again
    ↓
Compare hashes
    ↓
Same → Integrity verified
Different → Critical integrity failure
```

If the source file changes during analysis, the operation returns:

``` text
CRITICAL: Evidence file changed during analysis
```

This gives us evidence that the source file examined after analysis is
byte-for-byte identical to the file registered before analysis.

------------------------------------------------------------------------

## 6. Analyze UI integration

`src/presentation/analyze.rs` stores:

``` rust
pub evidence: Option<EvidenceRecord>
```

The analysis background task now returns both:

``` text
Analysis + EvidenceRecord
```

The Analyze sidebar displays a new section:

``` text
FORENSIC EVIDENCE

File
<filename>

Size
<file size>

SHA-256
<64-character hash>

Integrity verified
```

The SHA-256 is split across multiple lines so that it fits the existing
narrow sidebar.

The existing MP4 metadata/layout functionality remains available below
the forensic evidence information.

------------------------------------------------------------------------

## 7. Evidence modification detection tests

The evidence subsystem currently tests three important cases:

### Evidence record creation

Confirms that the correct file size and SHA-256 are stored.

### Unchanged evidence

Creates an evidence record, verifies the same file again, and expects:

``` text
integrity_verified = true
```

### Changed evidence

Creates an evidence record, modifies the test file, then verifies it
again.

Expected result:

``` text
integrity_verified = false
```

This demonstrates that BitsPlayer can detect source evidence
modification.

------------------------------------------------------------------------

## 8. Case model

`src/domain/case.rs` introduces a forensic `Case`. Persistence is in
`src/infrastructure/case.rs`.

Current structure:

``` rust
pub struct Case {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub examiner: Option<String>,
    pub case_directory: PathBuf,
}
```

Each case therefore has:

-   a UUID;
-   a case name;
-   UTC creation timestamp;
-   optional examiner information;
-   its own directory.

Additional dependencies were added:

``` toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
```

------------------------------------------------------------------------

## 9. Persistent `case.json`

Cases can now be serialized to disk.

Example structure:

``` json
{
  "id": "68bf4adf-c777-41ee-bd40-48bc493c4f3c",
  "name": "BitsPlayer Session",
  "created_at": "2026-10-06T13:38:31.409020594Z",
  "examiner": null,
  "case_directory": "/.../BitsPlayer-GUI/cases/CASE-68bf4adf"
}
```

The `Case` implementation supports:

``` text
Case::save()
Case::load()
Case::case_file_path()
```

Saving/loading is covered by unit tests.

------------------------------------------------------------------------

## 10. Unique case directories

The initial prototype used:

``` text
cases/current_session/
```

That was replaced with unique case directories.

Current runs create structures similar to:

``` text
cases/
└── CASE-68bf4adf/
    ├── case.json
    └── logs/
        └── audit.jsonl
```

The short folder identifier is derived from the case UUID, while the
full UUID remains stored in `case.json`.

The old `cases/current_session/` directory may still exist locally from
earlier development tests, but new sessions use the `CASE-xxxxxxxx`
structure.

------------------------------------------------------------------------

## 11. Audit logging

`src/infrastructure/audit.rs` introduces an `AuditLogger`. The entry
type and the hash payload live in `src/domain/audit.rs`.

Audit entries currently contain:

``` rust
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub case_id: Uuid,
    pub action: String,
    pub tool_version: String,
    pub evidence_filename: Option<String>,
    pub evidence_sha256: Option<String>,
    pub result: String,
    pub previous_entry_hash: Option<String>,
    pub entry_hash: String,
}
```

Logs are stored as **JSON Lines (`.jsonl`)**.

One JSON object is written per line.

This makes logs both machine-readable and relatively easy to inspect
manually.

------------------------------------------------------------------------

## 12. Actions currently recorded

A session can record:

``` text
CASE_CREATED
EVIDENCE_REGISTERED
ANALYSIS_STARTED
ANALYSIS_COMPLETED or ANALYSIS_FAILED
INTEGRITY_VERIFICATION
EXTRACT_STARTED
EXTRACT_COMPLETED or EXTRACT_FAILED
ARTIFACT_CREATED
CASE_CLOSED
```

`ANALYSIS_STARTED` is written before analysis runs. `EXTRACT_STARTED`
and `EXTRACT_COMPLETED` carry the extraction parameter snapshot
(dimensions, matrix, and the include flags). `ARTIFACT_CREATED` carries
the recovered file name, type, size, SHA-256, and the source evidence
hash. `CASE_CLOSED` is written only when the window-close seal
succeeds.

Each entry also stores build provenance: tool version, git commit,
Cargo.lock SHA-256, and the running binary's SHA-256. The version comes
from `CARGO_PKG_VERSION`. The commit and lock hash are captured at
build time; the build refuses to proceed when either is unknown.

------------------------------------------------------------------------

## 13. Tamper-evident hash chaining

The audit log is not merely a list of independent events.

Every entry contains:

``` text
previous_entry_hash
entry_hash
```

For example:

``` text
Entry 1
entry_hash = AAA
        ↓
Entry 2
previous_entry_hash = AAA
entry_hash = BBB
        ↓
Entry 3
previous_entry_hash = BBB
entry_hash = CCC
```

Therefore, modifying an earlier record causes verification of the chain
to fail.

The entry hash includes the important contents of the audit record,
including:

-   timestamp;
-   case UUID;
-   action;
-   tool version;
-   evidence filename;
-   evidence SHA-256;
-   result;
-   previous entry hash.

------------------------------------------------------------------------

## 14. Audit-log verification

The audit subsystem can now verify an existing audit file.

It checks:

1.  whether each line contains valid JSON;
2.  whether `previous_entry_hash` correctly references the previous
    entry;
3.  whether each stored `entry_hash` matches a freshly recalculated
    hash.

The verification result records:

``` text
valid
entries_checked
last_hash
error
```

This provides the basis for reporting whether an audit trail remains
internally consistent.

------------------------------------------------------------------------

## 15. Audit chain resumption

An important issue was identified during development.

Originally, reopening an existing audit file would initialize:

``` text
last_hash = None
```

while still appending to the existing file.

That could create a second independent chain inside the same audit log.

This has now been corrected.

When `AuditLogger::new()` opens an existing log, it:

``` text
Open existing audit.jsonl
        ↓
Verify complete existing chain
        ↓
Invalid → refuse initialization
        ↓
Valid → obtain final entry hash
        ↓
Use final hash as last_hash
        ↓
New entries continue the existing chain
```

This behavior is covered by a unit test.

------------------------------------------------------------------------

## 16. Tampering detection

A dedicated test deliberately modifies an existing audit record after it
has been written.

The verifier then detects that the recalculated entry hash does not
match the stored hash.

Therefore the current implementation can detect this type of
audit-record alteration.

This is an important distinction:

> The log is currently **tamper-evident**, not impossible to modify.

A person with filesystem access can still edit the `.jsonl` file, but
verification should expose the modification because the hash chain no
longer validates.

------------------------------------------------------------------------

## 17. Case/audit relationship verified manually

The generated case metadata and audit log were manually inspected.

Example case:

``` text
CASE-68bf4adf
```

Full case UUID:

``` text
68bf4adf-c777-41ee-bd40-48bc493c4f3c
```

The same UUID appeared in:

``` text
case.json → id
```

and in every:

``` text
audit.jsonl → case_id
```

This confirms that audit events are associated with the correct
persisted forensic case.

------------------------------------------------------------------------

## 18. Current automated test status

At the latest checkpoint:

``` text
running 10 tests
test result: ok. 10 passed; 0 failed
```

The tested functionality includes:

-   known SHA-256 calculation;
-   evidence record creation;
-   unchanged-evidence verification;
-   changed-evidence detection;
-   case creation;
-   case save/load;
-   audit-entry chaining;
-   valid audit-chain verification;
-   existing-chain resumption;
-   tampered-audit detection.

> A subsequent change adds a test for creating a case inside a unique
> base directory. After that version is tested, the expected forensic
> test count is 11.

------------------------------------------------------------------------

## 19. Current case workflow

Startup and shutdown currently do this:

``` text
Start BitsPlayer
      ↓
Create cases/CASE-<uuid>/
      ↓
Write case.json and logs/audit.jsonl
      ↓
Write CASE_CREATED
      ↓
Analyze and Extract append audit entries
      ↓
Custody tab shows those entries
      ↓
Close the main window
      ↓
Seal: case_closure.json, case_signature.json, CASE_CLOSED
      ↓
Run the sealed-case verifier
      ↓
Leave the checklist on screen until Exit
```

Recovered PNGs are written to a folder the examiner picks. That folder
is not inside the case directory. The seal review passes every folder
that received a logged artifact.

------------------------------------------------------------------------

## 20. Example current directory structure

``` text
BitsPlayer-GUI/
├── Cargo.toml
├── Cargo.lock
├── cases/
│   └── CASE-<uuid>/
│       ├── case.json
│       ├── case_closure.json      after a successful seal
│       ├── case_signature.json    after a successful seal
│       └── logs/
│           └── audit.jsonl
└── src/
    ├── domain/
    ├── application/
    ├── infrastructure/
    ├── presentation/
    └── forensic/mod.rs
```

The signing key is not stored in the case. It lives under
`~/.config/bitsplayer/signing/` (`private.key` and `public.key`).
`bitsplayer-verify` trusts `public.key` from that directory unless
`--public-key` points somewhere else.

`current_session` is legacy development output and is no longer the
intended case structure.

------------------------------------------------------------------------

## 21. Chain of custody in the GUI

The Custody tab reads the audit entries this process has already
committed. Opening the tab does not write an audit event.

It shows:

-   case name, id, examiner, directory, created time, and whether the
    case is still open;
-   host, operating system, architecture, tool version, git commit,
    Cargo.lock hash, and binary hash, taken from the first entry;
-   chain length and the current head hash;
-   one row per entry: sequence, time, action, result, evidence or
    artifact name, a short hash, and the extraction parameters when
    that entry has them.

The Analyze sidebar still shows evidence integrity and the full
evidence SHA-256. That line is unchanged.

### Seal review

Closing the main window seals the case. A successful seal does not
exit. The same task re-reads `audit.jsonl` with `read_verified_audit`
(so `CASE_CLOSED` appears on the chain) and runs
`verify_case_directories`.

The review replaces the tab body. It shows the closure path, the
signature path, the public key path, and whether the signing identity
was loaded or just created. A new identity is called out on that
screen, because the signature is only meaningful once that public key
is trusted. Then it lists every line of `VerificationReport`: the
`[OK]` checks, the warnings, or the verifier error.

Exit leaves the application. Closing the window a second time also
exits, including when verification failed. The case is already sealed
on disk; the review is what the examiner reads before leaving.

`verify_case` refuses a log whose last action is not `CASE_CLOSED`, so
the live Custody tab does not call it.

### What the verifier checks

`bitsplayer-verify` and the seal review both use
`src/application/verify.rs`. `VerificationReport` is the custody
report. There is no separate PDF or Markdown generator.

The check covers `case.json`, the hash chain, a stable host and
examiner, operation context on analysis and extraction entries, the
closure file, the Ed25519 signature against a trusted public key,
build provenance, and artifact bytes. The command line still takes one
`--artifact-dir`. The GUI passes every directory that received an
artifact this session. A filename must match exactly one file across
those directories. A case with no `ARTIFACT_CREATED` entries does not
need a directory.

### Still absent

The GUI still creates the case automatically:

``` text
name = "BitsPlayer Session"
examiner = BITSPLAYER_EXAMINER, or absent when that variable is unset
```

There is no field for the case name or the examiner. There is no Open
Existing Case flow, even though `Case::load()` and audit resumption
exist. Opening the Custody tab and showing the seal review do not add
either of those.

------------------------------------------------------------------------

## 22. Important design principles being followed

### Source evidence should remain untouched

The analysis/hashing code opens the source evidence for reading.

Generated outputs, case metadata, and audit logs are written separately.

### Large-file hashing is streamed

SHA-256 hashing does not require loading the entire MP4 into RAM.

### Evidence identity is cryptographic

SHA-256 is used to identify the exact source evidence.

### Integrity is checked before and after analysis

The evidence hash is calculated before analysis and checked again
afterward.

### Audit records are structured

JSON Lines is used rather than free-form text logging.

### Audit records are tamper-evident

Hash chaining allows later verification of the audit sequence.

### Cases are isolated

New sessions use unique case directories rather than sharing one global
log.

### Forensic-critical components are tested

Hashing, evidence integrity, case persistence, audit chaining, audit
resumption, and tamper detection have automated tests.

------------------------------------------------------------------------

## 23. Current milestone summary

The project has progressed from:

``` text
MP4 forensic analysis/recovery tool
```

toward:

``` text
MP4 forensic analysis/recovery tool
        +
evidence identification
        +
pre/post integrity verification
        +
persistent forensic cases
        +
structured audit trail
        +
hash-chained tamper detection
        +
extraction parameters and artifact hashes
        +
build provenance
        +
Ed25519 case seal
        +
Custody tab and seal review
        +
bitsplayer-verify
```

Analyze and Extract remain the primary workflows. The Custody tab and
the seal review show the record those workflows already write.

------------------------------------------------------------------------

## 24. Recommended next implementation order

Extract auditing, artifact hashing, overwrite refusal, extraction
parameters, build provenance, closure, and Ed25519 sealing are in
place. The Custody tab and the seal review expose that record.

What is still missing:

``` text
1. Case name and examiner fields in the GUI
        ↓
2. Open an existing sealed case
        ↓
3. Validation and corpus metrics
```

------------------------------------------------------------------------

## Team handover note

The connected layer is `src/domain/`, `src/application/`, and
`src/infrastructure/`. `src/forensic/mod.rs` only re-exports it.
Changes to serialized case, audit, closure, or signature structures
may affect existing `case.json`, `audit.jsonl`, `case_closure.json`,
and `case_signature.json` files.

When making changes, run:

``` bash
cargo check
cargo test --lib
```

before continuing. The forensic tests live with the library, not under
a separate `forensic` filter name.
