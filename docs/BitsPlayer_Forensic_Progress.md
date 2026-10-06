# BitsPlayer Forensic Integrity Development Progress

## Purpose of this document

This document summarizes the forensic-integrity work implemented so far
in the **BitsPlayer-GUI** project. It is intended to help all team
members understand what has changed, why it was added, how the current
implementation works, and what remains to be implemented.

> **Current status:** The original MP4 analysis/recovery application is
> still intact. We have added an initial forensic evidence-integrity,
> case-management, and tamper-evident audit foundation around it.

------------------------------------------------------------------------

## 1. Original project context

BitsPlayer is a Rust/Iced desktop application for forensic MP4 analysis
and truncated H.264 video recovery.

The existing application already had two main workflows:

-   **Analyze** --- inspect MP4 structure, metadata, file layout,
    GOP/frame information, and selected bytes through a hex viewer.
-   **Extract** --- recover/decode frames from damaged or truncated
    MP4/H.264 files and export recovered frames as PNG images.

The main GUI is under `src/`, while the main analysis/recovery engines
are provided by the vendored `video-analyzer` and `iframe-extract`
crates.

The new work described below focuses on making the tool more
**forensically defensible**, particularly around evidence integrity,
traceability, and reproducibility.

------------------------------------------------------------------------

## 2. New forensic module structure

A new forensic subsystem has been introduced:

``` text
src/
├── forensic/
│   ├── mod.rs
│   ├── hashing.rs
│   ├── evidence.rs
│   ├── case.rs
│   └── audit.rs
├── analyze.rs
├── app.rs
├── extract.rs
├── main.rs
└── ...
```

`src/forensic/mod.rs` exposes the forensic modules:

``` rust
pub mod audit;
pub mod case;
pub mod evidence;
pub mod hashing;
```

The goal is to keep forensic bookkeeping separate from the existing MP4
analysis/recovery implementation.

------------------------------------------------------------------------

## 3. SHA-256 evidence hashing

### What was implemented

`src/forensic/hashing.rs` now contains a reusable SHA-256 file hashing
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

`src/forensic/evidence.rs` introduces:

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

`src/analyze.rs` has been updated to store:

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

`src/forensic/case.rs` introduces a forensic `Case`.

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

`src/forensic/audit.rs` introduces an `AuditLogger`.

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

When the application creates a case and analyzes evidence, the audit
trail currently records:

``` text
CASE_CREATED
    ↓
EVIDENCE_REGISTERED
    ↓
ANALYSIS_COMPLETED
    ↓
INTEGRITY_VERIFICATION
```

For the integrity verification event, the result is recorded as:

``` text
verified
```

when successful.

The application version is automatically included using:

``` rust
env!("CARGO_PKG_VERSION")
```

The current tested version was:

``` text
0.1.0
```

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

At present, application startup effectively performs:

``` text
Start BitsPlayer
      ↓
Generate UUID
      ↓
Create CASE-xxxxxxxx directory
      ↓
Create case.json
      ↓
Initialize logs/audit.jsonl
      ↓
Write CASE_CREATED
      ↓
User selects MP4
      ↓
Calculate SHA-256
      ↓
Analyze MP4
      ↓
Recalculate SHA-256
      ↓
Verify evidence unchanged
      ↓
Write evidence/analysis/integrity audit events
```

------------------------------------------------------------------------

## 20. Example current directory structure

``` text
BitsPlayer-GUI/
├── Cargo.toml
├── Cargo.lock
├── cases/
│   ├── CASE-68bf4adf/
│   │   ├── case.json
│   │   └── logs/
│   │       └── audit.jsonl
│   └── current_session/
│       └── logs/
│           └── audit.jsonl
│
└── src/
    ├── forensic/
    │   ├── mod.rs
    │   ├── hashing.rs
    │   ├── evidence.rs
    │   ├── case.rs
    │   └── audit.rs
    ├── analyze.rs
    ├── app.rs
    ├── extract.rs
    └── ...
```

`current_session` is legacy development output and is no longer the
intended case structure.

------------------------------------------------------------------------

## 21. What has NOT been completed yet

The forensic layer is still under development.

The following are important remaining tasks.

### Proper Case UI

Currently a case is automatically created with:

``` text
name = "BitsPlayer Session"
examiner = null
```

The intended next step is to add a GUI where an examiner can provide:

-   case name/number;
-   examiner/operator name;
-   potentially other case metadata.

Analysis/extraction can then operate inside the selected/created case.

### Extraction workflow integration

The forensic evidence/audit work has mainly been integrated with
**Analyze** so far.

The **Extract** workflow still needs equivalent integration, including:

-   source evidence registration/association;
-   pre/post extraction integrity verification;
-   extraction parameters in the audit trail;
-   extraction start/completion/failure events;
-   recovered-artifact registration.

### Artifact integrity

Recovered PNG files should eventually have their own records containing:

-   output path;
-   artifact type;
-   size;
-   SHA-256;
-   creation time;
-   originating evidence SHA-256.

Existing output files should also not be silently overwritten.

### Forensic reporting

A final report generator still needs to be implemented.

A report should eventually contain items such as:

``` text
Case ID
Case name
Examiner
Tool version
Evidence filename
Evidence SHA-256
Evidence size
Integrity verification result
Analysis details
Extraction parameters
Recovered artifacts
Artifact hashes
Warnings/errors
Audit verification status
```

### Better tool/build provenance

The audit currently records the Cargo package version.

A later improvement may also record the Git commit/build identifier so
that the exact source revision used for an examination can be
identified.

### Existing-case workflow

Although `Case::load()` and audit resumption exist, the GUI does not yet
provide a complete **Open Existing Case** workflow.

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
automated validation tests
```

The core MP4 analysis/recovery functionality remains the project's
primary purpose. The new forensic subsystem provides the foundation
required to make those operations more traceable and defensible.

------------------------------------------------------------------------

## 24. Recommended next implementation order

The current recommended development sequence is:

``` text
1. Case creation UI
        ↓
2. Examiner/case metadata
        ↓
3. Open existing case
        ↓
4. Integrate Extract with forensic case/audit system
        ↓
5. Artifact records + SHA-256 hashing
        ↓
6. Prevent silent artifact overwrites
        ↓
7. Record extraction parameters/results
        ↓
8. Generate forensic report
        ↓
9. Validation/corpus metrics
        ↓
10. Final documentation and evaluation
```

------------------------------------------------------------------------

## Team handover note

Before modifying the forensic subsystem, team members should be aware
that `hashing.rs`, `evidence.rs`, `case.rs`, and `audit.rs` now form a
connected integrity/audit layer. Changes to serialized case/audit
structures may affect existing `case.json` or `audit.jsonl`
compatibility.

When making changes, run:

``` bash
cargo check
cargo test forensic
```

before continuing.

The latest confirmed checkpoint had all forensic tests passing.
