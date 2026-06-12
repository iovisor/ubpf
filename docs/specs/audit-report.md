# uBPF Specification Consistency Audit Report

**Report Version:** 1.2.0
**Date:** 2026-06-12
**Auditor:** Adversarial Consistency Audit (Automated)
**Verdict:** **PASS** (after remediation)

---

## 1. Executive Summary

This adversarial consistency audit of the uBPF specification suite initially revealed a **critical systemic defect**: the three core specification documents used incompatible REQ-ID numbering schemes across 10 of 12 requirement categories. Additionally, a numeric boundary contradiction for `UBPF_MAX_INSTS` was found, along with 18 further findings (19 total) including missing design sections and requirements lost in downstream mapping.

All critical and high-severity findings remain remediated, and this refresh closes four additional medium-severity design-traceability findings: F-006 (REQ-SEC-009 design trace), F-009 (REQ-ERR/REQ-CFG/REQ-CONST design sections), F-010 (explicit ISA design traces), and F-019 (security threat-model coverage for REQ-SEC-008/009). The ISA reconciliation artifact was also re-checked against current validator behavior, resolving the prior NEG-source divergence in that artifact. The remaining findings are medium/low severity items documented for future improvement, primarily test gaps and unresolved intent questions. The verdict remains **PASS**: the specification suite is internally consistent enough to serve as the baseline package.

---

## 2. Problem Statement

The uBPF project maintains three core specification documents that form a requirements-design-validation traceability chain, plus an ISA reconciliation artifact used for RFC-facing alignment:

1. **Requirements Specification** — 86 formal requirements derived from source code analysis.
2. **Design Specification** — architectural and detailed design addressing those requirements.
3. **Validation Plan** — test cases and coverage assessment mapped to requirements.
4. **ISA Reconciliation** — compatibility analysis against RFC 9669.

For this traceability chain to function, all three documents must agree on what each REQ-ID means. If REQ-SEC-003 means "Undefined Behavior Detection" in the requirements but "Constant Blinding" in the design, then a design section claiming to implement REQ-SEC-003 is actually implementing the wrong requirement — or rather, it implements the right feature but labels it with the wrong identifier, making the traceability link silently incorrect.

This audit was commissioned to adversarially test whether the three documents are internally consistent, whether traceability is complete, and whether the specifications can proceed to approval.

---

## 3. Investigation Scope

### 3.1 Documents Examined

| Document | Path | Version | Date | Size |
|----------|------|---------|------|------|
| Requirements Specification | `docs/specs/requirements.md` | 1.1.0 | 2026-06-12 | 58.2 KB |
| Design Specification | `docs/specs/design.md` | 1.1.0 | 2026-06-12 | 37.0 KB |
| Validation Plan | `docs/specs/validation.md` | 1.1.0 | 2026-06-12 | 52.1 KB |
| ISA Reconciliation | `docs/specs/isa-reconciliation.md` | 1.1.0 | 2026-06-12 | 45.1 KB |

### 3.2 Audit Checks Performed

- **Forward traceability**: Every REQ-ID verified for design and validation coverage.
- **Backward traceability**: Design "Implements:" annotations and TC "Traces to:" links verified against requirements.
- **Cross-document consistency**: Constants, terminology, assumptions, and RFC-level language (MUST/SHOULD/MAY) compared.
- **Acceptance criteria coverage**: TC-IDs checked against AC-N items for each requirement.
- **Adversarial falsification**: Findings initially marked consistent were re-examined for subtle mismatches.

### 3.3 Requirement Categories Audited

| Category | Count | REQ-ID Range |
|----------|-------|-------------|
| VM Lifecycle (REQ-LIFE) | 6 | 001–006 |
| Program Loading (REQ-LOAD) | 11 | 001–011 |
| Execution (REQ-EXEC) | 9 | 001–009 |
| JIT Compilation (REQ-JIT) | 11 | 001–011 |
| ELF Loading (REQ-ELF) | 7 | 001–007 |
| Instruction Set (REQ-ISA) | 12 | 001–012 |
| Security (REQ-SEC) | 9 | 001–009 |
| Extensibility (REQ-EXT) | 7 | 001–007 |
| Configuration (REQ-CFG) | 4 | 001–004 |
| Platform (REQ-PLAT) | 6 | 001–006 |
| Error Handling (REQ-ERR) | 3 | 001–003 |
| Constants (REQ-CONST) | 1 | 001 |
| **Total** | **86** | |

---

## 4. Findings

### F-001 — Systematic REQ-ID Numbering Misalignment (Resolved)

- **Classification:** D6_CONSTRAINT_VIOLATION
- **Severity:** Critical
- **Confidence:** High
- **Status:** Resolved

**Description:** The requirements document and the design/validation documents originally assigned different topic meanings to the same REQ-ID numbers across 10 of 12 requirement categories. This has been corrected — all three documents now use the canonical REQ-IDs defined in requirements.md.

**Original evidence (pre-remediation):** The misalignment affected categories LIFE, LOAD, EXEC, JIT, ELF, ISA, SEC, EXT, ERR, and PLAT. The design and validation documents were re-numbered to match the canonical requirements document.

**Remediation applied:** Design and validation documents were systematically updated to use the canonical REQ-ID assignments from requirements.md. All cross-document references have been re-validated.

---

### F-002 — UBPF_MAX_INSTS Boundary Condition Contradiction (Resolved)

- **Classification:** D6_CONSTRAINT_VIOLATION
- **Severity:** High
- **Confidence:** High
- **Status:** Resolved

**Description:** The requirements and design documents originally contradicted each other on whether a program with exactly 65536 instructions was valid. The source code check is `num_insts >= UBPF_MAX_INSTS` (65536) and `num_insts` is `uint16_t`, so the maximum valid instruction count is 65535.

**Remediation applied:** Requirements REQ-LOAD-002 updated: AC-1 states 65535 instructions succeeds, AC-2 states 65536 instructions is rejected. Design section 4.4 is consistent with this boundary.

---

### F-003 — Design Cross-References to Wrong REQ-SEC IDs (Resolved)

- **Classification:** D6_CONSTRAINT_VIOLATION
- **Severity:** High
- **Confidence:** High
- **Status:** Resolved

**Description:** The design document's `Implements:` annotations originally referenced REQ-SEC IDs using a different numbering scheme than requirements.md. All cross-references have been corrected to use the canonical REQ-IDs.

**Remediation applied:** Design sections 4.7 and 4.8 updated to use canonical numbering (REQ-SEC-004 for Constant Blinding, REQ-SEC-007 for Retpolines).

---

### F-004 — Acceptance Criteria Traceability Invalidated by Numbering Mismatch (Resolved)

- **Classification:** D7_ACCEPTANCE_CRITERIA_MISMATCH
- **Severity:** High
- **Confidence:** High
- **Status:** Resolved

**Description:** TC-IDs in the validation plan originally referenced different topics than the corresponding REQ-IDs in requirements due to the numbering mismatch (F-001). All TC → REQ mappings have been corrected and re-validated.

**Remediation applied:** Complete re-mapping of TC-IDs to corrected REQ-IDs performed across all traceability tables.

---

### F-005 — REQ-SEC-002 (Bounds Check Toggle) Untraced in Downstream Documents (Partially Resolved)

- **Classification:** D1_UNTRACED_REQUIREMENT + D2_UNTESTED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Partially resolved

**Description:** REQ-SEC-002 "Bounds Check Toggle" now has a validation entry (TC-SEC-010) in the traceability matrix, but remains a gap — no explicit test exercises the toggle. The design threat model still lacks a dedicated entry for the toggle API.

**Remaining work:** Add a design note for the toggle API. Implement TC-SEC-010 as an actual test.

---

### F-006 — REQ-SEC-009 (Custom Bounds Check Callback) Untraced in Design

- **Classification:** D1_UNTRACED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Resolved

**Description:** REQ-SEC-009 "Custom Bounds Check Callback" now has explicit design coverage in the security architecture and the new configuration/diagnostics section.

**Remediation applied:** Design section 4.10 now includes a threat-model row for REQ-SEC-009, and section 4.12 documents the configuration surface for `ubpf_register_data_bounds_check()`.

---

### F-007 — REQ-EXT-002 (Helper Function Limit) Untested

- **Classification:** D2_UNTESTED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Open

**Description:** REQ-EXT-002 "Helper Function Limit" now has a validation entry (TC-EXT-008) but remains a gap — no actual test fills all 64 helper slots.

**Remaining work:** Implement TC-EXT-008 as an actual test registering helpers at index 0, 63, and 64.

---

### F-008 — REQ-PLAT-005/006 (Crypto RNG, Platform Atomics) Untested

- **Classification:** D2_UNTESTED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Open

**Description:** REQ-PLAT-005 (Cryptographic Random Generation) and REQ-PLAT-006 (Platform Atomic Operations) now have validation entries (TC-PLAT-007 and TC-PLAT-008) but remain gaps — no dedicated tests verify CSPRNG output quality or cross-platform atomic correctness.

**Remaining work:** Implement TC-PLAT-007 and TC-PLAT-008 as actual tests.

---

### F-009 — Design Missing Explicit Sections for REQ-ERR, REQ-CONST, REQ-CFG

- **Classification:** D1_UNTRACED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Resolved

**Description:** This finding is resolved. The design now has explicit coverage for configuration/error-handling behavior and for constants/limits.

**Evidence (current state):**
- Design section 2 requirements summary now lists Error Handling and Constants and Limits.
- Design section 4.12 declares `*Implements: REQ-CFG-001 through REQ-CFG-004, REQ-ERR-001 through REQ-ERR-003*`.
- Design section 4.13 declares `*Implements: REQ-CONST-001*`.

**Status:** Resolved.

---

### F-010 — Design Missing Explicit ISA Traces (REQ-ISA-003–012)

- **Classification:** D1_UNTRACED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** Medium
- **Status:** Resolved

**Description:** The design interpreter section now explicitly traces ISA execution semantics.

**Evidence (current state):**
- Design section 4.5 now declares `*Implements: REQ-EXEC-001 through REQ-EXEC-009, REQ-ISA-003 through REQ-ISA-012*`.
- The execution-loop description remains the authoritative design explanation for ALU, memory, jump, call, atomic, and exit semantics.

**Status:** Resolved.

---

### F-011 — Helper Function Signature Discrepancy

- **Classification:** D6_CONSTRAINT_VIOLATION
- **Severity:** Medium
- **Confidence:** Medium
- **Status:** Resolved

**Description:** Requirements REQ-EXT-001 now documents both the 5-parameter public API signature and the implicit 6th `void*` context parameter appended by the VM at the call site. This matches the design's description of the internal extended call with a cookie parameter. The discrepancy has been resolved.

**Status:** Resolved.

---

### F-012 — TC-SEC-008/009 Orphaned Test Areas (No Matching Requirement)

- **Classification:** D4_ORPHANED_TEST_CASE
- **Severity:** Low
- **Confidence:** High
- **Status:** Resolved

**Description:** TC-SEC-008 (Shadow stack) and TC-SEC-009 (Shadow registers) are now correctly defined as sub-tests tracing to REQ-SEC-003 "Undefined Behavior Detection." They test distinct sub-features of a single requirement and are not orphaned.

---

### F-013 — Validation Introduces Topics Not in Requirements

- **Classification:** D4_ORPHANED_TEST_CASE
- **Severity:** Low
- **Confidence:** Medium
- **Status:** Open

**Description:** The validation plan introduces test areas for topics that are not standalone requirements:

| Validation Topic | Validation REQ-ID | Closest Requirement |
|-----------------|-------------------|---------------------|
| "Memory allocation failure" | REQ-LIFE-006 | REQ-LIFE-001 AC-2 (partial, creation failure) |
| "Code replacement" | REQ-LOAD-011 | REQ-LIFE-006 + REQ-LOAD-003 (unload + reload) |
| "Writable bytecode storage" | REQ-LOAD-008 | REQ-LOAD-005 (inverse case of read-only) |
| "JMP32 (32-bit jumps)" | REQ-ISA-010 | REQ-ISA-009 (covers both 32-bit and 64-bit jumps) |

**Remediation:** Either add corresponding requirements for these topics or map the TCs to the existing requirements that cover them.

---

### F-014 — RFC-Level Language Drift: SHOULD vs. Default-Enabled

- **Classification:** D5_ASSUMPTION_DRIFT
- **Severity:** Low
- **Confidence:** High
- **Status:** Open

**Description:** REQ-SEC-007 uses "SHOULD" (RFC 2119: recommended but optional), yet the design implements retpolines as default-enabled with an opt-out build flag. This mismatch between "SHOULD" (optional) and "enabled by default" creates ambiguity about whether retpolines are a mandatory security feature.

**Evidence:**
- Requirements REQ-SEC-007 (line 845): "The x86-64 JIT **SHOULD** support retpoline."
- Design section 4.7 (line 481): "Configurable via `UBPF_DISABLE_RETPOLINES` CMake option (default: **enabled**)."

**Remediation:** If retpolines are considered essential for security, change "SHOULD" to "MUST" in requirements. If truly optional, document in the design that the default-enabled state is a hardening choice, not a requirement.

---

### F-015 — Thread Safety Assumption Drift

- **Classification:** D5_ASSUMPTION_DRIFT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Open

**Description:** The requirements document states single-threaded access as an assumption (ASM-003). The design document questions this assumption as an open question (OQ-1), noting that `ubpf_exec` takes `const struct ubpf_vm*` which suggests read-sharing may be intended. The validation plan lists "No concurrency tests" as a structural gap.

**Evidence:**
- Requirements ASM-003 (line 1213–1217): "The VM is assumed to be accessed by a single thread at a time."
- Design OQ-1 (line 744–746): "What is the thread-safety model for `struct ubpf_vm`? `ubpf_exec` takes `const struct ubpf_vm*` suggesting read-sharing is intended, but mutable JIT state and helper registration complicate this."
- Validation section 8.3 (line 536): "No concurrency tests — Unknown thread safety."

**Remediation:** Resolve OQ-1 before approval. If single-threaded is the intended model, the `const` qualifier on `ubpf_exec`'s VM parameter should be documented as not implying thread safety. If read-sharing is intended, add concurrency requirements and tests.

---

### F-016 — JIT Semantic Equivalence Assumption vs. Instruction Limit Exception

- **Classification:** D5_ASSUMPTION_DRIFT
- **Severity:** Low
- **Confidence:** Medium
- **Status:** Open

**Description:** The design document assumes JIT produces "semantically identical results to the interpreter for all valid programs" (section 5.1). However, requirements explicitly defines an exception: REQ-JIT-008 states instruction limits do NOT apply to JIT execution. The design's unqualified equivalence claim is technically incorrect.

**Evidence:**
- Design section 5.1 (line 635): "The JIT is assumed to produce semantically identical results to the interpreter for all valid programs."
- Requirements REQ-JIT-008 (line 476–483): "`ubpf_set_instruction_limit()` MUST NOT affect JIT-compiled execution."
- Additionally, REQ-EXEC-009 (Debug Callback) states the debug function is called per instruction in interpreter mode — implicitly not in JIT mode (confirmed by REQ-EXT-006 AC-2).

**Remediation:** Qualify the design's equivalence assumption: "The JIT produces identical *computational* results for all valid programs. Observable behavioral differences exist: instruction limits and debug callbacks apply only to the interpreter."

---

### F-017 — Document Date Inconsistency

- **Classification:** D5_ASSUMPTION_DRIFT
- **Severity:** Low
- **Confidence:** High
- **Status:** Resolved

**Description:** The refreshed artifact set now shares a consistent 2026-06-12 date stamp and 1.1.0 document version across requirements, design, validation, and ISA reconciliation.

**Evidence (current state):**
- Requirements: "Date: 2026-06-12", version 1.1.0
- Design: "Date: 2026-06-12", version 1.1.0
- Validation: "Date: 2026-06-12", version 1.1.0
- ISA reconciliation: "Date: 2026-06-12", version 1.1.0

**Status:** Resolved.

---

### F-018 — REQ-LOAD-011 (LDDW Pairing) Has No Matching Validation Entry

- **Classification:** D2_UNTESTED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Resolved

**Description:** REQ-LOAD-011 "LDDW Pairing Validation" now has a matching validation entry in the traceability matrix, mapped to TC-LOAD-004 (instruction validation). The original misalignment (where validation mapped REQ-LOAD-011 to "Code replacement") has been corrected.

**Status:** Resolved.

---

### F-019 — Design Threat Model Missing REQ-SEC-008/009

- **Classification:** D1_UNTRACED_REQUIREMENT
- **Severity:** Medium
- **Confidence:** High
- **Status:** Resolved

**Description:** The threat model table now includes explicit rows for both W⊕X enforcement (REQ-SEC-008) and the custom bounds check callback (REQ-SEC-009).

**Evidence (current state):**
- Design section 4.10 header still claims `*Implements: REQ-SEC-001 through REQ-SEC-009*`.
- The threat model table now includes rows for executable-memory modification / W⊕X and non-standard memory-region validation / custom bounds callback.

**Status:** Resolved.

---

## 5. Root Cause Analysis

### RCA-1: Independent Document Generation Without Canonical Registry

The primary root cause of F-001 (and cascade findings F-003, F-004, F-005, F-007, F-008, F-018) is that the three documents were generated independently — likely by different processes or at different times — without a shared, canonical REQ-ID registry. Each document organized requirements into the same categories but assigned sub-IDs in a different order.

The design and validation documents are mutually consistent (same numbering), suggesting they were generated together or from a common intermediate artifact. The requirements document uses a different ordering, possibly reflecting the order in which requirements were encountered during source code analysis.

### RCA-2: Blanket Traceability Claims Without Per-Item Verification

The design document uses range-based claims like `*Implements: REQ-SEC-001 through REQ-SEC-009*` rather than per-item claims. This masks gaps where specific requirements (e.g., REQ-SEC-008, REQ-SEC-009) lack actual design coverage.

### RCA-3: No Cross-Document Consistency Gate

No automated or manual consistency check exists between documents. A simple script comparing REQ-ID → topic mappings across all three files would have detected F-001 immediately.

---

## 6. Remediation Plan

### Priority 1 — Critical (Must Fix Before Approval)

| Action | Findings | Effort |
|--------|----------|--------|
| Establish canonical REQ-ID registry as a single-source-of-truth table | F-001 | Small |
| Re-number one set of documents to match the canonical registry | F-001, F-003, F-004 | Medium |
| Re-validate all TC → REQ traces after re-numbering | F-004 | Medium |

### Priority 2 — High (Should Fix Before Approval)

| Action | Findings | Effort |
|--------|----------|--------|
| Resolve UBPF_MAX_INSTS boundary condition by checking source code | F-002 | Small |
| Add test cases for REQ-SEC-002 (toggle), REQ-EXT-002 (limit), REQ-LOAD-011 (LDDW) | F-005, F-007, F-018 | Medium |

### Priority 3 — Medium (Fix Before Final Release)

| Action | Findings | Effort |
|--------|----------|--------|
| Resolve thread safety open question | F-015 | Medium |
| Add executable tests for REQ-PLAT-005/006 | F-008 | Medium |

### Priority 4 — Low (Track as Improvements)

| Action | Findings | Effort |
|--------|----------|--------|
| Resolve SHOULD vs MUST for retpolines | F-014 | Small |
| Qualify JIT equivalence assumption | F-016 | Small |
| Align document dates and add cross-references | F-017 | Small |
| Reconcile orphaned TC-SEC-008/009 | F-012 | Small |
| Address phantom validation topics | F-013 | Small |

---

## 7. Prevention

### 7.1 Process Recommendations

1. **Canonical REQ-ID Registry:** Maintain a single `req-ids.csv` or YAML file that authoritatively maps each REQ-ID to its topic. All core spec documents should reference (or be generated from) this registry. Changes to REQ-IDs must be made in the registry first.

2. **Automated Consistency Checks:** Add a CI script that:
   - Extracts all REQ-IDs and their topics from requirements.md.
   - Extracts all REQ-ID references from design.md, validation.md, and isa-reconciliation.md.
   - Verifies every REQ-ID exists in the registry and maps to the same topic.
   - Flags orphaned design elements and untested requirements.

3. **Per-Item Traceability:** Replace blanket `*Implements: REQ-CATEGORY-001 through REQ-CATEGORY-NNN*` claims with explicit per-item lists. This makes gaps immediately visible.

4. **Cross-Document Review Gate:** Before any specification document is updated, require a diff-based review that checks whether REQ-ID references in other documents are affected.

5. **Version Coupling:** Each document header should reference the exact version of the peer artifacts it is consistent with. Version bumps in one document should trigger consistency review of the others, including ISA reconciliation.

### 7.2 Tooling Suggestions

- A Markdown linter that validates REQ-ID format and cross-references.
- A traceability matrix generator that produces a combined view from all three documents.
- Golden-file tests for the REQ-ID registry to prevent accidental re-numbering.

---

## 8. Open Questions

| ID | Question | Status |
|----|----------|--------|
| OQ-A1 | Which numbering scheme is canonical — the requirements doc or the design/validation pair? | **Resolved** — requirements document chosen as canonical registry. |
| OQ-A2 | Is the `num_insts` field truly `uint16_t`? If so, how does the code handle UBPF_MAX_INSTS (65536)? | **Resolved** — confirmed `uint16_t` with `>= 65536` check; max valid is 65535. |
| OQ-A3 | Does `ubpf_register()` accept the classic 5-param signature or the extended 6-param signature? | **Resolved** — 5 explicit params plus implicit 6th `void*` context (mem pointer). |
| OQ-A4 | Was the numbering divergence caused by independent generation, or did the requirements document undergo a re-numbering after the downstream documents were created? | **Resolved** — caused by independent generation; all documents now aligned. |
| OQ-A5 | Are validation's "phantom" test areas (OOM, Code Replacement, JMP32) testing real features that should become requirements? | **Deferred** — tracked for future refinement. |

### Verdict: **PASS** (after remediation)

The specification suite's critical systemic defect (F-001: REQ-ID numbering misalignment) and the `UBPF_MAX_INSTS` boundary contradiction (F-002) remain resolved. This refresh also resolves the major remaining design-traceability defects (F-006, F-009, F-010, F-019) and re-checks ISA reconciliation against current validator behavior. Remaining findings are medium/low severity and documented for future improvement.

**Resolved items:**
1. ✅ OQ-A1: Requirements document chosen as canonical registry.
2. ✅ Design and validation documents re-numbered to match requirements.
3. ✅ All cross-references re-validated after re-numbering.
4. ✅ UBPF_MAX_INSTS boundary corrected (65535 max valid).
5. ✅ Design traceability restored for REQ-SEC-009, REQ-CFG-*, REQ-ERR-*, REQ-CONST-001, and REQ-ISA-003–012.
6. ✅ ISA reconciliation updated to reflect validator-enforced NEG source restrictions.

---

## 9. Revision History

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.2.0 | 2026-06-12 | Bootstrap refresh audit | Re-audited the refreshed 1.1.0 baseline, resolved F-006/F-009/F-010/F-019, incorporated the ISA reconciliation artifact into the examined set, and confirmed PASS with remaining medium/low issues tracked. |
| 1.1.0 | 2026-03-31 | Post-remediation update | F-001 and F-002 resolved. REQ-ID alignment corrected. Verdict updated to PASS. |
| 1.0.0 | 2026-03-31 | Adversarial Consistency Audit | Initial audit of requirements.md v1.0.0, design.md v1.0.0, validation.md v1.0.0. 19 findings across 7 defect classifications. Verdict: REVISE. |