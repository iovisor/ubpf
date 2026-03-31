# Workflows

This directory contains LLM prompt specifications that guide AI-assisted
specification management for the uBPF project. Each workflow defines a
structured, multi-phase process executed by an AI agent operating under a
"Senior Systems Engineer" persona with built-in guardrails against
hallucination, fabrication, and specification drift.

All three workflows share a common foundation:

- **Anti-Hallucination Guardrails** — epistemic labeling, refusal to fabricate,
  uncertainty disclosure.
- **Self-Verification** — sampling checks, citation audits, coverage
  confirmation.
- **Adversarial Falsification** — assume more bugs exist, disprove before
  reporting.
- **Traceability Audit** — forward/backward traceability between requirements,
  design, code, and tests.
- **Specification Drift Taxonomy (D1–D16)** — a classification system for
  traceability gaps across documents, code, and tests.

## Workflow Files

### `bootstrap-specs.md` — Spec Extraction

Extracts requirements, design, and validation specifications from an existing
codebase that lacks formal documentation.

**Phases:** Repository scan → Draft extraction (requirements, design,
validation) → Human clarification → Consistency audit → Human approval →
Deliverable creation.

**Use when:** The project has working code but no formal specs, and you need to
create the initial specification suite.

### `evolve-specs.md` — Incremental Development

Evolves specifications alongside new feature development, ensuring that specs,
code, and tests stay synchronized as changes are made.

**Phases:** Requirements discovery → Specification changes → Spec audit → User
review → Implementation changes → Implementation audit → User review →
Deliverable creation.

**Use when:** Adding new features or modifying existing behavior and you need
specs, implementation, and tests to advance together.

### `maintain-specs.md` — Maintenance Audit

Audits the full specification suite against the current codebase and tests to
detect and correct drift.

**Phases:** Full audit (document-level, code-level, test-level) → Human
classification of findings → Corrective patch generation → Patch audit → Human
approval → Deliverable creation.

**Use when:** Specs, code, or tests may have diverged over time and you need to
bring them back into alignment.

## Usage

These workflows are designed to be provided as system prompts (or prompt
context) to an LLM agent with tool access to the repository. Each workflow
expects specific inputs (e.g., file paths, specification documents) documented
in its **Inputs** section.
