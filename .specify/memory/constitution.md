<!--
Sync Impact Report
==================
Version change: 0.0.0 → 1.0.0 (initial adoption)

Added sections:
  - Section: "Development Standards" (VI. Testing Requirements, VII. Error Handling, VIII. Input Validation)
  - Section: "Governance" with amendment procedures and compliance requirements

Added principles:
  - I. Iterative Generation (Memory Safety)
  - II. Worker Pool Concurrency
  - III. Wildcard Detection and Filtering
  - IV. Checkpoint and Resumability
  - V. Security and Responsible Use
  - VI. Testing Requirements
  - VII. Error Handling
  - VIII. Input Validation

Templates requiring updates:
  ✅ plan-template.md - Constitution Check section unchanged (generic placeholder)
  ✅ spec-template.md - No changes needed (references functional requirements)
  ✅ tasks-template.md - No changes needed (references user story phases)
  ⚠ .opencode/command/speckit.constitution.md - Line 49 mentions CLAUDE in comment (acceptable - explains validation task)

Deferred items:
  None

Rationale for version 1.0.0:
  Initial adoption of the constitution. All 8 principles derived from:
  - README.md (planning document)
  - AGENTS.md (development guidelines)
  - main.go (existing implementation patterns)
  - go.mod (Go 1.26.1 project)
-->

# discover-internal-domain Constitution

## Core Principles

### I. Iterative Generation (Memory Safety)

Every subdomain combination is generated iteratively using a base-36 counter (index vector) that maintains O(maxLen) memory usage. No full permutation arrays may be allocated. The generator must produce combinations on-demand through channels to prevent memory exhaustion during large enumerations.

Rationale: The search space grows as 36^maxLen, which becomes infeasible for memory allocation beyond small maxLen values. Iterative generation enables exploring billions of combinations within bounded memory.

### II. Worker Pool Concurrency

DNS queries MUST be executed through a bounded worker pool with configurable concurrency. Workers consume jobs from buffered channels and MUST respect context timeouts. Worker count, timeout, and channel buffer sizes are configurable via command-line flags with validated defaults.

Rationale: Unbounded concurrency would create a denial-of-service condition against target DNS servers. Context deadlines ensure individual query failures do not block the entire enumeration.

### III. Wildcard Detection and Filtering

The tool MUST detect DNS wildcard responses through preliminary random subdomain queries and MUST filter subsequent results that match only the wildcard baseline IPs. When enabled, wildcard detection occurs before enumeration begins; when disabled, all resolved subdomains are reported.

Rationale: Wildcard DNS causes false positives that obscure legitimate internal assets. Filtering ensures output contains only verifiable internal domain discoveries.

### IV. Checkpoint and Resumability

Long-running enumerations MUST support checkpointing via periodic state serialization to enable resumption after interruption. Checkpoint files MUST be written atomically (temp file + rename) with restrictive permissions (0600). A --max-combinations flag MUST be available to bound total enumeration scope.

Rationale: Enumerating large search spaces may take hours or days. Checkpoints prevent work loss from interrupts, crashes, or resource exhaustion. Atomic writes prevent corruption. Combination limits prevent accidental resource exhaustion.

### V. Security and Responsible Use

This tool MUST NOT be used for unauthorized reconnaissance. Users MUST have explicit permission to enumerate the target domain. The tool MUST include safeguards against self-inflicted DoS: bounded worker pools, per-query timeouts, combination limits, and graceful shutdown on SIGINT/SIGTERM.

Rationale: DNS enumeration against unauthorized targets violates computer crime laws in most jurisdictions. Built-in rate limiting protects both external targets and the user's own infrastructure from accidental self-DoS.

## Development Standards

### VI. Testing Requirements

All exported functions MUST have corresponding unit tests. Integration tests MUST cover: DNS resolution pipeline, wildcard detection logic, worker pool coordination, and checkpoint serialization. Tests MUST use the Go testing package with race detection enabled.

Rationale: The enumeration pipeline involves concurrency, network I/O, and file I/O—areas prone to race conditions. Comprehensive test coverage ensures reliability during long-running enumerations.

### VII. Error Handling

All errors MUST be wrapped with contextual information using fmt.Errorf "%w" pattern. Silent failures are acceptable only for DNS query timeouts (expected behavior). All other errors MUST be logged at minimum log.Printf level. Exported errors that callers may need to inspect MUST be package-level var errors.

Rationale: Debugging failed or hung enumerations requires traceable error chains. Timeout silence prevents log spam during legitimate network latency. Exported sentinel errors enable caller-specific recovery logic.

### VIII. Input Validation

All flags MUST be validated before enumeration begins. Invalid inputs (empty domain, non-positive maxlen/workers, negative max-combinations) MUST produce a descriptive error to stderr and exit with status 1. Domain format SHOULD NOT be strictly validated to support internal DNS zones with non-standard TLDs.

Rationale: Early validation prevents wasted enumeration cycles on invalid configurations. Relaxed domain validation supports corporate internal DNS zones (e.g., .local, .internal).

## Governance

Amendments to this constitution require:

1. A pull request that modifies only the constitution file (exception: version bumps may accompany changes)
2. A description of the rationale and impact of each change
3. Review approval from at least one maintainer
4. An incremented version following semantic versioning rules:
   - MAJOR: Backward-incompatible governance changes or principle removals
   - MINOR: New principles or materially expanded guidance
   - PATCH: Clarifications, wording fixes, non-semantic refinements

Compliance verification:

- All pull requests MUST pass go vet, golangci-lint, and go test -race
- The constitution supersedes conflicting guidance in other documentation
- golangci-lint configuration MUST enforce constitution-aligned practices

**Version**: 1.0.0 | **Ratified**: 2026-03-19 | **Last Amended**: 2026-03-19
