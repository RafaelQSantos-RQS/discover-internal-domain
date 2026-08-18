# AGENTS.md – Development Guidelines

## Project Overview
- **Repository:** `discover-internal-domain`
- **Language:** Rust (edition 2021)
- **Purpose:** Brute-force DNS enumeration for internal assets (wildcard detection, worker pools, checkpointing)
- **Entry point:** `src/main.rs` (binary `dnsbrute`)

---

## Build & Run Commands

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run
cargo run -- -d example.com -m 4 -w 20

# Run the compiled binary
./target/release/dnsbrute -d example.com -m 4 -w 20

# Clean
cargo clean
```

## Testing

```bash
# All tests
cargo test

# Single test by name
cargo test <test_name>

# Tests with output
cargo test -- --nocapture
```

## Linting & Formatting

```bash
# Format (required before commit)
cargo fmt

# Check formatting (CI)
cargo fmt --check

# Lint (CI: deny warnings)
cargo clippy
cargo clippy -- -D warnings
```

## Code Style

### Module Structure
```
src/
  main.rs        # entry, pipeline (produtor → canal → workers), signals, resumo
  cli.rs         # clap args + validação
  generator.rs   # gerador iterativo de combinações (com retomada)
  resolver.rs    # lookup DNS + detecção/filtragem de wildcard
  negcache.rs    # cache negativo (HashMap + VecDeque)
  checkpoint.rs  # save/load atômico + validação
```

### Naming Conventions
| Element | Convention |
|---------|------------|
| Crates/types | `snake_case` (`TokioResolver`) |
| Functions | `snake_case` (`lookup_ip`) |
| Local variables | `snake_case` (`max_len`) |
| Constants | `SCREAMING_SNAKE_CASE` (`MAX_MAX_LEN`) |
| File names | `snake_case` (`negcache.rs`) |
| Modules | lowercase, no underscores (`negcache`) |

### Error Handling
- Return `Result<T, String>` with clear messages: `format!("read checkpoint: {e}")`
- Use `Option` for non-error absence (`Option<Vec<String>>`)
- Prefer `?` for propagation; handle fatal errors in `main` with `eprintln!` + `process::exit(1)`
- Non-fatal errors: `eprintln!("Warning: ...")`

### Types & Structs
- Keep structs small, single responsibility
- Use `pub` only when needed; tests use `#[cfg(test)] mod tests` in-file
- Async I/O functions are `async fn`; `Arc`/`Mutex` for shared state

```rust
pub struct NegCache {
    inner: Mutex<Inner>,
    ttl: Duration,
}
```

## Concurrency Patterns
- `tokio::spawn` worker pool consuming a bounded `async_channel`
- `Arc` + `Mutex` for shared mutable state (generator, output writer)
- `Arc<AtomicU64>` for counters
- `tokio::sync::watch` for cancellation signals
- Per-query DNS timeout via `tokio::time::timeout` + `ResolverOpts.timeout`
- `hickory_resolver::TokioResolver` for DNS queries (clone into workers)
- Avoid global mutable state

## Security Guidelines
- Do NOT log IPs/hostnames at INFO level
- Validate all input flags (non-negative, reasonable bounds)
- Use `--max-combinations` to prevent resource exhaustion
- Write checkpoints atomically (temp + rename + sync)
- Set checkpoint file permissions: `0600`

## Documentation
- Every `pub` item needs a `///` doc comment
- Complex algorithms need complexity analysis
- Line length: ≤100 characters (enforced by `cargo fmt`/`rustfmt`)

---

## Cursor & Copilot Rules
None present. Reference this file if added later.

*Last updated: 2026-08-18*
