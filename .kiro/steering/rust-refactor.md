---
inclusion: always
# fileMatchPattern: "src/**/*.rs"
---

# Rust Refactoring Guidelines

Guidelines for updating and refactoring Rust code in the fast-paseto library.

## Module Organization

- Keep modules focused on single responsibilities (e.g., `error.rs` for errors, `key_generator.rs` for key generation)
- Re-export public types through `lib.rs` using `pub use` statements
- Place unit tests in a `#[cfg(test)]` module at the bottom of each file, not inline
- Integration tests belong in `tests/rust/` directory (Rust tests)
- Integration tests belong in `tests/python/` directory (Python pytest tests)

## PyO3 Bindings

- Use `#[pyclass]` for types exposed to Python
- Use `#[pymethods]` for methods callable from Python
- Use `#[pyfunction]` for standalone functions
- Document all Python-facing APIs with docstrings (triple-slash `///` comments)
- Include usage examples in docstrings for complex functions
- Use `#[pyo3(signature = (...))]` to define default parameter values

## Error Handling

- Define errors in `error.rs` using `thiserror::Error` derive macro
- Map Rust errors to Python exceptions via `From<PasetoError> for PyErr`
- Use specific error variants (e.g., `InvalidKeyLength`, `TokenExpired`) over generic ones
- Include context in error messages (expected vs actual values)

## Code Style

- Follow Rust 2024 edition idioms
- Use `?` operator for error propagation
- Prefer `match` over `if let` chains for multiple variants
- Use `impl Into<T>` or `AsRef<T>` for flexible function parameters
- Avoid `unwrap()` and `expect()` in library code; return `Result` instead
- Use `const` for compile-time constants
- Avoid using `Options` for function parameters;
- Don't use `default` inside `new()` methods; use `new` inside `Default` instead
- Follow a data oriented approach instead of normal OOP
- Avoid having redundant data structures and classes;
- Use `#[derive(Debug)]` for structs and enums

## Cryptographic Code

- All crypto operations must remain in Rust (never Python)
- Use constant-time comparisons via `subtle` crate for sensitive data
- Validate key lengths at function entry points
- Zero sensitive data after use where possible

## Aho-Corasick Pattern Matching

The `aho-corasick` crate provides efficient multi-pattern string matching. Use it when searching for multiple patterns simultaneously.

### Builder Configuration

Use `AhoCorasickBuilder` for customization:

```rust
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

let ac = AhoCorasickBuilder::new()
    .ascii_case_insensitive(true)
    .match_kind(MatchKind::LeftmostLongest)
    .build(&["pattern1", "pattern2"])
    .unwrap();
```

Key builder options:
- `ascii_case_insensitive(bool)` - Ignore ASCII case
- `match_kind(MatchKind)` - Control match semantics
- `dfa(bool)` - Explicitly enable/disable DFA (faster but more memory)
- `dense_depth(usize)` - Limit dense DFA depth for memory optimization
- `prefilter(bool)` - Enable quick rejection of impossible matches

### Match Kinds

- `MatchKind::Standard` - Reports all matches as found (default)
- `MatchKind::LeftmostFirst` - Earliest start position; first pattern in list wins ties
- `MatchKind::LeftmostLongest` - Earliest start position; longest match wins ties

### Memory Optimization (DFA vs NFA)

- **DFA**: Faster matching, higher memory usage. Use for performance-critical paths
- **NFA**: Lower memory, slightly slower. Use for large pattern sets or memory constraints
- Use `auto_optimize(dfa)`

### Common Usage Patterns

```rust
use aho_corasick::{AhoCorasick, Match};

let patterns = &["foo", "bar", "baz"];
let ac = AhoCorasick::new(patterns).unwrap();

// Check if any pattern matches
if ac.is_match("some text with foo") {
    // ...
}

// Find all non-overlapping matches
for mat in ac.find_iter("foo bar baz") {
    println!("Pattern {}: {}..{}", mat.pattern().as_usize(), mat.start(), mat.end());
}

// Find overlapping matches
for mat in ac.find_overlapping_iter("foobar") {
    // ...
}
```

### Best Practices

- Build the automaton once, reuse for multiple searches
- Works on `&[u8]` - use `.as_bytes()` for `&str`
- Does not handle Unicode case-folding beyond ASCII
- Store patterns with `store_patterns(true)` if you need to retrieve them later

## Build Workflow

After any Rust changes:
```bash
maturin develop  # Rebuild extension
cargo test       # Run Rust unit tests
pytest           # Run Python integration tests
```

Run before committing:
```bash
cargo fmt        # Format code
cargo clippy     # Lint for common issues
```
