---
inclusion: always
---

# Subagent Usage

## Quick Reference

| Subagent | Use For | Don't Use For |
|----------|---------|---------------|
| `context-gatherer` | Exploring unfamiliar code, bug investigation | Already know which files to edit |
| `general-task-execution` | 🔀 Parallel independent tasks | Sequential/dependent work |

## 🔀 Parallel Tasks

Tasks marked with 🔀 in specs can run simultaneously via `general-task-execution`. Look for independent subtasks like:
- Multiple unrelated Rust modules
- Separate test files
- Independent feature implementations

## Rules

1. **Tests in main agent only** - never run `pytest` or `cargo test` in subagents
2. **Build in main agent only** - run `maturin develop` after subagent Rust changes
3. **Trust subagent output** - don't re-read files they've already analyzed
4. **One context-gatherer per query** - use at start, then work with gathered context
