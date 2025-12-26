---
inclusion: manual
---

# Subagent Usage Guidelines

## When to Use Subagents

### context-gatherer (Use First for Unfamiliar Code)
- **Always use at the start** when working with unfamiliar parts of the codebase
- Investigating bugs or issues that span multiple files
- Understanding how components interact before making changes
- Repository-wide problems where relevant files are unclear
- Use **once per query** at the beginning, then work with gathered context

### general-task-execution (For Parallel Work)
- Delegating well-defined subtasks while continuing other work
- Parallelizing independent work streams (e.g., multiple file modifications)
- Tasks that benefit from isolated context and tool access

## Critical Rules

### Testing
- **Never run tests in subagents** - always run `pytest` and `cargo test` in the main agent
- Subagents should focus on code exploration, analysis, or isolated modifications
- Test execution requires the full context and should be done after all changes are complete

### Parallel Execution
- When a task has multiple independent subtasks, use subagents to parallelize work
- Example: Modifying multiple unrelated Rust modules simultaneously
- Do not parallelize dependent tasks (e.g., don't modify a function and its caller in parallel)

### Build Commands
- Subagents should not run `maturin develop` - this is a main agent responsibility
- After subagent modifications to Rust code, the main agent must rebuild before testing

## Best Practices

- Trust subagent output - avoid redundantly re-reading files they've analyzed
- Use context-gatherer proactively based on task type, not just when explicitly requested
- Choose the most specific subagent for the task
- Don't overuse subagents for simple, single-file tasks you can handle directly
