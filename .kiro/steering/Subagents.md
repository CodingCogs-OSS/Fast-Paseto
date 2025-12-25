---
inclusion: always
---
When running tasks if task has multiple subtasks it is possible to run them in parallel. This can be done by using `parallel` keyword in task definition. It's like using "Run subagents to...". This keyword can be used in two ways:

1. `parallel: true` - this will run all subtasks in parallel
2. `parallel: <number>` - this will run only specified number of subtasks in parallel

never run any test in subagents and always run tests in main agent
