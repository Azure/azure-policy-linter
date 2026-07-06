# GitHub Copilot Instructions for Policy Linter

## Project Overview

This repo is the Azure Policy Linter - a tool that inspects policy definitions for quality issues.

Start here:
- `README.md` - what the linter is, install, CLI usage.
- `CONTRIBUTING.md` - how to engage with the project (issues, feedback, code of conduct).

For deeper divers:
- `docs/linter-rule-design.md` - what a good linter rule should be (scope, severity, naming, description). **Read first when working on any rule.**
- `docs/linter-architecture.md` - engineer-facing reference for the linter's code.

For rule work, use the skills under `.github/skills/`:
- `triage-linter-rule` - interactive: turn a fuzzy idea into a concrete spec.
- `implement-linter-rule` - interactive: implement a rule from a spec.
- `review-linter-rule` - interactive: review a proposed rule against the design conventions.
- `sanity-check-linter` - run the CLI against a temporary policy to confirm a change behaves as expected.

## Working in this repo

### Testing and coverage

Before submitting a PR, run tests and verify diff coverage on your changes:

```powershell
dotnet test src/Tests/PolicyLinter.Tests/PolicyLinter.Tests.csproj --collect:"XPlat Code Coverage" --results-directory ./TestResults
diff-cover TestResults/**/coverage.cobertura.xml --compare-branch origin/main
```

Diff coverage must be at least 90% (aim for 100%). If `diff-cover` reports uncovered lines in your changes, add tests before submitting.

### Communication
- Be concise and matter-of-fact. State what you know, don't editorialize.
- Separate fact from inference. When inferring, guessing, recalling from training, or offering an opinion, mark it explicitly ("I think", "in my opinion").
- Never use emojis. Use plain ASCII punctuation in files: a hyphen (`-`) instead of en/em dashes, `->` instead of arrow characters, and straight quotes instead of curly quotes.
- When writing documentation, ask who the audience is. For docs aimed at engineers in this repo: concise, accurate, no padding.

### Engagement
- Don't simply agree. If a request doesn't make sense, push back.
- Ask for clarification before making non-trivial changes.

### Fit the codebase
- Consistency with the existing codebase matters more than your personal preferences. Changes should feel like they belong.
- If you're unsure about a pattern or convention, find more examples before writing.
- Reinventing helpers or utilities that already exist is a common review finding. When the work spans multiple modules, scan for prior art first.

## Basic C# code style hints

### Layout
- `using` statements go inside the namespace block.
- No trailing whitespace, including on blank lines.

### Documentation and comments
- Public methods, properties, and classes need XML documentation.
- Comment why, not what. Add comments only when context is needed or when the code isn't trivial to follow.

### Naming and member access
- When calling a method, explicitly specify the argument names.
- Non-static method calls: `this.MethodName()`.
- Static method calls: `ClassName.MethodName()`.
- Static field or property access: `ClassName.MemberName`.

### LINQ
- End `.Select(...)` chains with `.ToArray()`.
- Prefer arrays over lists for return values and intermediate LINQ results. Use lists only when the size is genuinely unknown or the collection is expected to grow.

### Chained method calls

Break long fluent chains across lines. For small arg counts, one method per line:

```csharp
this
    .Method1(argName: argValue)
    .Method2(argName: argValue)
    .ConfigureAwait(false);
```

For methods with many args, break each arg onto its own line:

```csharp
this
    .Method1(
        argName: argValue,
        ...)
    .Method2(
        argName: argValue,
        ...)
    .ConfigureAwait(false);
```
