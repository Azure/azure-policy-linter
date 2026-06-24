---
name: review-linter-rule
description: 'Review a proposed or generated Azure Policy Linter rule against the repo''s design conventions and common AI-fingerprint failure modes. High-signal, low-noise - only flags things that actually matter. Triggers: "review this linter rule", "check the rule", "review the rule before I commit", "audit this rule".'
---

# Skill: Review a Policy Linter Rule

Review a single proposed or modified linter rule - its code, its tests, and its doc - and return a tight list of issues that genuinely matter. Optimize for signal: do not flag formatting nits, things compilers/analyzers catch, or principles that the canonical docs cover and the author is plainly aware of.

## References

Read these before reviewing anything:

- `docs/linter-rule-design.md` - what a good rule looks like. The review is largely an audit against this doc.
- `docs/linter-architecture.md` - how rules work in code. Reference for the contract, helpers, and where things live.

Related skills:
- `implement-linter-rule` - produces the artifacts this skill reviews. Understanding its flow helps you spot where things tend to drift.

## The things that matter most

1. **The rule must help a policy author do something about their policy.** Every artifact - the finding's title, the description, the doc - has to help the author understand what was found, why it matters for their policy, and what to do about it. This is the lens for everything below.

2. **Coherence cascade.** A rule's identity lives in ~10 places - class name, file path, namespace, `[RuleSet]` attribute, `identifier`, `RuleTitle`, `RuleDescription` placeholder count, doc filename, doc H1, doc metadata table. AI implementations reliably update some and forget others. Audit all of them.

3. **AI-fingerprint tone failures.** A separate cluster of failures recur because the model defaults to confident, abstract, exhaustive prose. Catch them by name (see the "Tone discipline check" below).

## Flow

1. **Read** the rule's `.cs` file, its test file, and its doc file. If any of the three is missing, that's the first finding - stop and report it.

2. **Read** `docs/linter-rule-design.md` if you haven't already in this session. The design doc is the source of truth for the design checks below; don't review from memory.

3. **Work through the three check groups in order:** coherence cascade -> tone discipline -> implementation. Stop and gather findings as you go; don't report them one at a time.

4. **Report findings** in the format below. If a check group is clean, say so in one line - don't pad. If the rule passes everything, say so plainly.

## Coherence cascade check

Walk the list. Any mismatch is a finding.

1. Class name (PascalCase, matches `RuleTitle` with spaces removed).
2. File name (matches class name).
3. File path (under the correct rule-set subfolder).
4. Namespace - sits under `Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Rules.<Folder>` regardless of which project; matches the folder structure.
5. `[RuleSet("...")]` attribute present for non-default rule sets, absent for default.
6. `identifier` constructor argument (kebab-case, matches doc filename exactly).
7. `RuleTitle` constant (matches doc H1 verbatim).
8. `RuleDescription` constant placeholder count matches the args passed to `CreateXxx(...)`.
9. Doc filename (matches identifier exactly).
10. Doc metadata table (identifier, category, severity, rule set all match what's in code).

## Tone discipline check

Check every user-facing string (title, description format, doc body, suggestions) against this list:

- **Invented categorical nouns.** "Effect groups", "shapes", "buckets", "patterns" - terms that don't exist in Azure Policy documentation. Flag and propose either the existing taxonomy term or a prose description.
- **Engine-mechanics digressions.** "More efficient", "the engine still performs pattern matching", "avoids extra allocations." The policy author doesn't care. Flag.
- **Speculative-mistake explanations.** "Typically indicates a typo", "the author probably forgot to..." Don't speculate about author intent. Flag.
- **Harsh verdicts.** "Incorrectly cased", "wrong value", "invalid configuration." The author hasn't done anything wrong; the rule found a pattern. Flag.
- **Branching descriptions.** Single description format string with "missing X" / "missing Y" / "missing X and Y" fragments. Should be one finding per problem. Flag.
- **`Must` outside Error severity.** `Must` in class name, title, description, or doc with anything other than `Severity.Error`. Flag.
- **Awkward substitution.** Pick a realistic value for each `{0}`/`{1}` placeholder and read the description aloud. If it reads strangely with the substituted value (e.g. "The parameter reference 'myParam' does not..." vs the expected "...references parameter 'myParam'..."), flag it.
- **URLs or line breaks in description.** Description is single-line, no URLs. Flag.
- **Description longer than 400 characters.** Aim for 150-300; 400 is a hard ceiling. Flag.
- **Comments that take dependencies on other code.** `// other rules handle that case` and similar. Flag.

## Implementation check

The implementation checks worth running are the ones that catch real bugs:

- **Engine-code modification.** The rule must only touch its own `.cs`, its test, and its doc. Files added or modified under `src/PolicyLinter.Core/Expressions/`, `Parsing/`, `Extensions/`, `Metadata/`, or other root engine paths are a red flag - the logic belongs in the rule. **Flag as Error.**
- **`sealed class` and `applyToDerivedTypes: false`.** Every rule should be `sealed`. Constructor should pass `applyToDerivedTypes: false` unless the rule has a documented reason to walk derived expression types. Both are easy to miss; analyzers don't catch either.
- **XML documentation shape.** Class has a real `<summary>` describing what the rule checks - never `/// <inheritdoc/>`. `Evaluate` uses `<inheritdoc/>`. Constructor uses the standard `Initializes a new instance of the <see cref="..."/> class.` form.
- **`HasLiteralValue` guard and `HasSimpleParameterizedValue` companion.** Any read of `Property.Value` that doesn't go through `HasLiteralValue` first will misfire on `[parameters('...')]` values. Inversely, rules that intentionally handle parameterized values should use `HasSimpleParameterizedValue`, not regex on the raw string. Flag either failure mode.
- **`null` vs `[]` collection handling.** Verify the rule treats `null` (absent property) differently from an empty array (explicitly set to empty). Skipping on both is a common bug.
- **Emit target specificity.** `CreateError`/`CreateWarning`/`CreateInformational` should be called with the most specific expression node, not the parent. Diagnostic line numbers and JSON paths come from the passed node. Flag if the rule passes a parent node when it could pass a child.
- **One finding per independent problem.** If the rule checks multiple unrelated properties and aggregates them into one finding (especially via a branching description), flag - should be one per problem.
- **Regex on template language expressions.** Any use of `Regex` to detect or parse `[...]` expressions. Use `ExpressionEngine.IsLanguageExpression()` / `ExpressionsEngine.ParseLanguageExpression()`. Flag.
- **`.ToLower()`/`.ToUpper()` for case-insensitive comparison.** Use `StringComparison.OrdinalIgnoreCase` overloads. Flag.
- **Local allocation of allowlist sets.** Static allowlists belong as `private static readonly HashSet<T>` on the class, not allocated per `Evaluate` call. Flag.
- **Reserved severity/category.** `Severity.Critical` and `Category.Parsing` / `Linter` / `LinterRule` are reserved for engine-emitted findings. A rule using any of these is wrong. Flag as Error.
- **Non-default rule-set conventions.** For non-default rule sets, set-specific conventions live in the existing rules in that set, not in the design doc. Skim 2-3 sibling rules and flag deviations from their patterns.

### Test-specific checks

- **At least one negative and one positive case.** Negative = rule fires with exact-equivalence assertion; positive = `Should().BeEmpty()`.
- **`HaveCount(N)` before `ContainEquivalentOf`.** Without the count assertion, a test passes when the rule wrongly emits extra findings alongside the expected one. Flag if a test asserts `ContainEquivalentOf` without first asserting count.
- **Assertion via `ContainEquivalentOf` on a full `LinterOutput` record.** Substring or field-only assertions are brittle - they pass for the wrong reason. Flag if used.
- **Case-insensitivity, missing properties, and empty arrays each get a test** when the rule's logic touches them.
- **Test names follow `LinterTests_<RuleName>_<Case>`.** The class location identifies the rule set; the method name shouldn't repeat it. If pre-existing tests in the same file carry a legacy `_<RuleSet>_` segment, the rule's new tests should still use the current convention - flag inherited legacy patterns.

### Doc-specific checks

- **Four sections in order:** metadata table, description, suggestions, examples.
- **Description is third-person declarative**, suggestions are imperative second-person, examples are minimal fragments (not full policies).
- **Examples are labelled `Violation` and `Correct`** - not `compliant` / `non-compliant`. The latter is bureaucratic AI-default phrasing.
- **Property names in doc body match the policy JSON's actual casing** (camelCase: `endpointKind`, `allowedValues`, `existenceCondition`). PascalCasing them is a recurring AI fingerprint that survives review because both readings parse.
- **Microsoft Learn links for documented Azure Policy concepts** (operators, effects, parameter types). Their absence isn't always a finding, but flag if the doc restates concepts that have canonical pages.
- **Depth matches the problem.** A short rule deserves a short doc; padding to look thorough is a finding. So is compressing a judgment-heavy rule to look tidy.
- **No CLI-invocation block** ("to run this rule, do X") - that's the CLI's documentation problem, not the rule's. The metadata table already names the rule set.

## Output format

Group findings by check group (Coherence cascade / Tone discipline / Implementation). Within each group:

```
[SEVERITY] <short label>
  File: <path>:<line>
  <one-line description of the issue>
  Fix: <one-line concrete fix>
```

Severities:
- **Error** - the rule is broken, ships wrong, or violates a hard project rule. Must fix.
- **Warning** - the rule deviates from convention in a way that will hurt readers or maintainers. Should fix.
- **Suggestion** - minor improvement; the rule works without it.

If a check group has no findings, list it with "No findings." Don't pad.

If the whole rule passes, say "Rule passes review. No findings." That's the whole output.

## Hard rules

- Output is a tight, grouped list of findings or "Rule passes review. No findings." - nothing else.
- Don't flag things that compilers, analyzers, or `.editorconfig` already catch.
- Don't flag formatting (whitespace, brace placement, import ordering).
- Don't restate principles the rule already follows.
- Don't speculate about intent. State what was found.
- Don't propose alternative implementations beyond a one-line "Fix:" - the implement skill owns implementation.
- When in doubt, omit. A clean review with three real findings is more valuable than a noisy review with thirty.
