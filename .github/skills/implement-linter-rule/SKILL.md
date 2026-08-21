---
name: implement-linter-rule
description: 'Implement an Azure Policy Linter rule from a spec. Produces the rule code, tests, per-rule doc, and version bump, coherent across every artifact. Triggers: "implement this linter rule", "write the linter rule", "build the rule from spec", "add a new linter rule".'
---

# Skill: Implement a Policy Linter Rule

Take a spec for a single linter rule and produce a working, tested, documented rule that conforms to repo conventions. Hand off to `sanity-check-linter` and `review-linter-rule` at the end.

## References

Read these before writing anything:

- `docs/linter-rule-design.md` - what a good rule looks like (scope, severity, naming, description, documentation). Source of truth for design decisions.
- `docs/linter-architecture.md` - how rules work in code (contract, expression tree, helpers, test placement, file locations). Source of truth for implementation.

- Follow the guidelines in [linter-rule-design.md](../../../docs/linter-rule-design.md) to the letter.

## The things that matter most

- **The rule must advance the quality of the policy or the knowledge of the author.**
  - You must be able to articulate the value this rule will provide to the policy author.
  - Every choice you make must serve that goal: when to fire, when not to, severity, name, description and documentation.

- **Specs aren't ground truth, especially not AI-generated ones.**
  - Even if the rule is implemented in the same session where it was triaged, treat implementation as an independent engineering step.
  - A well-polished spec isn't a guarantee of quality or value.
  - The implementation stage will often uncover things the spec missed. Pivot when necessary. Adhering to the linter's guidelines and providing value to the policy author matter more than following the spec literally.

- **One check, one rule.**
  - If the spec combines independent checks, split them into separate rules.

- **Clarity and simplicity are critical.**
  - An engineer familiar with the linter should be able to review the core implementation in 10 minutes or less.
  - Getting partial rule coverage is preferred if the "perfect" implementation requires complex, over-the-top, implementation.
    - The main red flags are custom logic for expression parsing, processing or evaluation logic for a specific linter rule.
    - Example: Identifying resource type applicability in a rule that looks for policies for a specific resource type can do a simple check of which aliases are being used. No need to write a perfect applicability detector, which is most likely an NP-Complete problem. This is a linter, not a SAT solver.

- **Use the policy author's vocabulary.**
  - Names, descriptions, and docs only use terms that already exist in Azure Policy documentation - `field`, `alias`, `effect`, `parameter`, `allowedValues`, etc. **Do not invent categorizing nouns** ("groups", "shapes", "patterns", "buckets"). If you find yourself coining a term, describe the pattern instead, or pick a name that already exists in the policy documentation.
  - The rule name, description and documentation MUST be simple and easy to read. They should not echo the spec, describe implementation details, or use software engineering jargon. They should target policy authors, not policy engineers.

- **Don't leave dead or stale artifacts.** Implementation can change between iterations. Clean all references to old implementations.

## Flow

### 1. Confirm the spec

If you received a spec from `triage-linter-rule`, you have: Title, Summary, Target, Applicability, Required context, Additional details, examples, optional severity / category / rule set. Read Additional details for missing core capabilities and coverage trade-offs before proceeding.

If you received an informal request, ask only what you need to start:
- What policy construct does this inspect? (Target)
- When does it fire and when does it stay silent? (Applicability)
- Suggested severity?

Without applicability you can't write the rule - resolve it before going further.

If the rule needs a core capability the linter does not have, **stop before locking the identity or writing code**. Ask the user whether to:

- Narrow the rule to a simpler check with explicit coverage gaps.
- Defer the rule until the core capability exists.
- Scope the core capability as separate work.

Do not implement the missing core capability as part of the rule. Do not recreate it privately inside the rule. A utility method local to the check is fine; generic parsing, policy evaluation, applicability, or cross-branch analysis is core functionality.

If you identify a simple-versus-complete coverage trade-off but the spec does not record the user's choice, stop and ask.

### 2. Lock the identity

Before writing any code, decide and surface to the user for confirmation:

- **Rule set** - `default` (universal) or a non-default set. Most rules belong in `default`.
- **Identifier** - kebab-case, used in CLI output and as the doc filename. Describes the smell, not the fix: `optional-field-alias`, not `add-field-existence-check`.
- **Title** - descriptive PascalCase noun phrase by default (`OptionalFieldAlias`, `MissingDisabledEffectAllowedValue`). Prescriptive titles using `Must`/`Should`/`Use`/`Avoid` are acceptable only for non-default rule sets, or when the descriptive form is awkward.
- **Severity** - Error / Warning / Informational. **`Must` in any user-facing string means Error severity** - do not use `Must` for warnings or informationals. The `Critical` severity and the `Parsing`/`Linter`/`LinterRule` categories are reserved for engine-emitted findings; do not use them in rules.
- **Category** - match an existing category used by rules in the same rule set; don't invent unless there's truly no existing match.
- **Target expression type** - the `T` in `LinterRule<T>`. See the architecture doc's expression tree catalog.

Renames after this step are expensive - they ripple across the cascade audit.

### 3. Implement the rule class

- **File location**: see the architecture doc for the current layout. Default-set rules and non-default rules live in different folders; verify against where rules of the same set actually live today rather than hardcoding.
- **Namespace**: all rule namespaces sit under `Microsoft.Azure.Policy.PolicyLinter.Core.Rules.<Folder>`.
- **Standard structure**: `sealed class`, parameterless constructor calling `base(...)`, `private const string RuleTitle` and `RuleDescription` fields, override `Evaluate` returning `LinterOutput[]`.
- **Early-return guards first**; emit only after all preconditions are satisfied.
- **Don't modify files outside the rule's own file, its tests, and its doc.** Utility methods specific to the rule can live in the rule file. If the implementation needs a generic core capability or an engine change, return to step 1 and stop for explicit user approval.

**Complexity check before continuing:**
- Most shipped rules are 40-120 lines.
- Rules should take no more than 10 minutes to review.
- Stop and do an honest self-assessment. Have you gone over the top? Is it overkill?
  - Ask a sub-agent to review and provide explicit feedback on simplicity and scope.
- Stop and revisit the coverage decision when the implementation is heading past roughly 150 lines, takes longer than 10 minutes to review, or its complexity is disproportionate to the value and coverage gained.
- Correct and tested code can still be over-built.

**Common traps the engine model invites:**

- **Effect details (`then.details.*`) are not typed nodes.** If your rule needs to inspect `roleDefinitionIds`, `existenceCondition`, `deploymentScope`, etc., target `ThenExpression` and walk the raw `JToken` - do not invent an expression type for them.
- **Guard with `HasLiteralValue` before treating `Property.Value` as a runtime constant.** Otherwise `[parameters('x')]` strings get compared as raw text. If your rule intentionally handles parameterized values, use `HasSimpleParameterizedValue` instead of parsing the raw string.
- **Treat `null` and `[]` differently on collections.** `null` means the property is absent; an empty array means the author set it to empty explicitly. Skip on `null`; evaluate on `[]` unless the rule has a documented reason not to.
- **Operator names are case-sensitive literals.** The valid set: `equals`, `notEquals`, `like`, `notLike`, `in`, `notIn`, `contains`, `notContains`, `containsKey`, `notContainsKey`, `exists`, `match`, `notMatch`, `greater`, `greaterOrEquals`, `less`, `lessOrEquals`, `matchInsensitively`, `notMatchInsensitively`. Note `greaterOrEquals` (not `greaterOrEqual`) and `matchInsensitively` (not `matchInsensitive`).

**Things AI agents reach for first that are wrong:**

- *"I'll use regex to find or parse `[...]` template expressions"* - no. Use `ExpressionEngine.IsLanguageExpression()` and `ExpressionsEngine.ParseLanguageExpression()`.
- *"Field references are always inside `field()` calls"* - not always. They also appear as `LeafCondition.Field` directly or implicitly in `current()` functions. `Reference.IsResolvedFieldReference()` handles all shapes.
- *"I'll lowercase both sides for case-insensitive compare"* - no `.ToLower()`/`.ToUpper()`. Use `StringComparison.OrdinalIgnoreCase` overloads.
- *"I'll allocate the allowlist `HashSet` inside `Evaluate`"* - no. Static allowlists are `private static readonly HashSet<T>` on the class, allocated once.

**Description format string discipline:**

- This is string will be included in the linter's output and is the user's first encounter with the issue.
- It will typically be included in the console output (when using CLI), or in a PR comment based on running the linter.
- Therefore, it must be a short, informative, description of the issue the linter rule found.
- By the end of the first sentence, the author **MUST** understand what is wrong with their specific policy.
- The description is a static string format, with placeholders to include dynamic information from the policy expression.
- Typical format: `"The *problematic expression type* *problematic expression value* *problem description*"`
  - e.g. `"The field alias: 'Microsoft.Test/whatever' is not available in older API versions: 2021-01-01, ...."`
  - 150-300 characters. Hard ceiling 400. No URLs, no line breaks.
- Do not:
  - Mention how the linter found the issue, or any implementation or design details of the linter rule.
  - Go into excessive details on context, examples, mitigation options, etc. These should be in the linter rule doc file.
  - Abuse the string format. **The description content should be static. Formatting is only used to include policy details**. Descriptions like `found issue: "{0}"` are not allowed and are usually a sign you need more than one rule.
- Open with the construct named in the user's vocabulary and quoted in single quotes: `"The field alias: '{0}'..."`.
- Use structured placeholders (`{0}`, `{1}`) filled at emit time to include information from the analyzed policy.

### 4. Write tests

xUnit + FluentAssertions. Location: see the architecture doc's testing section.

- Each rule gets its own separate file: `src/Tests/RuleTests/<RuleName>Tests.cs`. Do not add a new rule's tests to a shared file or to another rule's file.
- For test structure, mock/utility choices, and other implementation details, look at the existing files in `src/Tests/RuleTests/` and helpers in `src/Tests/Common/`.

Minimum coverage:
- One negative (rule fires, exact-equivalence assertion on the `LinterOutput`).
- One positive (rule doesn't fire, `Should().BeEmpty()`).
- Each distinct triggering condition gets its own negative case.
- Missing properties, empty arrays, and case-insensitivity get their own positive cases when the rule's logic touches them.

Construct a full `LinterOutput` record and assert via `ContainEquivalentOf` - this checks all fields including line number and path in one expression rather than matching on substrings. For path-aware rules (those that consume `context.FilePath`), pass `filePath:` to `Lint(...)`.

Test names: `RuleTests_<RuleName>_<Case>` for the default rule set; `RuleTests_<RuleSet>_<RuleName>_<Case>` for non-default rule sets.

### 5. Write the rule doc

The filename matches the rule identifier exactly. The H1 matches the rule's title verbatim. Default-set rule docs live in `docs/Rules/`; see the architecture doc for the layout.

Three required sections, followed by optional examples:
1. **Metadata table** - category, identifier, severity, rule set.
2. **Description** - 2-4 sentences, third-person declarative. Start with the problem in the policy and its consequence. Detection mechanics, expression-tree details, metadata predicates, and exhaustive applicability conditions belong in the implementation or references, not here.
3. **Suggestions** - imperative, second-person. Bulleted when there are multiple steps.
4. **Examples (optional)** - minimal "violation" and "correct" fragments, when they add signal. Show only the relevant property, not a full policy document. Omit examples when the description is self-evident.

When the rule touches a documented Azure Policy concept (operator, field reference shape, effect, parameter type), link to the official Microsoft Learn page. Don't restate documentation that already exists elsewhere - point at it.

Match doc depth to problem depth. An obvious-once-pointed-out issue deserves a short doc; a rule whose remediation involves judgment deserves the space.

Don't add a long block of CLI invocation instructions to each doc just because the rule is in a non-default rule set - the metadata table already says which rule set the rule belongs to.

### 6. Coherence cascade audit

Before declaring done, verify the rule's identity is consistent across every artifact:

1. Class name (PascalCase, matches `RuleTitle` with spaces removed).
2. File name (matches class name).
3. File path (under the correct rule-set subfolder).
4. Namespace (matches folder structure, sits under `.Core.Rules.*`).
5. `[RuleSet("...")]` attribute (or absence, for default).
6. `identifier` constructor argument (kebab-case derived from class name).
7. `RuleTitle` constant.
8. `RuleDescription` constant (placeholder count matches the `CreateXxx` call's args).
9. Doc filename (matches identifier exactly).
10. Doc H1 (matches `RuleTitle` verbatim).
11. Doc metadata table values (match identifier, category, severity, rule set used in code).
12. The doc's first paragraph plainly states what's the issue with the policy.
12. The remediation in `RuleDescription` agrees with the doc's Suggestions section, and that both use the same terms for the same policy concepts.

Any mismatch is a bug. If you rename or rescope mid-flow, **run this audit before declaring done.**

### 7. Version bump (if applicable)

If the release process requires a version bump, bump `<Version>` in `Directory.Build.props` - the single source shared by both packages. Suggest it to the user; don't apply without confirmation.

### 8. Hand off

- Run `sanity-check-linter` to confirm the CLI behaves end-to-end with the new rule.
- Offer to run `review-linter-rule` for a design + correctness review of what you produced.

## Hard rules

- Output is a working rule + tests + doc, all coherent across every artifact.
- Never proceed past identity-lock without the user's confirmation on rule set, title, identifier, and severity.
- Never invent vocabulary not present in Azure Policy documentation.
- When in doubt about a convention or pattern, look at existing rules in the same rule set rather than inferring from first principles.
- Don't modify files outside the rule, its tests, and its doc without explicit user confirmation.
- Never implement missing core linter functionality inside a rule.
