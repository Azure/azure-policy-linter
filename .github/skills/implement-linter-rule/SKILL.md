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

Related skills:
- `triage-linter-rule` - produces the spec this skill consumes. If you don't have a spec, defer to triage first.
- `sanity-check-linter` - end-to-end CLI verification after the change.
- `review-linter-rule` - design + correctness review of the produced rule.

## The things that matter most

- **The rule and its doc must advance the quality of the policy or the knowledge of the author.**
  - You must be able to articulate the value this rule will provide to the policy author.
  - Every choice you make must serve that goal: when to fire, when not to, severity, name, description and documentation.

- **One check, one rule.**
  - If the spec combines independent checks, split them into separate rules.

- **Clarity and simplicity are critical.**
  - An engineer familiar with the linter should be able to review the core implementation in 10 minutes or less.
  - It's ok if a rule doesn't catch all cases. Prefer simple heuristics over complex deterministic checks.
  - Strongly prefer simple-but-not-perfect coverage over an off-the-rails "perfect" implementation.
  - Example: to identify whether the rule targets a specific resource type, check whether it references aliases for that type instead of building a SAT solver to reverse engineer the policy rule.

- **Specs aren't ground truth, especially not AI-generated ones.**
  - Even if the rule is implemented in the same session where it was triaged, treat implementation as an independent engineering step. The goal is to **ship** a valuable rule to policy users. A polished spec isn't a guarantee of quality or value.
  - The implementation stage will often uncover things the spec missed. Pivot when necessary. Adhering to the linter's guidelines and providing value to the policy author matter more than following the spec literally.

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

- Start with the semantic problem in the author's policy. By the end of the first sentence, the author **MUST** understand what is wrong.
- Do not go into describing the implementation details, or echo the rule's spec. This is not the place.
- Open with the construct named in the user's vocabulary and quoted in single quotes: `"The field alias: '{0}'..."`.
- Use structured placeholders (`{0}`, `{1}`) filled at emit time. **Avoid the passthrough form** (`descriptionFormat: "{0}"`); that's usually a sign you actually have more than one rule.
- Substitute a realistic value mentally and read the result aloud. If it reads awkwardly - "The parameter reference 'myParam' does not match..." vs "The parameter reference '[parameters('myParam')]' does not match..." - rewrite the format string so it reads naturally regardless of what's substituted.
- 150-300 characters. Hard ceiling 400. No URLs, no line breaks.

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

Any mismatch is a bug. If you rename or rescope mid-flow, **run this audit before declaring done.**

Also verify that the remediation in `RuleDescription` agrees with the doc's Suggestions section, and that both use the same terms for the same policy concepts.

### 7. Version bump (if applicable)

If the release process requires a version bump, bump `<Version>` in `Directory.Build.props` - the single source shared by both packages. Suggest it to the user; don't apply without confirmation.

### 8. Hand off

- Run `sanity-check-linter` to confirm the CLI behaves end-to-end with the new rule.
- Offer to run `review-linter-rule` for a design + correctness review of what you produced.

When addressing review feedback, determine whether the comment is specific to one artifact or exposes a convention that applies across the rule, its tests, its doc, or other rules in the same change. Apply the general feedback everywhere it holds before replying.

## Patterns worth knowing about

The architecture doc has one end-to-end walkthrough. A few patterns are non-obvious and worth knowing exist; look at the reference rule when your task fits the shape:

- **One error per missing property, not aggregated.** When checking that several properties are present, emit a separate finding for each missing one rather than stitching them into one branching message.
- **Negation detection via `PathSegments`.** A rule that needs to know whether it's inside a `not` quantifier reads the parent path rather than walking up by reference. See the field-alias rules.
- **Field-alias metadata inspection.** When the rule's decision depends on resource-provider metadata (API versions, readonly/optional), use `Reference.ResourcePropertyMetadata` rather than re-resolving the alias. See `OptionalFieldAlias`, `ConditionalFieldAlias`.
- **Raw `JToken` traversal for unmodeled structures.** When the rule needs to inspect parts of the policy the engine doesn't model as typed nodes (effect details, metadata bag), use the shared JSON walker rather than ad-hoc recursion.

When the rule set is non-default, look at 2-3 existing rules in that set before writing - those sets have scenario-specific conventions that aren't covered here and won't be apparent from first principles.

## Specifics that bite

The design doc's *Naming* and *Description* sections cover the recurring AI-fingerprint tone failures (invented vocabulary, engine-mechanics digressions, speculative explanations, harsh verdicts, branching descriptions, `Must` outside Error severity). Re-read those before shipping if you're unsure.

Two failures that aren't in the design doc and recur enough to call out:

- **Comments that take dependencies on "other code".** Don't write `// other rules handle that case` - that's an implicit coupling. Comment the local invariant only.
- **Re-checking what the platform already validates.** The policy definitions REST API rejects malformed policies before the linter sees them. Rules that duplicate platform validation are low value; if you find yourself writing one, confirm with the user that it's intentional, and use Error severity (not Warning - the platform already errors).

## Hard rules

- Output is a working rule + tests + doc, all coherent across every artifact.
- Never proceed past identity-lock without the user's confirmation on rule set, title, identifier, and severity.
- Never invent vocabulary not present in Azure Policy documentation.
- When in doubt about a convention or pattern, look at existing rules in the same rule set rather than inferring from first principles.
- Don't modify files outside the rule, its tests, and its doc without explicit user confirmation.
- Never implement missing core linter functionality inside a rule.
