# How the Policy Linter Works

A guide to the linter's code: how it's put together, where things live, and what it takes to add a rule. The audience is engineers who are familiar with policy but haven't worked on the linter before. It also assumes familiarity with the project's code conventions. Companion to `linter-rule-design.md`, which covers what a rule *should* be; this doc covers what a rule *is* in code.

## The 30-second picture

The linter ships as two packages: **Core** holds the engine, the in-memory model of a policy definition, and the rules; a **CLI** package hands the engine a stream of policy JSON files. Additional distributions can build their own CLI that bundles extra custom rule sets (for example, conventions for a specific class of policies).

Rules are C# classes that implement `LinterRule<T>`, where `T` is the policy definition expressions the rule wants to inspect - a `ThenExpression`, a `LeafCondition`, a `Reference`, the root `PolicyDefinition`, etc. The engine parses each policy into a strongly-typed tree of these components, walks the tree, and for every node hands the node to whichever rules declared that node's type as their `T`. Each rule's `Evaluate` returns zero or more findings. Every node carries its source line, column, and JSON path, so a finding can point back to the exact location in the input file.

Rules don't register themselves. At startup the CLI reflects over the assemblies it knows about, finds every concrete `ILinterRule` implementation, and instantiates them. Filtering by `--rule-set` happens at this stage.

Beyond the parsed tree, the engine makes additional context available to each `Evaluate` call: a `TypeMetadata` for resolving resource-type aliases, the policy's parameters dictionary, the source file path, and any other components of the policy definition. Rules consume this via a `LinterContext` argument.

## The expression tree

A policy JSON is parsed into a strongly-typed tree. Every node derives from `PolicyExpression` (`src/PolicyLinter.Core/Expressions/PolicyExpression.cs`), which carries `LineNumber`, `LinePosition`, `Path`, `PathSegments`, and `Parent`. The line/position come from the JSON deserializer's line tracking; the path is the dot-joined property route from the root.

The node types you'll most often target as a rule author:

| Node | Holds |
|---|---|
| `PolicyDefinition` | Root. `Name?`, `Properties`. |
| `PolicyDefinitionProperties` | `DisplayName?`, `Description?`, `PolicyType?`, `Mode?`, `Metadata?`, `Version?`, `Parameters` (case-insensitive dictionary), `ExternalEvaluationEnforcementSettings?`, `PolicyRule`. |
| `PolicyRule` | `If` (IfCondition), `Then` (ThenExpression). |
| `IfCondition` | Wraps a single `Condition`. |
| `LeafCondition` | One condition: `Field?` / `Value?` / `Count?` (mutually exclusive) plus an `Operator?` (one of 18 supported operator names). |
| `Quantifier` | `AllOf?`, `AnyOf?`, `Not?`. |
| `ThenExpression` | Just `Effect` (a `Property`). The linter does **not** currently model effect details (`details.roleDefinitionIds`, `existenceCondition`, etc.) as typed nodes - if you need them, walk the raw `JToken`. |
| `Property` | Key-value pair derived from a json property. Holds `Name`, `Value` (`JToken`), `LanguageExpressions` (template references in the value), `HasLiteralValue`, and `HasSimpleParameterizedValue(...)`. |
| `Reference` | A parsed template-language reference (`field`, `parameters`, `current`, `claims`, etc.). Carries `Kind`, `Identifier`, `IsResolved`, `PropertySelectionPath?`, and `ResourcePropertyMetadata` for resolved field aliases. |
| `Parameter` | A policy parameter's `Name`, `Type`, `AllowedValues?`, `DefaultValue?`, plus `TryAsConcreteType<T>` for unwrapping to a C# type. |

There's also `Count` (for `count` conditions with their own scope), `ExternalEvaluationEnforcementSettings` and `EndpointSettings` (for policies that declare an external-evaluation enforcement block), and `TemplateLanguageExpression` (the parsed form of a `[...]` value). For the full list see `src/PolicyLinter.Core/Expressions/`.

Things to know about parsing: it's eager (every child is built when its parent is constructed), it's strict and will fail to parse a policy component that is missing required properties, and it doesn't support partial JSON files. Generally, the linter expects the input to have a valid policy definition JSON structure.

## What a rule has access to

A rule's `Evaluate` is called with the typed expression node it targets, plus a `LinterContext` (`src/PolicyLinter.Core/Rules/Contracts/LinterContext.cs`):

- `ResourceTypeMetadata` (`ITypeMetadata`) - `TryGetAliasPropertyMetadata(alias, out ResourcePropertyMetadata[])`. The real implementation walks an offline metadata snapshot via `TypeMetadata` (`src/PolicyLinter.Core/Metadata/TypeMetadata.cs`).
- `Parameters` - the policy's parameters as an immutable dictionary, populated during parsing.
- `ExternalEvaluationEnforcementSettings` - the parsed external-evaluation block if the policy has one.
- `FilePath` - caller-supplied. Optional; if non-null the engine validates it's absolute. Rules that consume it must handle null.

Resolved field references in `Reference.ResourcePropertyMetadata` are pre-populated at parse time, so a rule asking "what resource type and properties does this alias map to" doesn't have to call the metadata service itself.

## The rule contract

Two pieces in `src/PolicyLinter.Core/Rules/Contracts/`:

```csharp
public interface ILinterRule
{
    string Identifier { get; }
    string Title { get; }
    Category Category { get; }
    string Description { get; }
    bool ApplyToDerivedTypes { get; }
    LinterOutput[] Evaluate(PolicyExpressionBase expression, LinterContext context);
}

public abstract class LinterRule<T> : ILinterRule where T : PolicyExpressionBase
{
    protected LinterRule(string identifier, Category category, string title,
                        string descriptionFormat, bool applyToDerivedTypes) { ... }

    protected abstract LinterOutput[] Evaluate(T expression, LinterContext context);

    public LinterOutput CreateError(PolicyExpression? expression, params object[] descriptionParams);
    public LinterOutput CreateWarning(PolicyExpression? expression, params object[] descriptionParams);
    public LinterOutput CreateInformational(PolicyExpression? expression, params object[] descriptionParams);
}
```

You always derive from `LinterRule<T>`. The base class type-checks the incoming expression against `T` and forwards to your typed `Evaluate`; if the dispatcher ever feeds your rule the wrong type, the base returns a synthetic engine-level finding (`BuiltinLinterOutputs.UnexpectedRuleInvocation`) rather than crashing.

Rules should be thread-safe and stateless. The engine instantiates each rule once and reuses the instance across files, and the linter (both Core library and the CLI) processes multiple policy files in parallel.

**Rules must have a public parameterless constructor** to allow activation via reflection.

### Choosing linter rule target (the `T` in `LinterRule<T>`)

- **Pick the most specific target type that's still right.** Targeting `PolicyExpression` (abstract) without `applyToDerivedTypes: true` matches nothing. Targeting `Condition` (abstract) with `applyToDerivedTypes: true` matches both `LeafCondition` and `Quantifier`. Most rules pick a concrete leaf type (`ThenExpression`, `LeafCondition`, `Reference`, etc.).
- **`applyToDerivedTypes: true` will apply the rule to derived types within the same assembly as `T`.** A subtype added in a different assembly won't be picked up. In practice nearly every shipped rule passes `false`.

### Rule sets

A `[RuleSet("Name")]` attribute on the rule class assigns membership. The CLI's `--rule-set` flag filters by name (case-insensitive). A rule with no attribute is in the rule set named `"default"`, which is what runs when no `--rule-set` is passed.

The attribute is `AllowMultiple = false, Inherited = false` - a rule belongs to exactly one set.

### Discovery is reflection-only

Rules are discovered by scanning their containing assembly. No need to perform any kind of registration or activation beyond just including the rule in the `Core` library.

## The engine

`src/PolicyLinter.Core/PolicyLinter.cs` is the orchestration class. Its constructor takes a `rules` array and a `TypeMetadata`, builds a dictionary keyed by each rule's `T`, and exposes `Lint(rawJson, filePath?)`. `Lint` parses, sets up the context, walks the tree by calling `policyDefinition.Visit(visitor)`, and returns aggregated `LinterOutput[]`.

## Expression tree traversal

All policy expressions in the tree derive from `PolicyExpression`, which has a `Parent` reference, allowing a linter rule to climb up the tree and inspect the parents if necessary.

To traverse child expressions, instantiate a `PolicyExpressionVisitor` and pass it to the `Visit` method of the expression you want to walk. This is how the engine itself evaluates a policy: it creates a visitor that dispatches each node to the rules targeting that node's type, and applies it to the root `PolicyDefinition`.

Traversal might be needed when the rule's logic spans multiple node types in a sub-tree, where the relationship between the nodes is what's interesting (and you couldn't have written it as several smaller rules). It might also be needed to identify the right position to emit an outout. For example, a rule that warns on redundant quantifiers (`allOf` of `allOf`) might want to check its children to see if any of them are qualifiers of the same type (identifying the issue). The same rule might also want to not fire if it's **parent** is a quantifier of the same type so that it the case of multiple levels of redundant quantifiers (`allOf` of `allOf` of `allOf`), the rule only fire once on the root to avoid spamming.

## The output model

```csharp
public record LinterOutput(
    string RuleIdentifier,
    string Title,
    Category Category = Category.Unknown,
    Severity Severity = Severity.Unknown,
    int? LineNumber = null,
    int? LinePosition = null,
    string Description = "",
    string Path = "");
```

`CreateError`/`CreateWarning`/`CreateInformational` on the linter rule base class construct this record for you. The fields you don't pass explicitly come from the rule's metadata or from the `PolicyExpression?` you pass in: `LineNumber`, `LinePosition`, and `Path` on which the rule output applies. **Pass the most specific node** to get the most precise diagnostic location.

**Use structured placeholders.** `Description` is produced by `string.Format(descriptionFormat, descriptionParams)`. The intended shape: a template fixed at rule construction (`"The field alias: '{0}' maps to ... resource type: '{1}'"`) with positional args filled in at finding time. This keeps the message shape inspectable from the rule's static metadata and makes findings from the same rule consistent.

A handful of rules use a passthrough format (`descriptionFormat: "{0}"`) and synthesize the full message at finding time. Avoid this - if findings from one rule need substantively different messages, that usually means you have more than one rule.

### Console vs JSON output

The console formatter prints four lines per finding: the title colored by severity (Error/Critical red, Warning yellow, Informational blue), then `Identifier: <id>` in dark gray, then `Line: <n>, Position: <n>, Path: <path>` if any of those is populated, then the description. Category and the literal severity name aren't printed to the console - color is the only severity signal.

JSON output (`-o file.json`) writes the full record dictionary keyed by the original input file path, with camelCase property names and enums serialized as their string names. CI pipelines should read JSON; humans get the console.

### Engine-level findings

The engine itself can emit findings - typically for parsing failures or unexpected linter behavior. These are the only findings allowed to have `Critical` severity; rules never emit `Critical`. See `src/PolicyLinter.Core/BuiltinLinterOutputs.cs` for the catalog.

## Useful helpers for rule implementation

These show up in most shipped rules. Use them instead of writing the equivalent by hand.

- **`Property.HasLiteralValue`** (`src/PolicyLinter.Core/Expressions/Property.cs`) - true when the property's value has no template-language expressions. Use it to guard before treating `Value` as a runtime constant.
- **`Property.HasSimpleParameterizedValue(context, out parameterName, out allowedValues, out defaultValue)`** - returns true only when the value is a bare `[parameters('name')]` referring to a `String`-typed parameter, and populates the parameter's constraints. Powers most "is this a simple parameter reference and what are its allowed values" checks.
- **`FieldPathHelper`** (`src/PolicyLinter.Core/Expressions/EvaluationHelpers/FieldPathHelper.cs`) - `IsFieldAlias`, `IsArrayAlias`, `FieldAliasHasFullyQualifiedResourceType`, `GetFieldAliasFullyQualifiedResourceType`. Handles the "tags*" exception correctly.
- **`Reference.IsResolvedFieldReference()`** - true for both `[field('alias')]` and `[current('alias')]`-inside-count. Single check that covers both shapes; don't compare `Kind` directly.
- **`Reference.FromLanguageExpression`** - given a parsed `LanguageExpression`, returns every reference inside it (recursively). Use when you need to find references nested inside an arbitrary expression that isn't itself a top-level reference function.
- **`ExpressionsEngine.IsLanguageExpression(string)` / `ParseLanguageExpression(string)`** - from the upstream `Azure.Deployments.Expression` package. The right way to detect and parse a `[...]` value. Never use regex.
- **`TemplateLanguageExpression.ExtractFromJToken(JToken)`** - walks an arbitrary JSON sub-tree and returns every template-language expression it finds, with references already resolved. Useful when you need to inspect expressions inside JSON the linter doesn't model (e.g. `then.details`).
- **`EqualsOrdinalInsensitively` / `OrdinalInsensitiveHashSet`** - from `Microsoft.WindowsAzure.ResourceStack.Common`. Case-insensitive string equality and set lookup without repeating `StringComparison.OrdinalIgnoreCase` on every line.
- **`Parameter.TryAsConcreteType<T>(out T[]? allowed, out T? def)`** - type-checks and unwraps a parameter's `allowedValues` and `defaultValue` to concrete C#. Powers `HasSimpleParameterizedValue`.

## A rule end-to-end

```csharp
namespace Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules
{
    using System;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Collections;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    public sealed class RiskyEffectParameterDefaultValue : LinterRule<ThenExpression>
    {
        private const string RuleDescription =
            "Parameter '{0}' defaults to '{1}', an enforcement effect. " +
            "Assignments that don't override the default will enforce '{1}'. " +
            "Set the default to '{2}'.";

        private static readonly OrdinalInsensitiveHashSet EnforcementEffects = new OrdinalInsensitiveHashSet
        {
            "deployIfNotExists",
            "append",
            "modify",
            "deny",
        };

        public RiskyEffectParameterDefaultValue() : base(
            identifier: "risky-effect-parameter-default-value",
            category: Category.BestPractices,
            title: "Risky Effect Parameter Default Value",
            descriptionFormat: RiskyEffectParameterDefaultValue.RuleDescription,
            applyToDerivedTypes: false)
        {
        }

        protected override LinterOutput[] Evaluate(ThenExpression expression, LinterContext context)
        {
            if (!expression.Effect.HasSimpleParameterizedValue(context: context, out var parameterName, out _, out var defaultValue))
            {
                return Array.Empty<LinterOutput>();
            }

            if (defaultValue == null || !RiskyEffectParameterDefaultValue.EnforcementEffects.Contains(defaultValue))
            {
                return Array.Empty<LinterOutput>();
            }

            var safeDefault = defaultValue.EqualsOrdinalInsensitively("deployIfNotExists") ? "auditIfNotExists" : "audit";

            return new[]
            {
                this.CreateWarning(expression.Effect, parameterName, defaultValue, safeDefault),
            };
        }
    }
}
```

Top to bottom:

- **Namespace** `...Core.Rules.CommonRules` - the repo places all rule namespaces under `.Core.Rules.*`.
- **`using` statements inside the namespace block** - project-wide style rule.
- **No `[RuleSet(...)]` attribute** - the rule lands in `default` and runs whenever no `--rule-set` is specified. Other rule sets must declare the attribute explicitly.
- **`sealed class`** - every rule is sealed.
- **`LinterRule<ThenExpression>`** - the load-bearing choice. The rule cares about the `then` block's `effect`, so it targets `ThenExpression`. The engine will call this rule exactly once per policy.
- **Descriptive title** - names the smell (`"Risky Effect Parameter Default Value"`), not the fix. See `linter-rule-design.md`.
- **Structured-placeholder description** - `{0}`/`{1}`/`{2}` are positional `string.Format` slots filled in when `CreateWarning` is called.
- **Constructor** - Parameterless ctor required by reflection-based discovery. The base-call arguments become the rule's metadata: `identifier` is the kebab-case identifier used in CLI output and as the doc filename; `category` is the taxonomy tag on every finding; `title` and `descriptionFormat` are stored on the instance.
- **`applyToDerivedTypes: false`** - the convention unless you have a concrete reason otherwise.

Inside `Evaluate`:

- **First early return.** The effect isn't a simple `[parameters('name')]` reference - it's a literal, a complex expression, or the parameter isn't `String`-typed. This rule doesn't apply; a different rule handles the literal case.
- **Second early return.** Return if parameter's default is missing (rule is not applicable) or if it's a safe value (`audit`, `auditIfNotExists`, `disabled`, etc.) and there's nothing to flag.
- **The finding.** Compute the safer counterpart (`audit` for most effects, `auditIfNotExists` for `deployIfNotExists`) and emit. Passing `expression.Effect` (the `Property`) rather than `expression` (the whole `ThenExpression`) points the diagnostic's line/position/path at the `effect` key specifically.

The emitted `LinterOutput` for a policy whose effect parameter defaults to `"deny"`:

```
RuleIdentifier: "risky-effect-parameter-default-value"
Title:          "Risky Effect Parameter Default Value"
Severity:       Warning
Category:       BestPractices
LineNumber:     21
LinePosition:   17
Path:           "properties.policyRule.then.effect"
Description:    "Parameter 'effect' defaults to 'deny', an enforcement effect.
                 Assignments that don't override the default will enforce 'deny'.
                 Set the default to 'audit'."
```

## Testing

Tests are xUnit + FluentAssertions. They live in `src/Tests/`, split into three folders: `Common/` (shared mocks like `MockTypeMetadata` and `MockLinterRules`), `LinterTests/` (the engine, parsing, metadata, serialization, and CLI tests), and `RuleTests/` (one file per rule). Each rule's tests live in their own `RuleTests/<RuleName>Tests.cs`, in a class named `<RuleName>Tests`.

The basic shape of a test is small:

```csharp
[Fact]
public void RuleTests_RiskyEffectParameterDefaultValue_DefaultIsDeny()
{
    var linter = new PolicyLinter(
        rules: new ILinterRule[] { new RiskyEffectParameterDefaultValue() },
        metadata: TypeMetadata);

    var policyDefinition = @"{ /* raw JSON */ }";

    var results = linter.Lint(policyDefinition);

    results.Should().HaveCount(1);

    var output = new LinterOutput(
        RuleIdentifier: "risky-effect-parameter-default-value",
        Title: "Risky Effect Parameter Default Value",
        Severity: Severity.Warning,
        Category: Category.BestPractices,
        LineNumber: 21, LinePosition: 17,
        Path: "properties.policyRule.then.effect",
        Description: "...");

    results.Should().ContainEquivalentOf(output);
}
```

For a no-finding case: `results.Should().BeEmpty()`. For multiple findings: `HaveCount(N)` then `ContainEquivalentOf(...)` per expected output. Policy JSON is inlined as a verbatim string; the project deliberately doesn't use fixture files.

### `TypeMetadata` vs `MockTypeMetadata`

Each test file declares its metadata instance at the top - the real `TypeMetadata` for rules that need alias resolution, or a `MockTypeMetadata` for rules that don't:

```csharp
private static readonly TypeMetadata TypeMetadata = new TypeMetadata(
    metadataProvider: new OfflineMetadataProvider(),
    aliasResolver: new AliasResolver());
```

That's the two-argument constructor - there is no third `usageProvider` parameter (some older docs claim there is; they're wrong).

Use the real `TypeMetadata` when the rule's logic depends on alias resolution (anything that walks `Reference.ResourcePropertyMetadata` or asks `ITypeMetadata.TryGetAliasPropertyMetadata`). Use `MockTypeMetadata` (a small type that returns no metadata for any alias) when the rule's logic doesn't need alias resolution - it's faster and avoids depending on the offline metadata snapshot. The `FieldAlias*` rule tests use the real one; rules that don't touch alias resolution can use the mock.

### What good test coverage looks like

For every rule, at minimum: one negative (the rule fires, with an exact-equivalence assertion on the `LinterOutput`) and one positive (the rule doesn't fire, `Should().BeEmpty()`). Beyond that, cover the obvious variations: each distinct triggering condition gets its own negative case; missing properties, empty arrays, and case-insensitivity get their own positive cases when the rule's logic touches them. Shipped rules average around 6-10 tests per rule and that's a reasonable target.

### Coverage expectation

New code should land at 90% line coverage or above. CI measures this on the lines a pull request changes (not the whole codebase) and reports the result; falling short surfaces as a warning, not a failed build. The check is informational - use it to find untested branches, not as a number to game.

To reproduce the CI measurement locally:

```
dotnet test src/Tests/PolicyLinter.Tests.csproj --collect:"XPlat Code Coverage" --results-directory ./TestResults
```

That writes `TestResults/<guid>/coverage.cobertura.xml`. For the same new-code view CI produces, run [`diff-cover`](https://github.com/Bachmann1234/diff_cover) against it:

```
diff-cover TestResults/**/coverage.cobertura.xml --compare-branch origin/main
```

For a whole-codebase HTML report instead, point [ReportGenerator](https://github.com/danielpalme/ReportGenerator) at the same cobertura file.

Practical ways to close a gap the report flags: add a test per untested branch (the linter's early-return guards are the usual miss); assert on the cases in *What good test coverage looks like* above; and if a line is genuinely not worth testing, factor it out or accept the warning rather than writing a hollow test for the number.

### Test naming

- Default rule set: `RuleTests_<RuleName>_<Case>`.
- Non-default rule set: `RuleTests_<RuleSet>_<RuleName>_<Case>`.

The class location identifies the rule set for default rules; the rule set is explicit in the method name for non-default rules.

## What it takes to add a rule

The mechanical checklist:

1. **Pick the rule set.** `default` (universal) rules go in `src/PolicyLinter.Core/Rules/CommonRules/`. A custom rule set lives in its own subfolder under `Rules/`. The design doc covers when to pick which.
2. **Add the rule class.** Public sealed, derives from `LinterRule<T>` for your chosen target type, parameterless ctor calls `base(identifier, category, title, descriptionFormat, applyToDerivedTypes: false)`. Add `[RuleSet("...")]` unless it's a `default` rule. Namespace is `Microsoft.Azure.Policy.PolicyLinter.Core.Rules.<Subfolder>`.
3. **Add tests** in `src/Tests/RuleTests/<RuleName>Tests.cs` (a class named `<RuleName>Tests`). At minimum one negative and one positive case.
4. **Add a documentation file** at `docs/Rules/<rule-identifier>.md`. Structure per `linter-rule-design.md`.
5. **Run the CLI** against a test policy to confirm the rule fires (or doesn't).

## Related docs

- `linter-rule-design.md` - what a good rule looks like, independent of the C# code: scope, severity, naming, failure messages, documentation.
- `.github/skills/triage-linter-rule/` - interactive skill that walks a rule idea to a concrete spec before implementation.
