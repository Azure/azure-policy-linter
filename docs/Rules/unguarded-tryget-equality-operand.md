# Unguarded tryGet Equality Operand

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-tryget-equality-operand | Error | — |

## Description

The `tryGet` function returns null when the property it looks up is missing. The `equals` and `notEquals` operators reject a null on their value side: at evaluation time the engine throws because null is not a supported value type. When an `equals` or `notEquals` condition's value is a `tryGet(...)` expression that is not wrapped in `coalesce`, the policy fails at evaluation time for every resource where that property is missing.

## Suggestions

- Wrap the `tryGet(...)` expression in `coalesce` with a fallback value, so the operand is never null: `[coalesce(tryGet(...), '')]`.
- Choose a fallback that cannot collide with a real value you want to match.

See [Azure Policy definition structure - policy functions](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) for the `tryGet` and `coalesce` functions.

## Examples

### Violation

If `properties.displayName` is missing, the `equals` evaluation throws:

```json
{
  "field": "name",
  "equals": "[tryGet(field('properties'), 'displayName')]"
}
```

### Correct

`coalesce` supplies a fallback so the operand is never null:

```json
{
  "field": "name",
  "equals": "[coalesce(tryGet(field('properties'), 'displayName'), '')]"
}
```
