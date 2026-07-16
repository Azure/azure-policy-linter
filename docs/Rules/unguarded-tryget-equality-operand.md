# Unguarded TryGet Equality Operand

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-tryget-equality-operand | Error | — |

## Description

The `tryGet` function returns null when the property it looks up is missing. The `equals` and `notEquals` operators reject a null on their value side. When an `equals` or `notEquals` condition's value expression has `tryGet` as its outermost function, the policy fails at evaluation time for every resource where that property is missing.

## Suggestions

- Wrap the `tryGet(...)` expression in `coalesce` with a fallback value, so the operand is never null: `[coalesce(tryGet(...), '')]`.
- Choose a fallback that cannot collide with a real value you want to match.

See [Azure Policy definition structure - policy functions](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) for the `tryGet` and `coalesce` functions.

## Examples

### Violation

If the `environment` tag is missing, the `equals` evaluation throws:

```json
{
  "field": "name",
  "equals": "[tryGet(field('tags'), 'environment')]"
}
```

### Correct

`coalesce` supplies a fallback so the operand is never null:

```json
{
  "field": "name",
  "equals": "[coalesce(tryGet(field('tags'), 'environment'), '')]"
}
```
