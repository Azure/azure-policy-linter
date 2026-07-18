# Unguarded tryGet Operator Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-tryget-operator-value | Error | default |

## Description

The `tryGet` function returns null when the property it looks up is missing. Policy evaluation fails when an operator value evaluates to null. This rule applies to every policy condition operator when its entire value is a `tryGet` expression: `equals`, `notEquals`, `like`, `notLike`, `in`, `notIn`, `contains`, `notContains`, `containsKey`, `notContainsKey`, `exists`, `match`, `notMatch`, `greater`, `greaterOrEquals`, `less`, `lessOrEquals`, `matchInsensitively`, and `notMatchInsensitively`.

## Suggestions

- Wrap the `tryGet(...)` expression in `coalesce` with a fallback value, so the operand is never null: `[coalesce(tryGet(...), '')]`.
- Choose a fallback that cannot collide with a real value you want to match.

See [Azure Policy definition structure - policy functions](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) for the `tryGet` and `coalesce` functions.

## Examples

### Violation

If the `environment` tag is missing, the operator value evaluates to null and policy evaluation fails:

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
