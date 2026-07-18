# Unguarded tryGet Operator Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-tryget-operator-value | Error | default |

## Description

The `tryGet` function returns null when the first property it looks up is missing. Additional property arguments use ordinary dereferences and can fail before the condition operator runs. Policy evaluation also fails when the final operator value evaluates to null. This rule applies to every policy condition operator when its entire value is a `tryGet` expression: `equals`, `notEquals`, `like`, `notLike`, `in`, `notIn`, `contains`, `notContains`, `containsKey`, `notContainsKey`, `exists`, `match`, `notMatch`, `greater`, `greaterOrEquals`, `less`, `lessOrEquals`, `matchInsensitively`, and `notMatchInsensitively`.

## Suggestions

- Make each nested property lookup safe; only the first property passed to `tryGet` is safely dereferenced.
- Wrap the final `tryGet(...)` expression in `coalesce` with a fallback compatible with the operator's expected type.
- Choose a fallback that cannot collide with a real value you want to match. For a string-valued equality comparison, an empty-string fallback can be appropriate: `[coalesce(tryGet(...), '')]`.

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

For this string-valued equality comparison, `coalesce` supplies a string fallback so the operand is never null:

```json
{
  "field": "name",
  "equals": "[coalesce(tryGet(field('tags'), 'environment'), '')]"
}
```
