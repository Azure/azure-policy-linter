# tryGet Use with Null-Coercing Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | tryget-use-with-null-coercing-operator | Informational | default |

## Description

A `value` condition uses a [`tryGet`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) expression with an operator that coerces null to an empty string. The affected operators are `equals`, `notEquals`, `in`, `notIn`, `like`, `notLike`, `contains`, `notContains`, `match`, `notMatch`, `matchInsensitively`, and `notMatchInsensitively`. When `tryGet` returns null, the operator evaluates the condition as if the compared value were an empty string.

## Suggestions

- Account for the empty-string comparison whenever `tryGet` can return null.
- Use `coalesce` with an explicit fallback only when the null-result behavior should differ from an empty-string comparison.

## Examples

### Implicit empty-string comparison

```json
{
  "value": "[tryGet(field('properties'), 'tier')]",
  "equals": "premium"
}
```

### Explicit fallback

```json
{
  "value": "[coalesce(tryGet(field('properties'), 'tier'), 'none')]",
  "equals": "premium"
}
```
