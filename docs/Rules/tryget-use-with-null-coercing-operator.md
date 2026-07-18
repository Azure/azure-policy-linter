# tryGet Use with Null-Coercing Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | tryget-use-with-null-coercing-operator | Informational | default |

## Description

A `value` condition uses a [`tryGet`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) expression with an operator that coerces null to an empty string. When the selected property is absent, `tryGet` returns null and the operator evaluates the condition as if the compared value were an empty string.

## Suggestions

- Account for the empty-string comparison when the selected property is absent.
- Use `coalesce` with an explicit fallback only when the missing-property behavior should differ from an empty-string comparison.

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
