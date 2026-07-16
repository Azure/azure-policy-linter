# Unguarded tryGet in Compared Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-tryget-in-compared-value | Warning | - |

## Description

A `value` condition uses an unguarded [`tryGet`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) expression with `equals` or `notEquals`. When the selected property is absent, `tryGet` returns null and the comparison can produce a different result than a comparison against an explicit fallback.

## Suggestions

- Wrap the `tryGet` in `coalesce` with a meaningful fallback so the comparison always has a defined operand.

### Violation

```json
{
  "value": "[tryGet(field('properties'), 'tier')]",
  "equals": "premium"
}
```

### Correct

```json
{
  "value": "[coalesce(tryGet(field('properties'), 'tier'), 'none')]",
  "equals": "premium"
}
```
