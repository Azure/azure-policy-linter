# Unguarded tryGet in Compared Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-tryget-in-compared-value | Warning | — |

## Description

A `value` condition's value is a [`tryGet`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) expression that is not wrapped in `coalesce`, compared with `equals` or `notEquals`. `tryGet` returns null when a path segment is missing. On the compared-value (left) side this does not throw, but the null is compared directly, which can silently produce unexpected results. The condition may quietly produce a different outcome than the author intended.

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
