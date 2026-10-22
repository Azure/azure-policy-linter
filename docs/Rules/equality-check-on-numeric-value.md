# Equality Check on Numeric Value

| Category | Identifier | Severity | Rule Set |
|----------------|---------------------------------|---------------|----------|
| BestPractices | equality-check-on-numeric-value | Informational | default |

## Description

A condition uses [`equals` or `notEquals`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) with a numeric field, a `Float` parameter, or a floating-point literal in `value`.

These operators coerce scalar operands to strings and compare them case-insensitively. Numerically equal values whose string forms differ can therefore compare as unequal.

## Suggestions

- For numeric equality, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition with numeric operands.

## Examples

### Violation

```json
{
  "value": 5.0,
  "equals": "5.0"
}
```

### Correct

```json
{
  "value": "[equals(float('5.0'), float('5.0'))]",
  "equals": true
}
```
