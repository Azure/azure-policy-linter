# Equality Check on Numeric Field

| Category | Identifier | Severity | Rule Set |
|----------------|---------------------------------|---------------|----------|
| ResourceFields | equality-check-on-numeric-field | Informational | default |

## Description

A `field` condition uses [`equals` or `notEquals`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) with a literal value against a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) whose resource property is numeric (an integer or a number).

These operators coerce both operands to string and compare them case-insensitively. The comparison matches only when the literal is identical to the string form the property serializes to, so a literal whose string form differs will not match. For example, a property value of `5.0` stringifies to `"5.0"` and does not equal the literal `"5"`; a leading zero (`"05"`) has the same problem.

## Suggestions

- Confirm the literal matches the exact string form the property serializes to, accounting for decimal formatting and leading zeros.
- Use the numeric comparison operators (`greater`, `greaterOrEquals`, `less`, `lessOrEquals`) when comparing magnitudes rather than exact values.

### Violation

```json
{
  "field": "Microsoft.Test/resourceType/floatProperty",
  "equals": "5"
}
```

### Correct

```json
{
  "field": "Microsoft.Test/resourceType/floatProperty",
  "equals": "5.0"
}
```
