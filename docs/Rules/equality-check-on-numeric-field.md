# Equality Check on Numeric Field

| Category | Identifier | Severity | Rule Set |
|----------------|---------------------------------|---------------|----------|
| ResourceFields | equality-check-on-numeric-field | Informational | default |

## Description

A `field` condition uses [`equals` or `notEquals`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) directly against a JSON value on a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) whose resource property is numeric (an integer or a number).

These operators coerce both operands to string and compare them case-insensitively. Numerically equal values whose string forms differ can therefore compare as unequal. For example, a property value of `5.0` stringifies to `"5.0"` and does not equal `"5"`; a leading zero (`"05"`) has the same problem.

## Suggestions

- Test the policy and confirm the implicit type conversion yields the behavior you intend.
- For type-accurate equality, use `"value": "[equals(field('property'), 5)]", "equals": true`.

### Violation

```json
{
  "field": "Microsoft.KeyVault/vaults/softDeleteRetentionInDays",
  "equals": "5"
}
```

### Correct

```json
{
  "value": "[equals(field('Microsoft.KeyVault/vaults/softDeleteRetentionInDays'), 5)]",
  "equals": true
}
```
