# Bare Array Field Compared as Scalar

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | bare-array-field-compared-as-scalar | Warning | default |

## Description

A bare array field alias resolves to the whole array, while an alias with `[*]` references its members. Comparing the whole array against a scalar value never inspects the members, so the condition does not evaluate the resource the way the alias suggests. See [Referencing array fields](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#referencing-array-fields).

## Suggestions

- Use a [field count expression](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#field-count) to evaluate the array members.

## Examples

### Violation

```json
{
  "field": "Microsoft.Network/networkSecurityGroups/securityRules",
  "equals": "Deny"
}
```

### Correct

```json
{
  "count": {
    "field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
    "where": {
      "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
      "equals": "Deny"
    }
  },
  "greater": 0
}
```
