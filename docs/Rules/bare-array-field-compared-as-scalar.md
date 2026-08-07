# Bare Array Field Compared as Scalar

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | bare-array-field-compared-as-scalar | Warning | default |

## Description

A bare array field alias resolves to the whole array, while an alias with `[*]` references its members. This rule reports literal scalar operands used with equality, `like`, `match`, or ordering operators against bare aliases that metadata consistently identifies as arrays. See [Referencing array fields](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#referencing-array-fields).

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
