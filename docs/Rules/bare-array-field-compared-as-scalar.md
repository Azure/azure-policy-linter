# Bare Array Field Compared as Scalar

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | bare-array-field-compared-as-scalar | Warning | default |

## Description

This rule reports a condition that compares an array field to a single value. A field alias without `[*]` refers to the array object as a whole rather than to its members, so the comparison can never match a member and the condition does not do what it appears to do. See [Referencing array fields](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#referencing-array-fields).

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
