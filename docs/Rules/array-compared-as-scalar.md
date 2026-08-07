# Array Compared as Scalar

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | array-compared-as-scalar | Warning | default |

## Description

This rule reports a condition that compares an entire array field to a single value, performing an invalid comparison that will always be evaluated to `false`.

## Suggestions

- Adjust the policy to use [field count expression](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#field-count) (if the intent is to apply condition to the array members) or remove the condition entirely.

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
