# Bare Array Field Compared as Scalar

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | bare-array-field-compared-as-scalar | Warning | default |

## Description

A bare array field alias resolves to the whole array, while an alias with `[*]` references its members. This rule reports scalar comparisons against bare aliases that metadata consistently identifies as arrays. See [Referencing array fields](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#referencing-array-fields).

## Suggestions

- Add `[*]` to compare individual array members, or use field count when the condition depends on how many members match.
- Use `exists` when the condition only checks whether the array property is present.

## Examples

### Violation

```json
{
  "field": "Microsoft.Network/networkSecurityGroups/securityRules",
  "equals": "Deny"
}
```

### Correct - compare members

```json
{
  "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
  "equals": "Deny"
}
```

### Correct - count matching members

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
