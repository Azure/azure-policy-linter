# Policy Display Name and Description Must Be Specified


| Category | Identifier |
|----------------|-------------------------------|
| Misc | display-name-and-description-must-be-specified |

## Description

Change Safety policies require specific display name and description formatting to ensure consistency and proper identification.

The rule ensures that:
- The policy definition has a non-empty display name
- The display name starts with the `"Change Safety - "` prefix
- The display name does not exceed 128 characters
- The policy definition has a non-empty description

### Suggestions

Ensure your policy definition includes a properly formatted display name and description:

```json
{
  "properties": {
    "displayName": "Change Safety - Example policy name",
    "description": "This policy enforces change safety requirements for...",
    "policyType": "Custom",
    "mode": "All",
    "metadata": {
      // ... metadata
    },
    "policyRule": {
      // ... policy rule
    }
  }
}
```

### Rule Set

This rule is part of the `ChangeSafety` rule set and is specifically designed for 1P change safety policies. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```
