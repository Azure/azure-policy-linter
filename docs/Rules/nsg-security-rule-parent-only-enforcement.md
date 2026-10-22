# NSG Security Rule Parent-Only Enforcement

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-parent-only-enforcement | Warning | default |

## Description

The policy can enforce (`deny`, `modify`, or `append`) on the security rules of a network security group (NSG) through `Microsoft.Network/networkSecurityGroups/securityRules[*]` fields, but not on the `Microsoft.Network/networkSecurityGroups/securityRules` resource type. A single security rule can also be created or changed directly as a `Microsoft.Network/networkSecurityGroups/securityRules` resource. Azure Policy evaluates those requests only against the security rule resource type, so this policy doesn't apply to them, and non-compliant security rules can still be created.

## Suggestions

- Also enforce on `Microsoft.Network/networkSecurityGroups/securityRules`, using its `Microsoft.Network/networkSecurityGroups/securityRules/*` fields.
- You can do this in this policy, with an `anyOf` that has a branch for each resource type, or in a separate policy.

## Examples

### Violation

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Network/networkSecurityGroups" },
      {
        "count": {
          "field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
          "where": { "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access", "equals": "Allow" }
        },
        "greater": 0
      }
    ]
  },
  "then": { "effect": "deny" }
}
```

### Correct

```json
{
  "if": {
    "anyOf": [
      {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Network/networkSecurityGroups" },
          {
            "count": {
              "field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
              "where": { "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access", "equals": "Allow" }
            },
            "greater": 0
          }
        ]
      },
      {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Network/networkSecurityGroups/securityRules" },
          { "field": "Microsoft.Network/networkSecurityGroups/securityRules/access", "equals": "Allow" }
        ]
      }
    ]
  },
  "then": { "effect": "deny" }
}
```
