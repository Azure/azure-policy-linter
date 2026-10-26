# NSG Security Rule Child-Only Enforcement

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-child-only-enforcement | Warning | default |

## Description

The policy is enforcing a rule on the `Microsoft.Network/networkSecurityGroups/securityRules` resource type. Security rules can also be created or changed through the `securityRules` property of the parent network security group (NSG). Azure Policy evaluates those requests only against the parent NSG resource type, so this policy doesn't apply to them, and non-compliant security rules can still be created.

## Suggestions

- Also enforce on `Microsoft.Network/networkSecurityGroups`. Use a [field count expression](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#field-count-expressions) over `Microsoft.Network/networkSecurityGroups/securityRules[*]` to check its security rules.
- You can do this in this policy, with an `anyOf` that has a branch for each resource type.
- Alternatively, create a separate policy targeting `Microsoft.Network/networkSecurityGroups`.

## Examples

### Violation

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Network/networkSecurityGroups/securityRules" },
      { "field": "Microsoft.Network/networkSecurityGroups/securityRules/access", "equals": "Allow" }
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
          { "field": "type", "equals": "Microsoft.Network/networkSecurityGroups/securityRules" },
          { "field": "Microsoft.Network/networkSecurityGroups/securityRules/access", "equals": "Allow" }
        ]
      },
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
      }
    ]
  },
  "then": { "effect": "deny" }
}
```
