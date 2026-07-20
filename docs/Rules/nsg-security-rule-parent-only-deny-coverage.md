# NSG Security Rule Parent-Only Deny Coverage

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-parent-only-deny-coverage | Warning | default |

## Description

A deny-capable policy selects the parent `Microsoft.Network/networkSecurityGroups` resource type and references its `securityRules[*]` collection, but does not select independently deployed `Microsoft.Network/networkSecurityGroups/securityRules` child resources. Azure Resource Manager supports security rules both in the [parent network security group resource](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups) and as [child security-rule resources](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules), so the request paths require equivalent policy coverage.

## Suggestions

- Check whether another assigned policy already provides equivalent coverage for independently deployed child security-rule requests.
- If child coverage is needed in this policy, add conditions for `Microsoft.Network/networkSecurityGroups/securityRules` and adapt parent collection aliases such as `Microsoft.Network/networkSecurityGroups/securityRules[*].access` to child-resource aliases such as `Microsoft.Network/networkSecurityGroups/securityRules/access`. Adding the child resource type without adapting the conditions is not sufficient.

## Examples

### Violation

```json
{
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Network/networkSecurityGroups"
        },
        {
          "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
          "equals": "Allow"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

### Correct

```json
{
  "policyRule": {
    "if": {
      "anyOf": [
        {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Network/networkSecurityGroups"
            },
            {
              "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
              "equals": "Allow"
            }
          ]
        },
        {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Network/networkSecurityGroups/securityRules"
            },
            {
              "field": "Microsoft.Network/networkSecurityGroups/securityRules/access",
              "equals": "Allow"
            }
          ]
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```
