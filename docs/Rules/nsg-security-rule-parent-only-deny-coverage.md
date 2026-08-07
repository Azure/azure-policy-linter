# NSG Security Rule Parent-Only Deny Coverage

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-parent-only-deny-coverage | Warning | default |

## Description

This rule reports a deny policy that targets the security rules carried on the [parent network security group](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups) but not [security rules deployed as their own resource](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules). A security rule can be created either way, so the policy blocks one route and leaves the other open.

Note that the rule infers what the policy targets from the security rule aliases it uses, which may not match the resource types the policy actually applies to.

## Suggestions

- Check whether an existing assigned policy already covers security rules deployed as their own resource.
- Author a separate policy targeting security rules deployed as their own resource, or add a branch for them here. The conditions have to be rewritten to the child aliases: `Microsoft.Network/networkSecurityGroups/securityRules[*].access` becomes `Microsoft.Network/networkSecurityGroups/securityRules/access`.

## Examples

### Violation

```json
{
  "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
  "equals": "Allow"
}
```

### Correct

```json
{
  "anyOf": [
    {
      "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
      "equals": "Allow"
    },
    {
      "field": "Microsoft.Network/networkSecurityGroups/securityRules/access",
      "equals": "Allow"
    }
  ]
}
```
