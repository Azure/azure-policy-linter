# NSG Security Rule Child-Only Deny Coverage

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-child-only-deny-coverage | Warning | default |

## Description

This rule reports a deny policy that targets [security rules deployed as their own resource](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules) but not the security rules carried on the [parent network security group](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups). A security rule can be created either way, so the policy blocks one route and leaves the other open.

Only `All` mode policies evaluate the security rule resource, so the rule does not apply to policies in `Indexed` mode.

Note that the rule infers what the policy targets from the security rule aliases it uses, which may not match the resource types the policy actually applies to.

## Suggestions

- Check whether an existing assigned policy already covers security rules submitted with the parent network security group.
- Author a separate policy targeting security rules submitted with the parent network security group, or add a branch for them here. The conditions have to be rewritten to the parent aliases: `Microsoft.Network/networkSecurityGroups/securityRules/access` becomes `Microsoft.Network/networkSecurityGroups/securityRules[*].access`.

## Examples

### Violation

```json
{
  "field": "Microsoft.Network/networkSecurityGroups/securityRules/access",
  "equals": "Allow"
}
```

### Correct

```json
{
  "anyOf": [
    {
      "field": "Microsoft.Network/networkSecurityGroups/securityRules/access",
      "equals": "Allow"
    },
    {
      "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
      "equals": "Allow"
    }
  ]
}
```
