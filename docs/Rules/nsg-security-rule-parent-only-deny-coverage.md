# NSG Security Rule Parent-Only Deny Coverage

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-parent-only-deny-coverage | Warning | default |

## Description

This rule reports a deny-capable policy whose conditions reference security rules through the parent [network security group](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups) but never reference the [security rule child resource](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules). Security rules can be submitted either way, so a policy that only inspects the parent collection does not see security rules deployed as child resources.

Note that the rule infers the targeted resource types from the aliases the condition uses, which may not reflect the resource types the policy actually applies to.

## Suggestions

- Check whether another assigned policy already covers requests that deploy security rules as child resources.
- To cover both paths in this policy, add a branch for the child resource and adapt the conditions to the child aliases: `Microsoft.Network/networkSecurityGroups/securityRules[*].access` becomes `Microsoft.Network/networkSecurityGroups/securityRules/access`. Adding the child resource type without adapting the conditions is not sufficient.

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
