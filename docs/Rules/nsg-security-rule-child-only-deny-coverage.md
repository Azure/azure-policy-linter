# NSG Security Rule Child-Only Deny Coverage

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-child-only-deny-coverage | Warning | default |

## Description

This rule reports an `All` mode deny-capable policy whose conditions reference the [security rule child resource](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules) but never reference security rules through the parent [network security group](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups). Security rules can be submitted either way, so a policy that only inspects the child resource does not see security rules submitted with the parent network security group. `Indexed` mode and an absent mode do not evaluate the child resource type at all, so they are outside the rule's scope.

Note that the rule infers the targeted resource types from the aliases the condition uses, which may not reflect the resource types the policy actually applies to.

## Suggestions

- Check whether another assigned policy already covers requests that submit security rules with the parent network security group.
- To cover both paths in this policy, add a branch for the parent resource and adapt the conditions to the parent aliases: `Microsoft.Network/networkSecurityGroups/securityRules/access` becomes `Microsoft.Network/networkSecurityGroups/securityRules[*].access`. Adding the parent resource type without adapting the conditions is not sufficient.

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
