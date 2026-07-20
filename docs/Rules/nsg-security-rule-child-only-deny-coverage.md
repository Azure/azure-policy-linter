# NSG Security Rule Child-Only Deny Coverage

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-child-only-deny-coverage | Warning | default |

## Description

This rule checks policies whose effect is literal `deny` or a direct String parameter that is unconstrained or allows `deny`. When such a policy selects the independently deployable [`Microsoft.Network/networkSecurityGroups/securityRules` child resource](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules), it does not cover requests that submit security rules through the [`securityRules` collection on the parent network security group](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups). Complex effect expressions and other enforcement effects are outside the rule's scope.

## Suggestions

- Add equivalent coverage for the parent `Microsoft.Network/networkSecurityGroups` request path in this policy or another policy.
- Adapt the parent coverage to the parent `securityRules[*]` aliases. Adding the parent type to the same condition is not sufficient when the remaining conditions use child-resource aliases.
- Check existing assigned policies before adding another definition; another policy may already provide the parent coverage.

## Examples

### Violation

This condition selects only the child request path:

```json
{
  "field": "type",
  "equals": "Microsoft.Network/networkSecurityGroups/securityRules"
}
```

### Correct

Provide conceptually equivalent parent coverage in this policy or another policy. A separate parent condition can begin with:

```json
{
  "field": "type",
  "equals": "Microsoft.Network/networkSecurityGroups"
}
```

Conditions that inspect security-rule properties must also be adapted to the parent `securityRules[*]` aliases.
