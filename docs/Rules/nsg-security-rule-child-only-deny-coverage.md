# NSG Security Rule Child-Only Deny Coverage

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | nsg-security-rule-child-only-deny-coverage | Warning | default |

## Description

A deny-capable policy that selects the independently deployable [`Microsoft.Network/networkSecurityGroups/securityRules` child resource](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups/securityrules) does not cover requests that submit security rules through the [`securityRules` collection on the parent network security group](https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups). Equivalent conditions are needed for both request paths when both must be denied.

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
