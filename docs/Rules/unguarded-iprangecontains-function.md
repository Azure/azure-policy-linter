# Unguarded ipRangeContains Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-iprangecontains-function | Warning | default |

## Description

This rule reports a call to [`ipRangeContains()`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) with an argument that is known only when the policy is evaluated, for example a `field()` or `current()` value. `ipRangeContains()` fails when an argument isn't a single IP address, a CIDR range, or a range with start and end IP addresses. Many properties that hold IP ranges also accept other values, and a missing property returns an empty string. For example, the address prefix of a network security group rule can be `*`, `Internet`, `VirtualNetwork`, a service tag such as `Sql.EastUS`, or empty when the rule uses the plural prefixes property, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Find out which values the property accepts besides IP addresses and ranges. Check the resource provider documentation.
- Make sure only IP values reach `ipRangeContains()`. Use `if()` to return a fallback for the other values, and set the fallback to the result you want for each of them. There is no template function that checks whether a value is an IP address, so list the known non-IP values.

## Examples

### Violation

```json
{
  "count": {
    "field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
    "where": {
      "value": "[ipRangeContains('10.0.0.0/8', current('Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix'))]",
      "equals": false
    }
  },
  "greater": 0
}
```

### Correct

An empty prefix returns `true`, so the rule isn't counted. `*`, `Internet`, `VirtualNetwork`, and `AzureLoadBalancer` return `false`, so the rule is counted as outside `10.0.0.0/8`:

```json
{
  "count": {
    "field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
    "where": {
      "value": "[if(equals(current('Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix'), ''), true(), if(contains(createArray('*', 'internet', 'virtualnetwork', 'azureloadbalancer'), toLower(current('Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix'))), false(), ipRangeContains('10.0.0.0/8', current('Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix'))))]",
      "equals": false
    }
  },
  "greater": 0
}
```

This example doesn't handle service tags. Add the service tags that your environment uses.
