# Unguarded ipRangeContains Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-iprangecontains-function | Warning | default |

## Description

This rule reports a call to [`ipRangeContains()`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) with an argument that is known only when the policy is evaluated, for example a `field()` or `current()` value. `ipRangeContains()` fails when an argument isn't a single IP address, a CIDR range, or a range with start and end IP addresses. Many properties that hold IP ranges also accept other values. For example, the address prefix of a network security group rule can be `*`, `Internet`, `VirtualNetwork`, or a service tag such as `Sql.EastUS`. A missing property is returned as an empty string, which also fails. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Find out which values the property accepts besides IP addresses and ranges. Check the resource provider documentation.
- Make sure only IP values reach `ipRangeContains()`. Use `if()` to return a fallback for the other values. There is no template function that checks whether a value is an IP address, so exclude the known non-IP values and the empty string.

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

```json
{
  "count": {
    "field": "Microsoft.Network/networkSecurityGroups/securityRules[*]",
    "where": {
      "value": "[if(contains(createArray('', '*', 'internet', 'virtualnetwork', 'azureloadbalancer'), toLower(current('Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix'))), false(), ipRangeContains('10.0.0.0/8', current('Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix')))]",
      "equals": false
    }
  },
  "greater": 0
}
```

This example doesn't exclude service tags. Add the service tags that your environment uses.
