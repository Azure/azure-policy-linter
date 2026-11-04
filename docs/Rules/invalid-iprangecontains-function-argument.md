# Invalid ipRangeContains Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-iprangecontains-function-argument | Error | default |

## Description

This rule reports a call to [`ipRangeContains()`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) with a value that isn't a single IP address, a CIDR range, or a range with start and end IP addresses. Examples are `*`, `Internet`, and service tags such as `Sql.EastUS`. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Replace the value with an IP address, a CIDR range (`10.0.0.0/24`), or a start and end range (`10.0.0.1-10.0.0.9`).
- For a parameter, fix its `defaultValue` and `allowedValues`.

## Examples

### Violation

```json
"parameters": {
  "allowedRange": {
    "type": "String",
    "allowedValues": [ "10.0.0.0/8", "AzureCloud" ]
  }
}
```

```json
{
  "value": "[ipRangeContains(parameters('allowedRange'), field('Microsoft.Test/resourceType/ipAddress'))]",
  "equals": false
}
```
