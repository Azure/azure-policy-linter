# Invalid Div or Mod Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-div-or-mod-function-argument | Error | default |

## Description

This rule reports a call to [`div()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#div) or [`mod()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#mod) with a divisor of zero. The divisor is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Change the divisor to a value other than zero.
- For a parameter, remove zero from its `defaultValue` and `allowedValues`.

## Examples

### Violation

```json
"parameters": {
  "partitions": {
    "type": "Integer",
    "defaultValue": 0
  }
}
```

```json
{
  "value": "[div(field('Microsoft.Test/resourceType/totalSize'), parameters('partitions'))]",
  "greater": 100
}
```
