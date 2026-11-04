# Invalid Float Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-float-function-argument | Error | default |

## Description

This rule reports a call to [`float()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#float) with a value that can't be converted to a number. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Change the value to a number, or a string that holds a number.
- For a parameter, fix its `defaultValue` and `allowedValues`. If the parameter holds a number, declare it with the `Float` or `Integer` type.

## Examples

### Violation

```json
{
  "value": "[float(field('Microsoft.Test/resourceType/size'))]",
  "greater": "[float('two')]"
}
```
