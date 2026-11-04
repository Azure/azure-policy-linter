# Invalid Int Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-int-function-argument | Error | default |

## Description

This rule reports a call to [`int()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#int) with a value that can't be converted to an integer. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Change the value to a whole number, or a string that holds a whole number.
- For a parameter, fix its `defaultValue` and `allowedValues`. If the parameter holds a number, declare it with the `Integer` type.

## Examples

### Violation

```json
"parameters": {
  "maxCount": {
    "type": "String",
    "defaultValue": "ten"
  }
}
```

```json
{
  "value": "[int(parameters('maxCount'))]",
  "less": 5
}
```
