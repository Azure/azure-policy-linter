# Invalid Min or Max Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-min-or-max-function-argument | Error | default |

## Description

This rule reports a call to [`min()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#min) or [`max()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#max) with an empty array, or with a value that isn't a number. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Pass at least one number, and make sure every value is a number.
- For a parameter, fix its `defaultValue` and `allowedValues`. If an empty array is a valid value, check it with `if()` and `empty()` before you call `min()` or `max()`.

## Examples

### Violation

```json
"parameters": {
  "allowedPorts": {
    "type": "Array",
    "defaultValue": []
  }
}
```

```json
{
  "field": "Microsoft.Test/resourceType/port",
  "greater": "[max(parameters('allowedPorts'))]"
}
```
