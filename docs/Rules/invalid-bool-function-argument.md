# Invalid Bool Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-bool-function-argument | Error | default |

## Description

This rule reports a call to [`bool()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-logical#bool) with a value that can't be converted to a boolean. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Change the value to a boolean, or the string `'true'` or `'false'`.
- For a parameter, fix its `defaultValue` and `allowedValues`. If the parameter holds a boolean, declare it with the `Boolean` type.

## Examples

### Violation

```json
"parameters": {
  "requireBackup": {
    "type": "String",
    "allowedValues": [ "yes", "no" ]
  }
}
```

```json
{
  "value": "[bool(parameters('requireBackup'))]",
  "equals": true
}
```
