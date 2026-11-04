# Invalid Replace Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-replace-function-argument | Error | default |

## Description

This rule reports a call to [`replace()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#replace) whose string to replace (the second argument) is empty. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Change the string to replace to a value that isn't empty.
- For a parameter, remove the empty string from its `defaultValue` and `allowedValues`. If an empty string is a valid value, check it with `if()` and `empty()` before you call `replace()`.

## Examples

### Violation

```json
"parameters": {
  "namePrefix": {
    "type": "String",
    "defaultValue": ""
  }
}
```

```json
{
  "value": "[replace(field('name'), parameters('namePrefix'), '')]",
  "match": "app-###"
}
```
