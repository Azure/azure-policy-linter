# Invalid Substring Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-substring-function-argument | Error | default |

## Description

This rule reports a call to [`substring()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#substring) whose requested range runs past the end of the string, or whose start index or length is negative. The values are literals, or come from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses those values, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Change the start index and length so the range fits in the string.
- For a parameter, fix its `defaultValue` and `allowedValues`. If a short value is valid, check its length with `if()` and `length()` before you call `substring()`.

## Examples

### Violation

```json
"parameters": {
  "prefix": {
    "type": "String",
    "allowedValues": [ "prod", "dev" ]
  }
}
```

```json
{
  "value": "[substring(parameters('prefix'), 0, 4)]",
  "equals": "prod"
}
```
