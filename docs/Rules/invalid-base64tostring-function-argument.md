# Invalid base64ToString Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-base64tostring-function-argument | Error | default |

## Description

This rule reports a call to [`base64ToString()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#base64tostring) with a value that isn't a valid base64 string. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Replace the value with a valid base64 string.
- For a parameter, fix its `defaultValue` and `allowedValues`.
