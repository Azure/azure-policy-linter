# Invalid base64ToJson Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-base64tojson-function-argument | Error | default |

## Description

This rule reports a call to [`base64ToJson()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#base64tojson) with a value that isn't a valid base64 string, or that decodes to text that isn't valid JSON. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Replace the value with base64-encoded JSON.
- For a parameter, fix its `defaultValue` and `allowedValues`.
