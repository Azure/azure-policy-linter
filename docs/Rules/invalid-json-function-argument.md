# Invalid Json Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-json-function-argument | Error | default |

## Description

This rule reports a call to [`json()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-object#json) with a value that isn't valid JSON. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Fix the JSON text.
- For a parameter, fix its `defaultValue` and `allowedValues`. If the parameter holds an object or an array, declare it with the `Object` or `Array` type, and remove the `json()` call.

## Examples

### Violation

```json
{
  "value": "[json('{tier: premium')]",
  "containsKey": "tier"
}
```
