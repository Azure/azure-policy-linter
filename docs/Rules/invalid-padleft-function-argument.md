# Invalid padLeft Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-padleft-function-argument | Error | default |

## Description

This rule reports a call to [`padLeft()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#padleft) with a total length that isn't from 1 to 16, or a padding character that isn't exactly one character. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Use a total length from 1 to 16, and a single padding character.
- For a parameter, fix its `defaultValue` and `allowedValues`.

## Examples

### Violation

```json
{
  "value": "[padLeft(field('Microsoft.Test/resourceType/sequence'), 20, '0')]",
  "equals": "00000000000000000001"
}
```
