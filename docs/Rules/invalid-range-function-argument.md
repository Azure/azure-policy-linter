# Invalid Range Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-range-function-argument | Error | default |

## Description

This rule reports a call to [`range()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-array#range) with a count that is less than 0 or greater than 10000, or with a range whose last number is larger than the maximum 32-bit integer. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Use a count from 0 to 10000, and a start index for which the range stays inside the 32-bit integer limit.
- For a parameter, fix its `defaultValue` and `allowedValues`.

## Examples

### Violation

```json
{
  "value": "[range(0, 20000)]",
  "contains": "[field('Microsoft.Test/resourceType/port')]"
}
```
