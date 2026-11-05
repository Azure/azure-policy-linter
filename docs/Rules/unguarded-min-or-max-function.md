# Unguarded Min or Max Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-min-or-max-function | Warning | default |

## Description

This rule reports a call to [`min()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#min) or [`max()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#max) with an argument that is known only when the policy is evaluated, for example a `field()` value. Evaluation fails when the array is empty or a value isn't a number. A missing array alias returns an empty array, and a missing property returns an empty string, so both fail. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds a number, or an array of numbers.
- Check for an empty array with `if()` and `empty()`, or for a missing single value with `equals(..., '')`, before you call `min()` or `max()`. Set the fallback to the value that gives the result you want.

## Examples

### Violation

```json
{
  "value": "[max(field('Microsoft.Test/resourceType/rules[*].priority'))]",
  "greater": 4000
}
```

### Correct

```json
{
  "value": "[if(empty(field('Microsoft.Test/resourceType/rules[*].priority')), 0, max(field('Microsoft.Test/resourceType/rules[*].priority')))]",
  "greater": 4000
}
```
