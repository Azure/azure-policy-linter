# Unguarded Range Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-range-function | Warning | default |

## Description

This rule reports a call to [`range()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-array#range) with an argument that is known only when the policy is evaluated, for example a `field()` value. Evaluation fails when an argument isn't an integer, when the count is less than 0 or greater than 10000, or when the last number is larger than the maximum 32-bit integer. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds an integer in the allowed range.
- Check the value with `if()` before you call `range()`. A missing property is an empty string, so compare it with `equals(..., '')`. Return an empty array, or another fallback, when the value is missing or out of range.

## Examples

### Violation

```json
{
  "value": "[range(1, field('Microsoft.Test/resourceType/replicaCount'))]",
  "contains": 3
}
```

### Correct

```json
{
  "value": "[if(or(equals(field('Microsoft.Test/resourceType/replicaCount'), ''), less(field('Microsoft.Test/resourceType/replicaCount'), 0), greater(field('Microsoft.Test/resourceType/replicaCount'), 10000)), createArray(), range(1, field('Microsoft.Test/resourceType/replicaCount')))]",
  "contains": 3
}
```
