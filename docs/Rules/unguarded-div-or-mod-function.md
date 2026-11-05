# Unguarded Div or Mod Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-div-or-mod-function | Warning | default |

## Description

This rule reports a call to [`div()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#div) or [`mod()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#mod) with an argument that is known only when the policy is evaluated, for example a `field()` value. Evaluation fails when an argument isn't an integer or the divisor is zero. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure both properties always hold integers.
- Check for a missing value and for a zero divisor with `if()` before you call `div()` or `mod()`. A missing property is an empty string, so compare it with `equals(..., '')`. Set the fallback to the value that gives the result you want.

## Examples

### Violation

```json
{
  "value": "[div(field('Microsoft.Test/resourceType/totalSize'), field('Microsoft.Test/resourceType/partitionCount'))]",
  "greater": 100
}
```

### Correct

```json
{
  "value": "[if(or(equals(field('Microsoft.Test/resourceType/totalSize'), ''), equals(field('Microsoft.Test/resourceType/partitionCount'), ''), equals(field('Microsoft.Test/resourceType/partitionCount'), 0)), 0, div(field('Microsoft.Test/resourceType/totalSize'), field('Microsoft.Test/resourceType/partitionCount')))]",
  "greater": 100
}
```
