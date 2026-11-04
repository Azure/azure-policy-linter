# Unguarded Div or Mod Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-div-or-mod-function | Warning | default |

## Description

This rule reports a call to [`div()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#div) or [`mod()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#mod) whose divisor is known only when the policy is evaluated, for example a `field()` value. Evaluation fails when the divisor is zero or isn't an integer. A missing property is returned as an empty string, which isn't an integer. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request with such a divisor is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds an integer.
- Check for zero and for a missing value with `if()` before you divide. Set the fallback to the value that gives the result you want.

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
  "value": "[if(or(empty(field('Microsoft.Test/resourceType/partitionCount')), equals(field('Microsoft.Test/resourceType/partitionCount'), 0)), 0, div(field('Microsoft.Test/resourceType/totalSize'), field('Microsoft.Test/resourceType/partitionCount')))]",
  "greater": 100
}
```
