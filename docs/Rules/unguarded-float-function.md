# Unguarded Float Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-float-function | Warning | default |

## Description

This rule reports a call to [`float()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#float) whose argument is known only when the policy is evaluated, for example a `field()` value. `float()` fails when the value isn't a number or a numeric string. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds a number or a numeric string.
- Check for a missing value with `if()` before you call `float()`. A missing property is an empty string, so compare it with `equals(..., '')`. `coalesce()` doesn't replace an empty string. Set the fallback to the value that gives the result you want for a missing property.

## Examples

### Violation

```json
{
  "value": "[float(field('Microsoft.Test/resourceType/size'))]",
  "greater": 2.0
}
```

### Correct

```json
{
  "value": "[if(equals(field('Microsoft.Test/resourceType/size'), ''), float(0), float(field('Microsoft.Test/resourceType/size')))]",
  "greater": 2.0
}
```
