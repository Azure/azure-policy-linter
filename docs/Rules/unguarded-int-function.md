# Unguarded Int Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-int-function | Warning | default |

## Description

This rule reports a call to [`int()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#int) whose argument is known only when the policy is evaluated, for example a `field()` value. `int()` fails when the value isn't a whole number or a string that holds one. A missing property is returned as an empty string, so `int()` also fails when the property is missing. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request where the value can't be converted is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds a whole number or a string with a whole number.
- Check for a missing value with `if()` and `empty()` before you call `int()`. Set the fallback to the value that gives the result you want for a missing property.
- Don't use `coalesce()` as the guard. A missing property is an empty string, not null, so `coalesce()` doesn't replace it.

## Examples

### Violation

```json
{
  "value": "[int(field('tags[costCenter]'))]",
  "greater": 1000
}
```

### Correct

```json
{
  "value": "[if(empty(field('tags[costCenter]')), 0, int(field('tags[costCenter]')))]",
  "greater": 1000
}
```
