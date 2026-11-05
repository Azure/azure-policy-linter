# Unguarded Int Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-int-function | Warning | default |

## Description

This rule reports a call to [`int()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-numeric#int) whose argument is known only when the policy is evaluated, for example a `field()` value. `int()` fails when the value isn't an integer or a string that holds an integer. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds an integer or a string that holds an integer.
- Check for a missing value with `if()` before you call `int()`. A missing property is an empty string, so compare it with `equals(..., '')`. `coalesce()` doesn't replace an empty string. Set the fallback to the value that gives the result you want for a missing property.

The rule stays silent when the call is inside the second or third argument of an `if()` whose condition uses the same value, for example `field('tags[costCenter]')` in both. It doesn't check what the condition does with the value.

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
  "value": "[if(equals(field('tags[costCenter]'), ''), 0, int(field('tags[costCenter]')))]",
  "greater": 1000
}
```
