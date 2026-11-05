# Unguarded Bool Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-bool-function | Warning | default |

## Description

This rule reports a call to [`bool()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-logical#bool) whose argument is known only when the policy is evaluated, for example a `field()` value. `bool()` fails when the value can't be converted to a boolean, for example a string other than `'true'` or `'false'`. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds a boolean or the string `'true'` or `'false'`.
- Check for a missing value with `if()` before you call `bool()`. A missing property is an empty string, so compare it with `equals(..., '')`. `coalesce()` doesn't replace an empty string. Set the fallback to the value that gives the result you want for a missing property.

## Examples

### Violation

```json
{
  "value": "[bool(field('tags[backupEnabled]'))]",
  "equals": true
}
```

### Correct

```json
{
  "value": "[if(equals(field('tags[backupEnabled]'), ''), false(), bool(field('tags[backupEnabled]')))]",
  "equals": true
}
```
