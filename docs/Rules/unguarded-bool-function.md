# Unguarded Bool Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-bool-function | Warning | default |

## Description

This rule reports a call to [`bool()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-logical#bool) whose argument is known only when the policy is evaluated, for example a `field()` value. `bool()` fails when the value can't be converted to a boolean, for example a string other than `'true'` or `'false'`. A missing property is returned as an empty string, so `bool()` also fails when the property is missing. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request where the value can't be converted is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds a boolean or the string `'true'` or `'false'`.
- Check for a missing value with `if()` and `empty()` before you call `bool()`. Set the fallback to the value that gives the result you want for a missing property.
- Don't use `coalesce()` as the guard. A missing property is an empty string, not null, so `coalesce()` doesn't replace it.

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
  "value": "[if(empty(field('tags[backupEnabled]')), false(), bool(field('tags[backupEnabled]')))]",
  "equals": true
}
```
