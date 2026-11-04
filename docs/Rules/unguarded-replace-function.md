# Unguarded Replace Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-replace-function | Warning | default |

## Description

This rule reports a call to [`replace()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#replace) whose string to replace (the second argument) is known only when the policy is evaluated, for example a `field()` value. `replace()` fails when the string to replace is empty or null. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Check the string to replace with `if()` before you call `replace()`. A missing property is an empty string, so compare it with `equals(..., '')`. When it's empty, use the original string.

## Examples

### Violation

```json
{
  "value": "[replace(field('name'), field('tags[prefix]'), '')]",
  "match": "app-###"
}
```

### Correct

```json
{
  "value": "[if(equals(field('tags[prefix]'), ''), field('name'), replace(field('name'), field('tags[prefix]'), ''))]",
  "match": "app-###"
}
```
