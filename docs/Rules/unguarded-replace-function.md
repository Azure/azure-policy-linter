# Unguarded Replace Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-replace-function | Warning | default |

## Description

This rule reports a call to [`replace()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#replace) whose string to replace (the second argument) is known only when the policy is evaluated, for example a `field()` value. `replace()` fails when the string to replace is empty or null. A missing property is returned as an empty string, so `replace()` fails when the property is missing. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request where the string to replace is empty is denied, whether or not the policy was meant to deny it.

## Suggestions

- Check the string to replace with `if()` and `empty()` before you call `replace()`. When it's empty, use the original string.

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
  "value": "[if(empty(field('tags[prefix]')), field('name'), replace(field('name'), field('tags[prefix]'), ''))]",
  "match": "app-###"
}
```
