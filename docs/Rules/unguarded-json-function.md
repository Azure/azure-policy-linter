# Unguarded Json Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-json-function | Warning | default |

## Description

This rule reports a call to [`json()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-object#json) whose argument is known only when the policy is evaluated, for example a `field()` value. `json()` fails when the value isn't a string that holds valid JSON. A missing property is returned as an empty string, which isn't valid JSON, so `json()` also fails when the property is missing. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request where the value isn't valid JSON is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds valid JSON.
- Check for a missing value with `if()` and `empty()` before you call `json()`. Set the fallback to the value that gives the result you want for a missing property.

## Examples

### Violation

```json
{
  "value": "[json(field('tags[config]'))]",
  "containsKey": "tier"
}
```

### Correct

```json
{
  "value": "[if(empty(field('tags[config]')), createObject(), json(field('tags[config]')))]",
  "containsKey": "tier"
}
```
