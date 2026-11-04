# Unguarded base64ToString Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-base64tostring-function | Warning | default |

## Description

This rule reports a call to [`base64ToString()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#base64tostring) whose argument is known only when the policy is evaluated, for example a `field()` value. `base64ToString()` fails when the value is null or isn't a valid base64 string. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request where the value isn't valid base64 is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds a base64 string. There is no template function that checks whether a value is valid base64.
- If the value comes from a function that can return null, such as `tryGet()`, replace null with `coalesce()`: `[base64ToString(coalesce(tryGet(...), ''))]`.

## Examples

### Violation

```json
{
  "value": "[base64ToString(field('Microsoft.Test/resourceType/customData'))]",
  "contains": "password"
}
```
