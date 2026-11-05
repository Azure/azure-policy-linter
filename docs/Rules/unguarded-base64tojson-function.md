# Unguarded base64ToJson Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-base64tojson-function | Warning | default |

## Description

This rule reports a call to [`base64ToJson()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#base64tojson) whose argument is known only when the policy is evaluated, for example a `field()` value. `base64ToJson()` fails when the value isn't a valid base64 string, or when the decoded text isn't valid JSON. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds base64-encoded JSON.
- Check for a missing value with `if()` before you call `base64ToJson()`. A missing property is an empty string, so compare it with `equals(..., '')`. Set the fallback to the value that gives the result you want for a missing property.

## Examples

### Violation

```json
{
  "value": "[base64ToJson(field('Microsoft.Test/resourceType/settings'))]",
  "containsKey": "mode"
}
```

### Correct

```json
{
  "value": "[if(equals(field('Microsoft.Test/resourceType/settings'), ''), createObject(), base64ToJson(field('Microsoft.Test/resourceType/settings')))]",
  "containsKey": "mode"
}
```
