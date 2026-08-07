# Unguarded Substring on Resource Value

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-substring-on-resource-value | Error | default |

## Description

This rule reports an unsafe use of the `substring` function. `substring` fails when the requested range runs past the end of its input, and a [failed expression makes the policy deny the request](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Because the input here is a resource value, any resource with a shorter value is blocked, whether or not the policy was meant to block it.

## Suggestions

Check the length before taking the substring, using `if()` and `length()`.

## Examples

### Violation

```json
{
  "value": "[substring(field('name'), 0, 3)]",
  "equals": "abc"
}
```

### Correct

```json
{
  "value": "[if(greaterOrEquals(length(field('name')), 3), substring(field('name'), 0, 3), field('name'))]",
  "equals": "abc"
}
```
