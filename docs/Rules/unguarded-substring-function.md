# Unguarded Substring Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-substring-function | Error (Warning in an `if()` branch) | default |

## Description

This rule reports a call to `substring` on a value that is known only when the policy is evaluated, for example a `field()` value. `substring` fails when the requested range runs past the end of its input, and a [failed expression makes the policy deny the request](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Any request whose value is shorter than the requested range is blocked, whether or not the policy was meant to block it. When the call is in the second or third argument of an `if()`, the finding is a Warning, because the `if()` condition might check the length.

## Suggestions

- Replace `substring(value, start, length)` with `take(skip(value, start), length)`. `take()` and `skip()` return a shorter result instead of failing.
- If you keep `substring` inside an `if()`, make sure the condition checks the length of the value.

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
  "value": "[take(field('name'), 3)]",
  "equals": "abc"
}
```
