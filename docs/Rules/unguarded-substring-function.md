# Unguarded Substring Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-substring-function | Warning | default |

## Description

This rule reports a call to `substring()` with a value that is known only when the policy is evaluated, for example a `field()` value as the input, start or length. `substring()` fails when the requested range runs past the end of its input, and a [failed expression makes the policy deny the request](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Any request whose value makes the range run past the end is blocked, whether or not the policy was meant to block it.

**Note:** This rule can't tell whether your policy already checks the value before it calls `substring()`, for example with `if()`. It reports every such call.

## Suggestions

- Replace `substring(value, start, length)` with `take(skip(value, start), length)`. `take()` and `skip()` return a shorter result instead of failing.
- If you keep `substring()`, check the length of the value with `if()` before the call.

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
