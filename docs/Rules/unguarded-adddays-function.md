# Unguarded addDays Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-adddays-function | Warning | default |

## Description

This rule reports a call to [`addDays()`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) with an argument that is known only when the policy is evaluated, for example a `field()` value. `addDays()` fails when the date isn't a string in the Universal ISO 8601 format (`yyyy-MM-ddTHH:mm:ss.FFFFFFFZ`), or when the number of days isn't an integer. This includes the empty string that a missing property returns. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request with such a value is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the date property always holds a date in the Universal ISO 8601 format, and the number of days is an integer. Tag values are strings, so convert a number of days read from a tag with `int()`.
- Check for a missing value with `if()` before you call `addDays()`. A missing property is an empty string, so compare it with `equals(..., '')`. `coalesce()` doesn't replace an empty string. Set the fallback to the value that gives the result you want for a missing property.

## Examples

### Violation

```json
{
  "value": "[addDays(field('tags[createdOn]'), 90)]",
  "less": "[utcNow()]"
}
```

### Correct

A missing `createdOn` tag returns a date far in the future, so the condition is false:

```json
{
  "value": "[if(equals(field('tags[createdOn]'), ''), '9999-12-31T00:00:00Z', addDays(field('tags[createdOn]'), 90))]",
  "less": "[utcNow()]"
}
```
