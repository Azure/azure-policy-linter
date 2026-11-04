# Unguarded addDays Function

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-adddays-function | Warning | default |

## Description

This rule reports a call to [`addDays()`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) whose date is known only when the policy is evaluated, for example a `field()` value. `addDays()` fails when the date isn't a string in the Universal ISO 8601 format (`yyyy-MM-ddTHH:mm:ss.FFFFFFFZ`). A missing property is returned as an empty string, so `addDays()` also fails when the property is missing. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request where the date isn't valid is denied, whether or not the policy was meant to deny it.

## Suggestions

- Make sure the property always holds a date in the Universal ISO 8601 format.
- Check for a missing value with `if()` and `empty()` before you call `addDays()`. Set the fallback date to the value that gives the result you want for a missing property.
- Don't use `coalesce()` as the guard. A missing property is an empty string, not null, so `coalesce()` doesn't replace it.

## Examples

### Violation

```json
{
  "value": "[addDays(field('tags[createdOn]'), 90)]",
  "less": "[utcNow()]"
}
```

### Correct

```json
{
  "value": "[if(empty(field('tags[createdOn]')), utcNow(), addDays(field('tags[createdOn]'), 90))]",
  "less": "[utcNow()]"
}
```
