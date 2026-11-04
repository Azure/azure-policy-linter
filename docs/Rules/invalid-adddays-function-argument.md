# Invalid addDays Function Argument

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | invalid-adddays-function-argument | Error | default |

## Description

This rule reports a call to [`addDays()`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions) with a date that isn't in the Universal ISO 8601 format (`yyyy-MM-ddTHH:mm:ss.FFFFFFFZ`), or a number of days that isn't an integer. The value is a literal, or comes from a parameter's `defaultValue` or `allowedValues`. Evaluation fails whenever the policy uses that value, and [a failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Write the date in the Universal ISO 8601 format, for example `2026-01-31T00:00:00Z`.
- Write the number of days as an integer. For a parameter, declare it with the `Integer` type.
- For a parameter, fix its `defaultValue` and `allowedValues`.

## Examples

### Violation

```json
{
  "field": "Microsoft.Test/resourceType/expiresOn",
  "less": "[addDays('01/31/2026', 30)]"
}
```

### Correct

```json
{
  "field": "Microsoft.Test/resourceType/expiresOn",
  "less": "[addDays('2026-01-31T00:00:00Z', 30)]"
}
```
