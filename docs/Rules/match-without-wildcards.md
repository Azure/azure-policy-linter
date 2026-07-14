# Match Without Wildcards

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | match-without-wildcards | Warning | — |

## Description

The [`matchInsensitively` or `notMatchInsensitively`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) operator is used with a value that contains none of `#`, `?`, or `.`. Without these characters, these operators behave identically to `equals`/`notEquals`. Use `equals`/`notEquals` to express exact-match intent.

## Suggestions

- Replace `matchInsensitively` with `equals` when the value contains none of `#`, `?`, or `.`.
- Replace `notMatchInsensitively` with `notEquals` when the value contains none of `#`, `?`, or `.`.

### Violation

```json
{
  "field": "name",
  "matchInsensitively": "my-resource-name"
}
```

### Correct

```json
{
  "field": "name",
  "equals": "my-resource-name"
}
```

Or use `matchInsensitively` when the value contains `#`, `?`, or `.`:

```json
{
  "field": "name",
  "matchInsensitively": "my-resource-##"
}
```
