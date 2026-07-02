# match/matchInsensitively Without Wildcards

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | match-without-wildcards | Warning | — |

## Description

The `matchInsensitively` or `notMatchInsensitively` operator is used with a value that contains no wildcards (`#` for a digit, `?` for a letter, or `.` for any character). Without wildcards, these operators behave identically to `equals`/`notEquals` (both are case-insensitive), which suggests the author intended to use pattern matching but the value contains no patterns. Use `equals`/`notEquals` to clearly express exact-match intent.

## Suggestions

- Replace `matchInsensitively` with `equals` when no placeholders are used.
- Replace `notMatchInsensitively` with `notEquals` when no placeholders are used.

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

Or use placeholders when pattern matching is intended:

```json
{
  "field": "name",
  "matchInsensitively": "my-resource-##"
}
```
