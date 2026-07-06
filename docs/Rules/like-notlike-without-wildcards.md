# like/notLike Without Wildcards

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | like-notlike-without-wildcards | Warning | Common |

## Description

The `like` or `notLike` operator is used with a value that contains no wildcards (`*` or `?`). Without wildcards, these operators behave identically to `equals`/`notEquals`, which suggests the author intended to use wildcard matching but the value contains no wildcards. Use `equals`/`notEquals` to clearly express exact-match intent.

## Suggestions

- Replace `like` with `equals` when no wildcards are used.
- Replace `notLike` with `notEquals` when no wildcards are used.

### Violation

```json
{
  "field": "type",
  "like": "Microsoft.Compute/virtualMachines"
}
```

### Correct

```json
{
  "field": "type",
  "equals": "Microsoft.Compute/virtualMachines"
}
```
