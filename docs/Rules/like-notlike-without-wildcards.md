# like/notLike Without Wildcards

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | like-notlike-without-wildcards | Warning | — |

## Description

The [`like` or `notLike`](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) operator is used with a value that contains no wildcard (`*`). Without a wildcard, these operators behave identically to `equals`/`notEquals`. Use `equals`/`notEquals` to express exact-match intent.

## Suggestions

- Replace `like` with `equals` when no wildcard is used.
- Replace `notLike` with `notEquals` when no wildcard is used.

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
