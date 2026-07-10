# Broad Type Matching Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | broad-type-matching-operator | Warning | — |

## Description

The `type` field is compared with a broad matching operator (`like`, `match`, `matchInsensitively`, or `contains`) instead of `equals` or `in`. These operators match by pattern or substring, so they can match resource types the author did not intend to target. For example, `"contains": "virtualMachines"` matches both `Microsoft.Compute/virtualMachines` and `Microsoft.Compute/virtualMachines/extensions`, and `"like": "Microsoft.Compute/*"` matches every type under the provider.

## Suggestions

- Replace the broad operator with `equals` to target a single resource type.
- Use `in` with an explicit list to target several resource types.

### Violation

```json
{
  "field": "type",
  "contains": "virtualMachines"
}
```

### Correct

```json
{
  "field": "type",
  "in": [
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Compute/disks"
  ]
}
```
