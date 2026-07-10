# Broad Type Matching Operator

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | broad-type-matching-operator | Warning | — |

## Description

The `type` field is compared with a broad matching operator (`like`, `match`, `matchInsensitively`, or `contains`) instead of `equals` or `in`. These operators match by pattern or substring, so they can match resource types the author did not intend to target. For example, `"contains": "virtualMachines"` matches both `Microsoft.Compute/virtualMachines` and `Microsoft.ClassicCompute/virtualMachines`, and `"like": "Microsoft.Compute/*"` matches every type under the provider.

This is distinct from [match-without-wildcards](match-without-wildcards.md) and [like-notlike-without-wildcards](like-notlike-without-wildcards.md), which flag a pattern operator used with no pattern. This rule flags a broad operator applied to the `type` field at all, regardless of whether it carries a pattern.

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

## Related rules

- [policy-rule-references-multiple-resource-types](policy-rule-references-multiple-resource-types.md) - flags an `if` that targets more than one resource type.
