# Implicit Array Enumeration

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | implicit-array-enumeration | Informational | default |

## Description

A condition that uses an array alias containing `[*]` as its `field` implicitly applies the condition to every value selected from the array. This behaves like an implicit `allOf`, and an empty collection satisfies the condition. See [referencing array members](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#referencing-array-members) for the supported Azure Policy behavior.

## Suggestions

Use a field `count` expression when the policy needs to state how many members must match or handle an empty array explicitly.

## Examples

### Violation

```json
{
  "field": "Microsoft.Test/testResource/items[*].name",
  "equals": "approved"
}
```

### Correct

The following example explicitly requires at least one matching member, so an empty array does not satisfy the condition:

```json
{
  "count": {
    "field": "Microsoft.Test/testResource/items[*]",
    "where": {
      "field": "Microsoft.Test/testResource/items[*].name",
      "equals": "approved"
    }
  },
  "greater": 0
}
```
