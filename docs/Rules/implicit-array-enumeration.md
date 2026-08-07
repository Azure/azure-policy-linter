# Implicit Array Enumeration

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | implicit-array-enumeration | Informational | default |

## Description

This rule reports a condition whose `field` is an array alias containing `[*]`. Azure Policy applies the condition to every value selected from the array, which behaves like an implicit `allOf`, and an empty collection satisfies it. See [referencing array members](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#referencing-array-members) for the supported Azure Policy behavior.

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

The following example preserves the violation's behavior: no selected member may differ from `approved`, and an empty array satisfies the condition:

```json
{
  "count": {
    "field": "Microsoft.Test/testResource/items[*]",
    "where": {
      "field": "Microsoft.Test/testResource/items[*].name",
      "notEquals": "approved"
    }
  },
  "equals": 0
}
```
