# Count Less Than Array Length

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | count-less-than-array-length | Informational | default |

## Description

The policy checks that a [field count expression](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#field-count-expressions) is less than the length of the same array. This means "not every array member matches the `where` condition". The same check is easier to read when it counts the array members that don't match and checks that the count is greater than 0. Both forms give the same result, including for empty arrays.

## Suggestions

Change the operator to `greater` with the value `0`, and change the `where` condition so that it matches the array members that the policy should flag.

## Examples

### Violation

```json
{
  "count": {
    "field": "Microsoft.Test/resourceType/objectArray[*]",
    "where": { "field": "Microsoft.Test/resourceType/objectArray[*].state", "equals": "Allowed" }
  },
  "less": "[length(field('Microsoft.Test/resourceType/objectArray[*]'))]"
}
```

### Correct

```json
{
  "count": {
    "field": "Microsoft.Test/resourceType/objectArray[*]",
    "where": { "field": "Microsoft.Test/resourceType/objectArray[*].state", "notEquals": "Allowed" }
  },
  "greater": 0
}
```
