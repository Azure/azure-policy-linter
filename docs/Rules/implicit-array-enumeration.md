# Implicit Array Enumeration

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | implicit-array-enumeration | Informational | default |

## Description

This rule reports a condition whose `field` is an array alias containing `[*]`. Azure Policy applies the condition to every member the alias selects and requires all of them to match, which is the only thing this form can express. See [referencing array members](https://learn.microsoft.com/azure/governance/policy/how-to/author-policies-for-arrays#referencing-array-members).

## Suggestions

Use a field `count` expression when the policy needs to state how many members must match. A `count` expression can require at least one match, or an exact number, which implicit enumeration cannot express.

## Examples

### Violation

```json
{
  "field": "Microsoft.Test/testResource/items[*].name",
  "equals": "approved"
}
```

### Correct

Requires at least one member to match. Note that this is not the same condition as the violation, which holds only when every member matches:

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
