# Unguarded Split Index

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-split-index | Warning | default |

## Description

This rule reports an expression that selects an element after the first from the result of [`split()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#split), for example `split(field('id'), '/')[4]`, when the split value is known only when the policy is evaluated. If the value has fewer segments than the index requires, the index is out of bounds and evaluation fails. A missing property is returned as an empty string, which splits into a single empty element. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request whose value has too few segments is denied, whether or not the policy was meant to deny it.

## Suggestions

- To get the first or last segment, use `first()` or `last()`. They don't fail on short values.
- Otherwise, check the number of segments with `if()` and `length()` before you select the element.

## Examples

### Violation

```json
{
  "value": "[split(field('Microsoft.Test/resourceType/subnet.id'), '/')[2]]",
  "notEquals": "[subscription().subscriptionId]"
}
```

### Correct

```json
{
  "value": "[if(greater(length(split(field('Microsoft.Test/resourceType/subnet.id'), '/')), 2), split(field('Microsoft.Test/resourceType/subnet.id'), '/')[2], subscription().subscriptionId)]",
  "notEquals": "[subscription().subscriptionId]"
}
```

The fallback is the current subscription ID, so a resource without a subnet doesn't match the condition.
