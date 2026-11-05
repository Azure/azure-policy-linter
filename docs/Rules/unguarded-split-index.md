# Unguarded Split Index

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| TemplateFunctions | unguarded-split-index | Warning | default |

> **Note:** This rule can't tell whether your policy already checks the number of segments before it selects the element, for example with `if()`. It reports every such selection. If your policy has a check, make sure it handles values with too few segments and missing values.

## Description

This rule reports an expression that selects an element from the result of [`split()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-string#split), for example `split(field('id'), '/')[4]`, when the split value is known only when the policy is evaluated. If the value has fewer segments than the index requires, the index is out of bounds and evaluation fails. A missing property is an empty string, which splits into a single empty element. [A failed expression makes the policy deny the request](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures), so every request whose value has too few segments is denied, whether or not the policy was meant to deny it.

## Suggestions

- To get the first or last segment, use `first()` or `last()`.
- For another segment, use `first(skip(split(...), index))`. It returns null instead of failing when the value has too few segments, so wrap it in `coalesce()` with the value you want for that case.
- If you keep the index, check the number of segments with `if()` and `length()` before the selection.

## Examples

### Violation

```json
{
  "value": "[split(field('Microsoft.Test/resourceType/subnet.id'), '/')[2]]",
  "notEquals": "[subscription().subscriptionId]"
}
```

### Correct

The fallback is the current subscription ID, so a resource without a subnet doesn't match the condition:

```json
{
  "value": "[coalesce(first(skip(split(field('Microsoft.Test/resourceType/subnet.id'), '/'), 2)), subscription().subscriptionId)]",
  "notEquals": "[subscription().subscriptionId]"
}
```
