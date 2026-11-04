# tryGet with Multiple Keys

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | tryget-with-multiple-keys | Warning | default |

## Description

This rule reports a call to [`tryGet()`](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-object#tryget) with more than one key, for example `tryGet(field('properties'), 'settings', 'tier')`. Only the first key is looked up safely. If the first key is missing, `tryGet()` returns null. If the first key exists, the next keys are looked up as normal property accessors, and evaluation fails when one of them is missing. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures).

## Suggestions

- Use one `tryGet()` for each key that can be missing: `tryGet(tryGet(obj, 'a'), 'b')`.

## Examples

### Violation

```json
{
  "value": "[coalesce(tryGet(field('Microsoft.Test/resourceType/properties'), 'settings', 'tier'), '')]",
  "equals": "premium"
}
```

### Correct

```json
{
  "value": "[coalesce(tryGet(tryGet(field('Microsoft.Test/resourceType/properties'), 'settings'), 'tier'), '')]",
  "equals": "premium"
}
```
