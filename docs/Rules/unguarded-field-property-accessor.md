# Unguarded Field Property Accessor

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| BestPractices | unguarded-field-property-accessor | Warning | default |

## Description

This rule reports a property accessor or an array index on the result of `field()` or `current()`, for example `field('tags')['env']` or `current('Microsoft.Test/resourceType/items[*]').name`. The accessor fails when the property is missing or the index is out of bounds. It also fails when the field itself is missing, because a missing field is returned as an empty string, which has no properties. [A failed evaluation is an implicit deny](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#avoiding-template-failures). Every request where the property is missing is denied, whether or not the policy was meant to deny it.

## Suggestions

- Put the full path in the field reference instead of using an accessor. For example, use `field('tags[env]')` or the alias of the nested property. A missing property is then returned as an empty string and evaluation doesn't fail.
- If no field reference covers the path, use `tryGet()`, which returns null for a missing property. Replace null with `coalesce()`: `[coalesce(tryGet(field('...'), 'name'), '')]`.

See [Azure Policy definition structure - fields](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#fields) for the tag and alias field references.

## Examples

### Violation

```json
{
  "value": "[field('tags')['env']]",
  "equals": "prod"
}
```

### Correct

```json
{
  "field": "tags['env']",
  "equals": "prod"
}
```
