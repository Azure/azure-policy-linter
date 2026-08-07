# Field Alias Unavailable in Every API Version

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | field-alias-unavailable-in-every-api-version | Error | default |

## Description

This rule reports a usage of a [field alias](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) that maps to an unknown property on the target resource. This finding is based on the linter's embedded resource type metadata. The condition that uses the alias will most likely not evaluate as expected. For a recently added alias, it can also mean that the linter's metadata is out of date.

## Suggestions

- Verify that the property is valid and present on the target resource by consulting the resource provider documentation and attempting to create or update a test resource with that property set.
