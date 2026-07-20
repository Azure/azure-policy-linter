# Field Alias Unavailable in Every API Version

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | field-alias-unavailable-in-every-api-version | Error | default |

## Description

This rule reports a [field alias](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) that exists in the alias catalog and resolves to a resource type, but whose alias paths match no property in any known API version in the linter's offline metadata. The policy author is therefore using a recognized alias name even though the metadata cannot map it to a resource property. Findings can change as the linter's metadata is updated.

## Suggestions

- Verify that the property is valid and present on the target resource by consulting the resource provider documentation and attempting to create or update a test resource with that property set. If the resource accepts the property, report the alias or metadata mismatch.

## Examples

The same field reference can only be classified by using the linter's offline known API-version metadata, so JSON alone cannot provide a self-contained violation or correct example for this rule.
