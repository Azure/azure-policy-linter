# Field Alias Unavailable in Every API Version

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | field-alias-unavailable-in-every-api-version | Error | default |

## Description

This rule reports a resolved [field alias](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) when the linter's offline metadata contains no property path for it in any known API version of the resource type. The policy therefore has no known API-version property to evaluate through that alias. Findings can change as the linter's metadata is updated.

## Suggestions

- Verify that the alias is spelled correctly and applies to the intended resource type.
- Replace it with an available field alias for the property you need.

## Examples

The same field reference can only be classified by using the linter's offline known API-version metadata, so JSON alone cannot provide a self-contained violation or correct example for this rule.
