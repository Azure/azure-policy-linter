# Object Compared as Scalar

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | object-compared-as-scalar | Warning | default |

## Description

A condition uses [`equals` or `notEquals`](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) to compare an object field with a single value. These operators do not compare the contents of the object. As a result, the condition can match all resources or no resources, regardless of the properties in the object.

## Suggestions

- To check a property in the object, reference the alias of that property.
- To check only that the field is present, use `exists`.
- To compare the complete object, use the [`equals()` template function](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-functions-comparison#equals) in a `value` condition.

## Examples

### Violation

This compares the complete Key Vault properties object with a key name.

```json
{
  "field": "Microsoft.Automation/automationAccounts/encryption.keyVaultProperties",
  "equals": "my-key"
}
```
