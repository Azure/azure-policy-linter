# Object Compared as Scalar

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | object-compared-as-scalar | Warning | default |

## Description

An object field is compared to a scalar value using the `equals` or `notEquals` operator. These [equality conditions](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-policy-rule#conditions) do not compare the object's contents. The condition can therefore match every resource or no resources regardless of the object's properties.

## Suggestions

- To check a property within the object, reference that property's alias.
- Use `exists` if you only need to check whether the field is present.
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
