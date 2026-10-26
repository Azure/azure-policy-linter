# Auto-Generated Field Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | auto-generated-field-alias | Warning | default |

## Description

The policy enforces a condition on a [field alias](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) whose property is often missing from create and update requests. When a request doesn't include the property, the resource provider sets its value after Azure Policy evaluates the request. A `deny`, `append`, or `modify` policy that depends on this field doesn't act on those requests, so non-compliant resources can still be created.

Compliance results for existing resources are correct, because the property is present when Azure Policy reads the resource.

The rule checks a known list of fields, taken from the [Azure Policy known issues](https://github.com/Azure/azure-policy/blob/master/README.md#optional-or-auto-generated-resource-property-that-bypasses-policy-evaluation), for example `Microsoft.Storage/storageAccounts/networkAcls.defaultAction` and `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType`.

## Suggestions

- Decide what the policy should do when the property is missing from the request, and add an `exists` condition for that case.
- To act on the value the resource provider sets, use an `auditIfNotExists` or `deployIfNotExists` policy and check the property in its `existenceCondition`.
- For `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType`, identify the operating system from the image properties, such as `Microsoft.Compute/imagePublisher`, `Microsoft.Compute/imageOffer`, and `Microsoft.Compute/imageSku`.

## Examples

### Violation

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
      { "field": "Microsoft.Storage/storageAccounts/networkAcls.defaultAction", "notEquals": "Deny" }
    ]
  },
  "then": { "effect": "deny" }
}
```

### Correct

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
      {
        "anyOf": [
          { "field": "Microsoft.Storage/storageAccounts/networkAcls.defaultAction", "exists": false },
          { "field": "Microsoft.Storage/storageAccounts/networkAcls.defaultAction", "notEquals": "Deny" }
        ]
      }
    ]
  },
  "then": { "effect": "deny" }
}
```
