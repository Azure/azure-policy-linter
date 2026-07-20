# VM OS Type Alias Missing from Request Payload

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | vm-os-type-alias-missing-from-request-payload | Warning | default |

## Description

The `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) is absent from virtual machine create and update request payloads because the resource provider generates the property. As documented in the Azure Policy [known issues](https://github.com/Azure/azure-policy/blob/master/README.md#optional-or-auto-generated-resource-property-that-bypasses-policy-evaluation), conditions using this alias do not produce request-time `audit`, `deny`, or `append` behavior. Existing-resource compliance scans remain correct because the property is present when the resource is retrieved.

## Suggestions

- For request-time behavior, use a property that is present in the create and update payloads and accurately represents the requirement across the supported VM creation flows.
- When post-provisioning evaluation is appropriate, use the alias in an `existenceCondition` with an `auditIfNotExists` or `deployIfNotExists` effect.

## Examples

### Violation

The `deny` effect does not occur for this condition during VM create or update:

```json
"if": {
  "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
  "equals": "Windows"
},
"then": {
  "effect": "deny"
}
```

### Correct - request-time alternative

Use a caller-supplied property only when the deployment contract guarantees its presence and meaning:

```json
"if": {
  "field": "tags['declaredOsType']",
  "equals": "Windows"
},
"then": {
  "effect": "deny"
}
```

### Correct - post-provisioning alternative

Evaluate the OS type after the VM is available:

```json
"existenceCondition": {
  "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
  "equals": "Windows"
}
```
