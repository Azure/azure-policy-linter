# VM OS Type Field Alias

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | vm-os-type-field-alias | Warning | default |

## Description

The policy references the `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` field alias. The resource provider sets this property after the VM is created. As a result, `audit`, `deny`, `append`, and `modify` policies that depend on it don't act when VMs are created. Compliance results for existing VMs are correct.

## Suggestions

- Identify the operating system from properties that are in the create request:
  - For marketplace images, check `Microsoft.Compute/imagePublisher`, `Microsoft.Compute/imageOffer`, and `Microsoft.Compute/imageSku`.
  - For managed and gallery images, check `Microsoft.Compute/imageId` against the images you use.
  - Check whether `Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration` or `Microsoft.Compute/virtualMachines/osProfile.linuxConfiguration` exists.
- For built-in policies that use this pattern, see the [Guest Configuration policies](https://github.com/Azure/azure-policy/tree/master/built-in-policies/policyDefinitions/Guest%20Configuration).

See [Optional or auto-generated resource property that bypasses policy evaluation](https://github.com/Azure/azure-policy/blob/master/README.md#optional-or-auto-generated-resource-property-that-bypasses-policy-evaluation).

## Examples

### Violation

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
      { "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType", "equals": "Linux" }
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
      { "field": "type", "equals": "Microsoft.Compute/virtualMachines" },
      {
        "anyOf": [
          { "field": "Microsoft.Compute/imagePublisher", "in": [ "Canonical", "RedHat", "SUSE" ] },
          { "field": "Microsoft.Compute/virtualMachines/osProfile.linuxConfiguration", "exists": true }
        ]
      }
    ]
  },
  "then": { "effect": "deny" }
}
```
