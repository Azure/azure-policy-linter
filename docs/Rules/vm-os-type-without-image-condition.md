# VM OS Type Without Image Condition

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | vm-os-type-without-image-condition | Warning | default |

## Description

The policy identifies the virtual machine operating system only with the `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` field alias. Requests that create a VM from a marketplace, managed, or gallery image usually don't include this property; the resource provider sets it after the VM is created. As a result, `audit`, `deny`, `append`, and `modify` policies don't act when these VMs are created. Compliance results for existing VMs are correct.

## Suggestions

- Identify the operating system from properties that are in the create request, and keep `osType` as a fallback:
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
          { "field": "Microsoft.Compute/virtualMachines/osProfile.linuxConfiguration", "exists": true },
          { "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType", "equals": "Linux" }
        ]
      }
    ]
  },
  "then": { "effect": "deny" }
}
```
