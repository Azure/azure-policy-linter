# VM OS Type Alias May Be Missing from Request Payload

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | vm-os-type-alias-may-be-missing-from-request-payload | Warning | default |

## Description

Some virtual machine create and update flows omit the `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) because the resource provider can generate the property. Other flows, including [user-image and specialized-VHD creates](https://learn.microsoft.com/azure/templates/microsoft.compute/virtualmachines), can supply `osType` in the request. As documented in the Azure Policy [known issues](https://github.com/Azure/azure-policy/blob/master/README.md#optional-or-auto-generated-resource-property-that-bypasses-policy-evaluation), an omitted value prevents request-time `audit`, `deny`, or `append` behavior for conditions using this alias. Existing-resource compliance scans remain correct because the property is present when the resource is retrieved.

## Suggestions

- For request-time OS detection, keep the `osType` condition for requests that supply it and add sibling `anyOf` branches for known image publishers, offers, and SKUs.
- Add an `imageId` allowlist when known custom or Compute Gallery images must be included.
- Maintain the image conditions as supported images change. Images that are not represented by `osType`, image metadata, or the `imageId` allowlist cannot be classified reliably at request time.
- When post-provisioning evaluation is appropriate, use the alias in an `existenceCondition` with an `auditIfNotExists` or `deployIfNotExists` effect.

## Examples

### Violation

When the request omits `osType`, the `deny` effect does not occur for this condition during VM create or update:

```json
"if": {
  "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
  "equals": "Windows"
},
"then": {
  "effect": "deny"
}
```

### Request-time mitigation

Combine `osType` with image metadata for the images the policy must recognize:

```json
"if": {
  "allOf": [
    {
      "field": "type",
      "equals": "Microsoft.Compute/virtualMachines"
    },
    {
      "anyOf": [
        {
          "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
          "like": "Windows*"
        },
        {
          "allOf": [
            {
              "field": "Microsoft.Compute/imagePublisher",
              "equals": "MicrosoftWindowsServer"
            },
            {
              "field": "Microsoft.Compute/imageOffer",
              "equals": "WindowsServer"
            },
            {
              "field": "Microsoft.Compute/imageSku",
              "like": "2022-*"
            }
          ]
        },
        {
          "field": "Microsoft.Compute/imageId",
          "in": "[parameters('additionalWindowsImageIds')]"
        }
      ]
    }
  ]
},
"then": {
  "effect": "deny"
}
```

Built-in policies using this pattern include:

- [Windows virtual machines should have Azure Monitor Agent installed](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Monitoring/AzureMonitor_Agent_Windows_VM_Audit.json)
- [Configure Windows Virtual Machines to be associated with a Data Collection Rule for ChangeTracking and Inventory](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/ChangeTrackingAndInventory/DCRA_Windows_VM_DINE.json)
- [[Preview]: Configure supported Linux virtual machines to automatically enable Secure Boot](https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Security%20Center/ASC_EnableLinuxSB_DINE.json)

### Post-provisioning alternative

Evaluate the OS type after the VM is available:

```json
"existenceCondition": {
  "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
  "equals": "Windows"
}
```
