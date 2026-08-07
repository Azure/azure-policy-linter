# VM OS Type Alias May Be Missing from Request Payload

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | vm-os-type-alias-may-be-missing-from-request-payload | Warning | default |

## Description

Some virtual machine create and update flows omit the `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` [field alias](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) because the resource provider generates the property. As documented in the Azure Policy [known issues](https://github.com/Azure/azure-policy/blob/master/README.md#optional-or-auto-generated-resource-property-that-bypasses-policy-evaluation), an omitted value prevents request-time `audit`, `deny`, or `append` behavior for conditions that use this alias. Existing-resource compliance scans remain correct because the property is present when the resource is retrieved.

Image metadata does not cover every image, so a policy that combines these conditions can still miss virtual machines whose OS type cannot be determined at request time.

## Suggestions

- For request-time OS detection, keep the `osType` condition and add sibling `anyOf` branches for the known image publishers, offers, and SKUs the policy must recognize.
- Add an `imageId` allowlist when specific custom or Compute Gallery images must be included.
- When post-provisioning evaluation is appropriate, use the alias in an `existenceCondition` with an `auditIfNotExists` or `deployIfNotExists` effect.

## Examples

### Violation

When the request omits `osType`, the `deny` effect does not occur for this condition during VM create or update:

```json
{
  "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
  "equals": "Windows"
}
```

### Correct

Combine `osType` with image metadata for the images the policy must recognize:

```json
{
  "anyOf": [
    {
      "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
      "like": "Windows*"
    },
    {
      "field": "Microsoft.Compute/imagePublisher",
      "equals": "MicrosoftWindowsServer"
    },
    {
      "field": "Microsoft.Compute/imageId",
      "in": "[parameters('additionalWindowsImageIds')]"
    }
  ]
}
```
