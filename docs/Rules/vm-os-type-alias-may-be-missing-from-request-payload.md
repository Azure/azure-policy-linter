# VM OS Type Alias May Be Missing from Request Payload

| Category | Identifier | Severity | Rule Set |
|----------|------------|----------|----------|
| ResourceFields | vm-os-type-alias-may-be-missing-from-request-payload | Warning | default |

## Description

This rule reports a policy that decides a virtual machine's OS type from the `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` [field alias](https://learn.microsoft.com/azure/governance/policy/concepts/definition-structure-alias) while using a request-time effect. Azure populates that property after the virtual machine is created, so it is not in the create or update request and the condition never matches at request time. The policy silently does nothing on the requests it was written to catch. This is a known [Azure Policy issue](https://github.com/Azure/azure-policy/blob/master/README.md#optional-or-auto-generated-resource-property-that-bypasses-policy-evaluation).

Compliance scans of existing virtual machines are unaffected, because the property is present once the resource exists.

## Suggestions

- To catch the OS type at request time, match on the image instead: add sibling `anyOf` branches for the image publishers, offers, and SKUs the policy needs to recognize, plus an `imageId` allowlist for specific custom or Compute Gallery images. Images outside that set still cannot be classified.
- To keep using the alias, evaluate after provisioning instead: put it in an `existenceCondition` with an `auditIfNotExists` or `deployIfNotExists` effect.

## Examples

### Violation

```json
{
  "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType",
  "equals": "Windows"
}
```

### Correct

Match the image, which is present in the request:

```json
{
  "anyOf": [
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
