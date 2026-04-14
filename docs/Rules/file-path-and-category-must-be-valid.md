# Policy File Path and Category Must Be Valid


| Category | Identifier |
|----------------|------------------------|
| Misc | file-path-and-category-must-be-valid |

## Description

Change Safety policies require proper file organization and metadata consistency.

The rule ensures that:
- The policy definition file name does not exceed 100 characters
- The policy metadata contains a `category` property
- The `category` value is not null or empty
- The `category` value matches the parent folder name (case-insensitive)

### Suggestions

Ensure your policy file is properly named and organized:

**File Organization:**
- Place your policy definition file in a folder that represents its category
- Keep the file name under 100 characters
- Ensure the metadata category matches the parent folder name

**Example File Structure:**
```
Policies/
  ChangeSafety/
    Compute/
      deploy-vm-backup.json
    Storage/
      storage-account-encryption.json
    Network/
      nsg-rule-validation.json
```

**Policy Metadata:**
```json
{
  "properties": {
    "displayName": "Change safety - Example policy",
    "policyType": "Custom",
    "mode": "All",
    "metadata": {
      "category": "Compute",
      "posId": "12345678-1234-1234-1234-123456789012"
    },
    "policyRule": {
      // ... policy rule
    }
  }
}
```

In this example, if the policy file is located at `policies/Compute/deploy-vm-backup.json`, the metadata category must be set to `"Compute"` to match the parent folder name.

### Rule Set

This rule is part of the `ChangeSafety` rule set and is specifically designed for 1P change safety policies. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```
