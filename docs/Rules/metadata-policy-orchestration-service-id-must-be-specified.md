# Policy Metadata Must Specify Valid posId GUID


| Category | Identifier |
|----------------|------------------------|
| Misc | metadata-policy-orchestration-service-id-must-be-specified |

## Description

Change Safety policies require a valid Policy Orchestration Service ID (posId) in the policy definition metadata. This identifier is used to track and manage policies within the Policy Orchestration Service for 1P change safety scenarios.

The rule ensures that:
- The policy metadata exists and is a valid JSON object
- The metadata contains a `posId` property
- The `posId` value is a valid, non-empty GUID

### Suggestions

Add a `metadata` section to your policy definition with a valid `posId` GUID:

```json
{
  "properties": {
    "displayName": "My Change Safety Policy",
    "policyType": "Custom",
    "mode": "All",
    "metadata": {
      "posId": "12345678-1234-1234-1234-123456789012"
    },
    "policyRule": {
      // ... policy rule
    }
  }
}
```

### Rule Set

This rule is part of the `ChangeSafety` rule set and is specifically designed for 1P change safety policies. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```
