# Policy Metadata Must Specify Non-Compliance Message

| Category | Identifier |
|----------------|------------------------------------------|
| Misc | metadata-noncompliance-message-required |

## Description

Change Safety policies require a non-compliance message in the policy definition metadata. The non-compliance message is presented to users when the policy blocks their request and must include the aka.ms/changeSafety link to guide users on why the request failed and how to address it.

The rule ensures that:
- The policy metadata exists and is a valid JSON object
- The metadata contains a `nonComplianceMessage` property
- The `nonComplianceMessage` value is a string
- The message ends with `. For more information about the enforcement in-place, go to aka.ms/changeSafety`

### Suggestions

Add a `nonComplianceMessage` property to your policy metadata with the required suffix:

```json
{
  "properties": {
    "displayName": "My Change Safety Policy",
    "policyType": "Custom",
    "mode": "All",
    "metadata": {
      "posId": "12345678-1234-1234-1234-123456789012",
      "nonComplianceMessage": "This resource violates change safety requirements. For more information about the enforcement in-place, go to aka.ms/changeSafety"
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
