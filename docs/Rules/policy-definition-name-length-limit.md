# Policy Definition Name Length Limit


| Category | Identifier |
|----------------|------------------------|
| Misc | policy-definition-name-length-limit |

## Description

Change Safety policies have a strict limit on policy definition names. The name property must not exceed 24 characters,
and should follow Azure naming conventions (alphanumeric and hyphens only, no spaces)
This limit ensures compatibility with policy assignment naming and various Azure Policy infrastructure requirements.

The rule ensures that:
- The policy definition `name` property exists
- The `name` value does not exceed 24 characters
- The policy names should follow Azure naming conventions (alphanumeric and hyphens only, no spaces)

### Suggestions

Keep your policy definition name concise and under 24 characters:

```json
{
  "name": "ValidateVMDelete",
  "properties": {
    "policyType": "Custom",
    "mode": "All",
    "metadata": {
      "posId": "12345678-1234-1234-1234-123456789012",
      "category": "ChangeSafety"
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
