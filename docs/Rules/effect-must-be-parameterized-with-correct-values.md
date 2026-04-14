# Effect Parameter Must Have Correct Default and Allowed Values


| Category | Identifier |
|----------------|----------------------------------------|
| Misc | effect-must-be-parameterized-with-correct-values |

## Description

Change Safety policies require the effect parameter to be properly configured with specific default and allowed values.

The rule validates that:
- The policy effect is parameterized (e.g., `[parameters('effect')]`)
- The effect parameter has a default value of `auditAction`
- The effect parameter has exactly three allowed values: `auditAction`, `denyAction`, and `disabled`

### Suggestions

Ensure your Change Safety policy has a properly configured effect parameter in the `parameters` section:

```json
{
  "properties": {
    "displayName": "My Change Safety Policy",
    "policyType": "Custom",
    "mode": "All",
    "parameters": {
      "effect": {
        "type": "String",
        "metadata": {
          "displayName": "Effect",
          "description": "The effect determines what happens when the policy rule is evaluated to match"
        },
        "defaultValue": "auditAction",
        "allowedValues": [
          "auditAction",
          "denyAction",
          "disabled"
        ]
      }
    },
    "policyRule": {
      "if": {
        // ... conditions
      },
      "then": {
        "effect": "[parameters('effect')]"
      }
    }
  }
}
```

### Rule Set

This rule is part of the `ChangeSafety` rule set and is specifically designed for 1P change safety policies. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```
