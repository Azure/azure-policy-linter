# RequireChangeReference Parameter Must Be Set to True


| Category | Identifier |
|----------------|------------------------------------------|
| Misc | require-change-reference-must-be-parameterized-with-correct-value |

## Description

Change Safety policies require the `requireChangeReference` property to be parameterized with a default value of `true`. This ensures that all change operations are properly associated with a change reference, which is essential for tracking and auditing changes in 1P change safety scenarios.

The rule validates that:
- The `endpointSettings.details` section exists
- The `requireChangeReference` property is present in the details
- The property is parameterized (e.g., `[parameters('requireChangeReference')]`)
- The parameter is defined in the policy's parameters section
- The parameter has a default value of boolean `true` (not the string `"true"`)

### Suggestions

Ensure your Change Safety policy has a properly configured `requireChangeReference` parameter and endpoint settings:

```json
{
  "properties": {
    "displayName": "Change safety - Example policy",
    "policyType": "Custom",
    "mode": "Indexed",
    "parameters": {
      "requireChangeReference": {
        "type": "Boolean",
        "metadata": {
          "displayName": "Require Change Reference",
          "description": "Require a change reference for operations"
        },
        "defaultValue": true
      }
    },
    "policyRule": {
      "if": {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Storage/storageAccounts"
          },
          {
            "value": "[claims().outcome]",
            "notEquals": "Succeeded"
          }
        ]
      },
      "then": {
        "effect": "denyAction",
        "details": {
          "actionNames": [
            "delete"
          ]
        }
      }
    },
    "externalEvaluationEnforcementSettings": {
      "roleDefinitionIds": [],
      "endpointSettings": {
        "kind": "ChangeSafetyValidation",
        "details": {
          "requireChangeReference": "[parameters('requireChangeReference')]"
        }
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
