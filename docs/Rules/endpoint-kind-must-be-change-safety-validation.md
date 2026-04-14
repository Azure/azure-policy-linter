# Endpoint Kind Must Be 'ChangeSafetyValidation'


| Category | Identifier |
|----------------|-------------------------------------|
| Misc | endpoint-kind-must-be-change-safety-validation |

## Description

Change Safety policies require the endpoint kind to be set to `ChangeSafetyValidation`.

The rule ensures that:
- The endpoint settings contain a `kind` property
- The `kind` property is not null or empty
- The `kind` property value is set to `ChangeSafetyValidation` (case-insensitive)

### Suggestions

Ensure your Change Safety policy has a properly configured endpoint with the correct kind:

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
