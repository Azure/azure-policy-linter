# MissingTokenAction Parameter Must Have Correct Default and Allowed Values


| Category | Identifier |
|----------------|------------------------------------------------------|
| Misc | missing-token-action-must-be-parameterized-with-correct-values |

## Description

Change Safety policies that use external evaluation enforcement settings require the `missingTokenAction` property to be properly configured with specific default and allowed values.

The rule validates that:
- The `missingTokenAction` property is parameterized (e.g., `[parameters('missingTokenAction')]`)
- The `missingTokenAction` parameter has a default value of `audit`
- The `missingTokenAction` parameter has exactly two allowed values: `audit` and `deny`

### Suggestions

Ensure your Change Safety policy has a properly configured `missingTokenAction` parameter in the `parameters` section:

```json
{
  "properties": {
    "displayName": "Change safety - Example policy",
    "policyType": "Custom",
    "mode": "Indexed",
    "parameters": {
      "missingTokenAction": {
        "type": "String",
        "metadata": {
          "displayName": "Missing Token Action",
          "description": "Action to take when token is missing"
        },
        "defaultValue": "audit",
        "allowedValues": [
          "audit",
          "deny"
        ]
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
      "missingTokenAction": "[parameters('missingTokenAction')]",
      "endpointSettings": {
        "kind": "RequireChangeAssociation",
        "details": {
          "requireChangeReference": true
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
