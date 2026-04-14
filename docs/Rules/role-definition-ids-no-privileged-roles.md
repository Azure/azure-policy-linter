# Role Definition IDs Must Not Include Privileged Roles

| Category | Identifier |
|----------|-----------------------------------------|
| Misc     | role-definition-ids-no-privileged-roles |

## Description

ChangeSafety policies must not use privileged role definitions in `externalEvaluationEnforcementSettings.roleDefinitionIds`. Privileged roles grant broad permissions across many resources and violate the principle of least privilege.

The rule flags the following privileged role definitions:
- `/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635` - Owner - Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.
- `/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c` - Contributor - Grants full access to manage all resources, but does not allow you to assign roles in Azure RBAC, manage assignments
- `/providers/Microsoft.Authorization/roleDefinitions/92b92042-07d9-4307-87f7-36a593fc5850` - Azure File Sync Administrator - Provides full access to manage all Azure File Sync (Storage Sync Service) resources, including the ability to assign roles in Azure RBAC.
- `/providers/Microsoft.Authorization/roleDefinitions/a8889054-8d42-49c9-bc1c-52486c10e7cd` - Reservations Administrator - Lets one read and manage all the reservations in a tenant
- `/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9` - User Access Administrator - Lets you manage user access to Azure resources.
- `/providers/Microsoft.Authorization/roleDefinitions/f58310d9-a9f6-439a-9e8d-f62e7b41a168` - Role Based Access Control Administrator - Manage access to Azure resources by assigning roles using Azure RBAC. This role does not allow you to manage access using other ways, such as Azure Policy.
- `/providers/Microsoft.Authorization/roleDefinitions/36243c78-bf99-498c-9df9-86d9f8d28608` - Users with rights to create/modify resource policy, create support ticket and read resources/hierarchy.


ChangeSafety policies should request only the minimum permissions necessary. The roles needed for the typical Change Safety scenario are:
- **Reader** (`acdd72a7-3385-48ef-bd42-f606fba81ae7`) - Provides read access to resources
- **Change Safety Contributor** (`fdb3df26-8dd6-49ff-9a74-e95dbfadcad3`) - Grants permissions to interact with the Change Safety validation service

## Examples

### - Using Narrowly-Scoped Roles
```json
{
  "properties": {
    "externalEvaluationEnforcementSettings": {
      "roleDefinitionIds": [
        "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
        "/providers/Microsoft.Authorization/roleDefinitions/fdb3df26-8dd6-49ff-9a74-e95dbfadcad3"
      ],
      "endpointSettings": {
        "kind": "ChangeSafetyValidation",
        "details": {
          "validatorVersionId": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.ChangeSafety/validators/metricsValidator/versions/0.0.1-beta')]",
          "stageParameters": {
            "resourceId": "[field('id')]"
          }
        }
      }
    }
  }
}
```


## Rule Set

This rule is part of the `ChangeSafety` rule set. To run this rule, use:

```bash
policylinter policy.json --rule-set ChangeSafety
```

## Data sources

- [Azure built-in roles - Privileged roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#privileged)
- [Understand Azure role definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)