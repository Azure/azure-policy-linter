# Role Definition IDs Should Use Expected ChangeSafety Roles

| Category | Identifier |
|----------|-------------------------------------|
| Misc | role-definition-ids-expected-roles |

## Description

This warning alerts when ChangeSafety policies use role definitions that differ from the standard expected roles.

The roles specified in `roleDefinitionIds` will be granted to the policy assignment's Managed Service Identity (MSI) and will be used to invoke the Change Safety validation. 
We expect that these 2 roles are the ones that are most commonly used for Change Safety validations:
- **Change Safety Contributor** (`fdb3df26-8dd6-49ff-9a74-e95dbfadcad3`) is needed to create validations
- **Reader** (`acdd72a7-3385-48ef-bd42-f606fba81ae7`) is typically needed to access the external data being validated (like metrics, ARG, etc.)

If the author specified a different set of role definitions, they need to make sure they are not granting the policy too much or too little permissions,
and the author **should**:

1. **Review validation requirements**: Identify what data sources the Change Safety validation needs to access
2. **Verify role necessity**: Confirm that any non-standard roles are required for the specific scenario
3. **Follow least privilege**: Ensure to not grant more permissions than necessary

## Examples

### Standard Expected Roles

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

- Empty strings or invalid role definition paths will trigger a warning.
- Role definitions must be specified as **full ARM paths** in the format `/providers/Microsoft.Authorization/roleDefinitions/{guid}`

## Rule Set

This rule is part of the `ChangeSafety` rule set. To run this rule, use:

```
policylinter policy.json --rule-set ChangeSafety
```

## Related Rules

- [role-definition-ids-no-privileged-roles](./role-definition-ids-no-privileged-roles.md) - Enforces that privileged roles (Owner, Contributor, etc.) are not used

## Data sources

- [Azure built-in roles - Privileged roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#privileged)
- [Understand Azure role definitions](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions)