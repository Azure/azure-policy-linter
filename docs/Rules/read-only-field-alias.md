# Read-Only Field Alias


| Category | Identifier | Severity | Rule Set |
|----------------|----------------------------------------|----------|----------|
| ResourceFields | read-only-field-alias | Warning or Informational | default |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that is annotated as read-only by the resource provider in one or more API versions. Read-only aliases are always reported.

Audit-only policies receive Informational severity because they cannot block or modify a deployment. Policies with enforcement-capable effects receive Warning severity because the property cannot be relied upon during enforcement evaluation. Warning severity is also used when the effect is uncertain.

### Suggestions

- Avoid relying on read-only properties in enforcement policies, such as policies with a `deny` effect.
- Review Informational findings in audit-only policies to confirm that the property is suitable for compliance evaluation.

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.