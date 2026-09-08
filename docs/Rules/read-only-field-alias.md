# Read-Only Field Alias


| Category | Identifier | Severity | Rule Set |
|----------------|----------------------------------------|----------|----------|
| ResourceFields | read-only-field-alias | Warning or Informational | default |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that is annotated as read-only by the resource provider in one or more API versions. Read-only aliases remain relevant because a caller may omit the property and a resource provider may ignore a supplied value during request-time evaluation, while persisted resource state may still support compliance evaluation.

Literal `audit`, `auditIfNotExists`, and `auditAction` effects receive Informational severity, case-insensitively. A direct reference to a String effect parameter also receives Informational severity when its nonempty `allowedValues` contains only those three audit-class effects. The parameter default does not affect this classification.

Enforcement effects and `disabled`, `manual`, unknown, or uncertain effects receive Warning severity. Warning severity also applies when a parameter is unresolved, is not a String, has missing, empty, mixed, or malformed `allowedValues`, or when the effect uses a complex expression.

### Suggestions

- Avoid relying on read-only properties in enforcement policies, such as policies with a `deny` effect.
- Review Informational findings in audit-only policies to confirm that the property is suitable for compliance evaluation.

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.