# Read-Only Field Alias


| Category | Identifier | Severity | Rule Set |
|----------------|----------------------------------------|----------|----------|
| ResourceFields | read-only-field-alias | Warning | default |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that is annotated as read-only by the resource provider in one or more API versions.

This means that the property can't be relied upon during enforcement evaluations of incoming requests, since the caller isn't required to specify this property and even if they do, it'll most likely be ignored by the resource provider.

### Suggestions

- Avoid relying on read-only properties in enforcement policies (e.g. policies with a `deny` effect).
- If the purpose of the policy is mainly for compliance (e.g. `audit` effect), then it should be OK to use the alias.

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.