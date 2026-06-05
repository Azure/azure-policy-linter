# Conditional Field Alias


| Category | Identifier |
|----------------|----------------------------------------|
| ResourceFields | conditional-field-alias |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that is annotated as conditional by resource provider in one or more API versions. This means that this property will only exist in some cases. This is typical for resources that implement additional "typing" system. For example, Azure Data Factory triggers might have different trigger "kinds", and each trigger has it's own properties. 

If the policy rule is ignoring these additional conditions and is expecting the property to always exist, it may result in incorrect evaluation results.

### Suggestions

- Consult the resource provider documentation to find the exact condition in which the property exists, and ensure to include them in the policy rule to ensure the policy is invoked only when the property is expected.

## Data sources

- The policy team is scanning the [RESP API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification) and process them into [resource metadata](https://msazure.visualstudio.com/One/_git/Mgmt-Governance-Schema?path=/src/GeneratedMetadata).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.