# Field Alias Unavailable In Latest API Version


| Category | Identifier |
|----------------|----------------------------------------|
| ResourceFields | field-alias-unavailable-in-latest-api-version |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) that maps to a property that doesn't exist in the latest API versions of the targeted resource type.
Aliases are meant to map a property path across ALL available API versions of a resource. However, it is very common for resource properties to be available only starting from the API version in which they were introduced.
When a property is added to a new API version, it can't be added to older versions since it is considered a breaking change. It is also possible that a property is deprecated and no longer available in newer API versions, but the alias remains.

Using an alias that is not available in the latest API version of a resource can cause the following issues:
- Invalid policy [compliance data](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/compliance-states), since compliance scan is always using the latest API versions.
- There's a high likelihood of clients using the new API version when making requests. For these clients, policy enforcement might not work as expected.
  - This is expected to get worse over time, as more and more clients shift towards the latest API version.

### Suggestions

- The policy is most likely not doing the right thing, consult the resource provider documentation to see if a different property is available in the latest API version that provides the same functionality.
- Consider using the `[requestContext().apiVersion]` function in the policy rule to explicitly determine what to do in the case of which API versions.

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.