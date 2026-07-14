# Deeply Nested Field Alias

| Category | Identifier | Severity | Rule Set |
|----------------|---------------------------|----------|----------|
| ResourceFields | deeply-nested-field-alias | Warning  | default  |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) whose resolved property path is nested more than two resource bodies deep (its path contains more than two `properties` segments).

Aliases are generated from the resource provider's API specification. When a provider models a property as a *reference* to a separate resource rather than an embedded child resource, the generation can misread it as the entire referenced resource being embedded inline, producing an alias for a path that does not exist on the evaluated resource. One level of nesting is usually a legitimately embedded child resource (for example, a network security group embedding its rules); beyond that, the path increasingly threads through one or more resource references, and the property it targets may not exist on the resource being evaluated. A condition on such a property silently never matches.

### Suggestions

- Verify the property exists on the resource type against the resource provider's [REST API documentation](https://learn.microsoft.com/en-us/rest/api/azure/).
- If the property does not exist on the evaluated resource, target a property that does, or restructure the policy to evaluate the referenced resource type directly.

## Examples

### Triggers the rule

The resolved path crosses several resource-reference boundaries (subnet -> network security group -> network interface -> IP configuration -> virtual network tap -> load balancer frontend IP configuration) and points at a property that does not exist on the evaluated virtual network:

```json
{
  "field": "Microsoft.Network/virtualNetworks/subnets[*].networkSecurityGroup.networkInterfaces[*].ipConfigurations[*].virtualNetworkTaps[*].destinationLoadBalancerFrontEndIPConfiguration.privateIPAddressVersion",
  "exists": "true"
}
```

### Correct

A shallowly nested alias for a legitimately embedded child resource:

```json
{
  "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].access",
  "equals": "Allow"
}
```

## Data sources

- Resource metadata is derived from the public [Azure REST API specs](https://github.com/Azure/azure-rest-api-specs/tree/main/specification).
- The linter repo contains a dump of all available policy aliases **from the public cloud**.
