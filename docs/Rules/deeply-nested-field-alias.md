# Deeply Nested Field Alias

| Category | Identifier | Severity | Rule Set |
|----------------|---------------------------|----------|----------|
| ResourceFields | deeply-nested-field-alias | Warning  | default  |

## Description

The policy definition is referencing a [field alias](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-alias) whose resolved property path is nested more than two resource bodies deep (its path contains more than two `properties` segments). This alias may point to a property that doesn't actually exist on the evaluated resource, causing conditions on it to silently never match.

Aliases are generated from the resource provider's API specification. When a provider models a property as a *reference* to a separate resource rather than an embedded child resource, the generation can misread it as the entire referenced resource being embedded inline, producing an alias for a path that does not exist on the evaluated resource. One or two levels of nesting are usually legitimately embedded child resources (for example, a network security group embedding its rules); beyond that, the path increasingly threads through one or more resource references, and the property it targets may not exist on the resource being evaluated.

### Suggestions

- Verify the property exists on the resource type against the resource provider's [REST API documentation](https://learn.microsoft.com/en-us/rest/api/azure/).
- Test whether the property can actually be set by creating a test resource using Azure Portal, Azure CLI, or Azure PowerShell and attempting to configure the property. If the tools don't expose the property or fail when you try to set it, the property may not exist on the evaluated resource.
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
- The linter repo contains an export of all available policy aliases **from the public cloud**.
