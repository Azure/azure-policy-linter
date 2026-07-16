namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="DeeplyNestedFieldAlias"/> rule.
    /// </summary>
    public class DeeplyNestedFieldAliasTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_DeeplyNestedFieldAlias_DepthSeven()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DeeplyNestedFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Network/virtualNetworks/subnets[*].networkSecurityGroup.networkInterfaces[*].ipConfigurations[*].virtualNetworkTaps[*].destinationLoadBalancerFrontEndIPConfiguration.privateIPAddressVersion"",
                        ""exists"": ""true""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "deeply-nested-field-alias",
                Title: "Deeply Nested Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 234,
                Path: "properties.policyRule.if.field",
                Description: "The field alias: 'Microsoft.Network/virtualNetworks/subnets[*].networkSecurityGroup.networkInterfaces[*].ipConfigurations[*].virtualNetworkTaps[*].destinationLoadBalancerFrontEndIPConfiguration.privateIPAddressVersion' resolves to a property path nested 7 levels deep. Deeply nested paths often cross into a referenced resource, so the targeted property may not exist on the evaluated resource. Verify it against the resource provider's REST API documentation.");
            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DeeplyNestedFieldAlias_JustOverThreshold()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DeeplyNestedFieldAlias()
                },
                metadata: TypeMetadata);

            // Three "properties" segments (one over the threshold) fires.
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/applicationGateways[*].gatewayIPConfigurations[*].subnet.id"",
                        ""exists"": ""true""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "deeply-nested-field-alias",
                Title: "Deeply Nested Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 7,
                LinePosition: 161,
                Path: "properties.policyRule.if.field",
                Description: "The field alias: 'Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/applicationGateways[*].gatewayIPConfigurations[*].subnet.id' resolves to a property path nested 3 levels deep. Deeply nested paths often cross into a referenced resource, so the targeted property may not exist on the evaluated resource. Verify it against the resource provider's REST API documentation.");
            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_DeeplyNestedFieldAlias_AtThreshold_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DeeplyNestedFieldAlias()
                },
                metadata: TypeMetadata);

            // Two "properties" segments (an embedded child resource) is at the threshold and stays silent.
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Network/networkSecurityGroups/securityRules[*].access"",
                        ""equals"": ""Allow""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DeeplyNestedFieldAlias_ShallowAlias_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DeeplyNestedFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                        ""equals"": ""false""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_DeeplyNestedFieldAlias_UnresolvedReference_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new DeeplyNestedFieldAlias()
                },
                metadata: TypeMetadata);

            // "location" is a policy field, not a resource-property alias, so the rule short-circuits.
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""location"",
                        ""equals"": ""eastus""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
