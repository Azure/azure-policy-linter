namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="OptionalFieldAlias"/> rule.
    /// </summary>
    public class OptionalFieldAliasTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_OptionalFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""approvedIpRanges"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/allowBlobPublicAccess"",
                            ""equals"": ""Something""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    } 
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "optional-field-alias",
                Title: "Optional Field Alias",
                Severity: Severity.Informational,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 94,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/allowBlobPublicAccess' maps to a property that is not marked as required in some API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2019-04-01, 2019-06-01, 2020-08-01-preview, 2021-01-01, 2021-02-01, 2021-04-01, 2021-06-01, 2021-08-01, 2021-09-01, 2022-05-01, 2022-09-01, 2023-01-01, 2023-04-01, 2023-05-01, 2024-01-01, 2025-01-01, 2025-06-01, 2025-08-01, 2026-04-01'");
            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_OptionalFieldAlias_RequiredProperty_IsSilent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.KeyVault/vaults""
                          },
                          {
                            ""field"": ""Microsoft.KeyVault/vaults/sku.name"",
                            ""equals"": ""Something""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_OptionalFieldAlias_ReadOnlyProperty_IsSilent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
                },
                metadata: TypeMetadata);

            // privateEndpointConnections is read-only (and not required), so the read-only-field-alias
            // rule owns it; optional-field-alias must stay silent as the residual case.
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""allOf"": [
                          {
                            ""field"": ""type"",
                            ""equals"": ""Microsoft.Storage/storageAccounts""
                          },
                          {
                            ""field"": ""Microsoft.Storage/storageAccounts/privateEndpointConnections"",
                            ""equals"": ""Something""
                          }
                        ]
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_OptionalFieldAlias_UnresolvedReference_IsSilent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new OptionalFieldAlias()
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
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
