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
    /// Tests for the <see cref="ReadOnlyFieldAlias"/> rule.
    /// </summary>
    public class ReadOnlyFieldAliasTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void LinterTests_ReadOnlyFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ReadOnlyFieldAlias()
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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "read-only-field-alias",
                Title: "Read-Only Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 99,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.Storage/storageAccounts/privateEndpointConnections' maps to property that is marked as read-only in one or more old API versions of resource type: 'Microsoft.Storage/storageAccounts'. API versions: '2019-06-01, 2020-08-01-preview, 2021-01-01, 2021-02-01, 2021-04-01, 2021-06-01, 2021-08-01, 2021-09-01, 2022-05-01, 2022-09-01, 2023-01-01, 2023-04-01, 2023-05-01, 2024-01-01, 2025-01-01, 2025-06-01, 2025-08-01, 2026-04-01'");

            results.Should().ContainEquivalentOf(output);
        }
    }
}
