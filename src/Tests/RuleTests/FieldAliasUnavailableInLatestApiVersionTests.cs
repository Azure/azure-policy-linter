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
    /// Tests for the <see cref="FieldAliasUnavailableInLatestApiVersion"/> rule.
    /// </summary>
    public class FieldAliasUnavailableInLatestApiVersionTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void RuleTests_FieldAliasUnavailableInLatestApiVersion()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new FieldAliasUnavailableInLatestApiVersion()
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
                            ""equals"": ""Microsoft.DocumentDB/databaseAccounts""
                          },
                          {
                            ""field"": ""Microsoft.DocumentDB/databaseAccounts/ipRangeFilter"",
                            ""equals"": ""Allow""
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
                RuleIdentifier: "field-alias-unavailable-in-latest-api-version",
                Title: "Field Alias Unavailable In Latest API Version",
                Severity: Severity.Error,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 90,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.DocumentDB/databaseAccounts/ipRangeFilter' is referring to a property that doesn't exist in the latest API version (2025-11-01-preview) of resource type: 'Microsoft.DocumentDB/databaseAccounts'. This most likely means that the referenced property is deprecated and the policy might not work as intended.");

            results.Should().ContainEquivalentOf(output);
        }
    }
}
