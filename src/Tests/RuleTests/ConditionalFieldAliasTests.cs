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
    /// Tests for the <see cref="ConditionalFieldAlias"/> rule.
    /// </summary>
    public class ConditionalFieldAliasTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void LinterTests_ConditionalFieldAlias()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ConditionalFieldAlias()
                },
                metadata: TypeMetadata);

            // The "folderPath" property is only present in data factory triggers of type "BlobTrigger"
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
                            ""equals"": ""Microsoft.DataFactory/factories/triggers""
                          },
                          {
                            ""field"": ""Microsoft.DataFactory/factories/triggers/BlobTrigger.typeProperties.folderPath"",
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
                RuleIdentifier: "conditional-field-alias",
                Title: "Conditional Field Alias",
                Severity: Severity.Warning,
                Category: Category.ResourceFields,
                LineNumber: 18,
                LinePosition: 117,
                Path: "properties.policyRule.if.allOf[1].field",
                Description: "The field alias: 'Microsoft.DataFactory/factories/triggers/BlobTrigger.typeProperties.folderPath' maps to property path that only exists in the target resource type: 'Microsoft.DataFactory/factories/triggers' if some conditions are met. In all other cases, the property might be missing. Affected API versions: '2017-09-01-preview, 2018-06-01'");

            results.Should().ContainEquivalentOf(output);
        }
    }
}
