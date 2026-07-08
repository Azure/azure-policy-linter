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
    /// Tests for the <see cref="HardCodedEnforcementPolicyEffect"/> rule.
    /// </summary>
    public class HardCodedEnforcementPolicyEffectTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_HardCodedEnforcementPolicyEffect_EnforcementEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedEnforcementPolicyEffect()
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
                RuleIdentifier: "hard-coded-policy-enforcement-effect",
                Title: "Hard-Coded Enforcement Policy Effect",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 24,
                LinePosition: 40,
                Path: "properties.policyRule.then.effect",
                Description: "The policy definition has a hard-coded enforcement effect: 'deny'. Consider adding an \"effect\" policy definition parameter with default value: 'audit' and allowed values: 'audit,deny,disabled' and replace the hard-coded effect with \"[parameters('effect')]\". Parameterizing the policy effect makes it easy reuse the policy as well as to follow safe deployment practices (start with audit, then enforce).");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("audit")]
        [InlineData("[parameters('whatever')]")]
        public void RuleTests_HardCodedEnforcementPolicyEffect_ShouldNotBeTriggered(string effectValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedEnforcementPolicyEffect()
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

            // Replace the hard-coded effect with the provided value
            policyDefinition = policyDefinition.Replace("deny", effectValue);
            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
