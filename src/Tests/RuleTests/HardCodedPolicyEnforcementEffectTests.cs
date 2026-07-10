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
    /// Tests for the <see cref="HardCodedPolicyEnforcementEffect"/> rule.
    /// </summary>
    public class HardCodedPolicyEnforcementEffectTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Theory]
        [InlineData("deny", "audit", "audit,deny,disabled", 40)]
        [InlineData("append", "audit", "audit,append,disabled", 42)]
        [InlineData("modify", "audit", "audit,modify,disabled", 42)]
        [InlineData("deployIfNotExists", "auditIfNotExists", "auditIfNotExists,deployIfNotExists,disabled", 53)]
        [InlineData("denyAction", "auditAction", "auditAction,denyAction,disabled", 46)]
        [InlineData("DENY", "audit", "audit,DENY,disabled", 40)]
        public void RuleTests_HardCodedPolicyEnforcementEffect_EnforcementEffect(string effect, string defaultValue, string allowedValues, int linePosition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedPolicyEnforcementEffect()
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
                        ""effect"": """ + effect + @"""
                      }
                    } 
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "hard-coded-policy-enforcement-effect",
                Title: "Hard-Coded Policy Enforcement Effect",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 24,
                LinePosition: linePosition,
                Path: "properties.policyRule.then.effect",
                Description: $"The policy definition has a hard-coded enforcement effect: '{effect}'. Consider adding an \"effect\" policy definition parameter with default value: '{defaultValue}' and allowed values: '{allowedValues}' and replace the hard-coded effect with \"[parameters('effect')]\".");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("audit")]
        [InlineData("[parameters('whatever')]")]
        public void RuleTests_HardCodedPolicyEnforcementEffect_ShouldNotBeTriggered(string effectValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedPolicyEnforcementEffect()
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
