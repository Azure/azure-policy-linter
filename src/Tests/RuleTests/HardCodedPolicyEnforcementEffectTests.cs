namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="HardCodedPolicyEnforcementEffect"/> rule.
    /// </summary>
    public class HardCodedPolicyEnforcementEffectTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("deny", "audit", 40)]
        [InlineData("append", "audit", 42)]
        [InlineData("modify", "audit", 42)]
        [InlineData("deployIfNotExists", "auditIfNotExists", 53)]
        [InlineData("denyAction", "auditAction", 46)]
        [InlineData("DENY", "audit", 40)]
        public void RuleTests_HardCodedPolicyEnforcementEffect_EnforcementEffect(string effect, string defaultValue, int linePosition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedPolicyEnforcementEffect()
                },
                metadata: HardCodedPolicyEnforcementEffectTests.MockMetadata);

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
                Description: $"The policy effect '{effect}' is hard-coded, so assignments cannot select a non-enforcement effect. Add a string 'effect' parameter with defaultValue '{defaultValue}' and allowedValues containing '{defaultValue}', '{effect}', 'disabled', then set the policy effect to \"[parameters('effect')]\".");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("audit")]
        [InlineData("auditAction")]
        [InlineData("auditIfNotExists")]
        [InlineData("disabled")]
        [InlineData("[parameters('whatever')]")]
        public void RuleTests_HardCodedPolicyEnforcementEffect_ShouldNotBeTriggered(string effectValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new HardCodedPolicyEnforcementEffect()
                },
                metadata: HardCodedPolicyEnforcementEffectTests.MockMetadata);

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
                        ""effect"": """ + effectValue + @"""
                      }
                    } 
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
