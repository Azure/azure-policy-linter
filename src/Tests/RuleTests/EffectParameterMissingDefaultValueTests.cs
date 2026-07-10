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
    /// Tests for the <see cref="EffectParameterMissingDefaultValue"/> rule.
    /// </summary>
    public class EffectParameterMissingDefaultValueTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_EffectParameterMissingDefaultValue_NoDefaultValue()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingDefaultValue()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""allowedValues"": [
                          ""Audit"",
                          ""Deny"",
                          ""Disabled""
                        ]
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-missing-default-value",
                Title: "Effect Parameter Missing Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 21,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' does not define a defaultValue, so the effect must be set on every assignment. Add a defaultValue so the policy behaves predictably when the parameter is not set."));
        }

        [Fact]
        public void RuleTests_EffectParameterMissingDefaultValue_DefaultValuePresent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingDefaultValue()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('effect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_EffectParameterMissingDefaultValue_HardCodedEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingDefaultValue()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
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
        public void RuleTests_EffectParameterMissingDefaultValue_CustomParameterName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingDefaultValue()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""policyEffect"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""[parameters('policyEffect')]""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-missing-default-value",
                Title: "Effect Parameter Missing Default Value",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 64,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'policyEffect' does not define a defaultValue, so the effect must be set on every assignment. Add a defaultValue so the policy behaves predictably when the parameter is not set."));
        }
    }
}
