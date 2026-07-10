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
    /// Tests for the <see cref="EffectParameterMissingAllowedValues"/> rule.
    /// </summary>
    public class EffectParameterMissingAllowedValuesTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_EffectParameterMissingAllowedValues_NoAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingAllowedValues()
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

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-missing-allowed-values",
                Title: "Effect Parameter Missing Allowed Values",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 17,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' does not constrain its allowedValues, so any value can be assigned. Add an allowedValues array to restrict the effect to a known set of values (e.g. ['Audit', 'Deny', 'Disabled'])."));
        }

        [Fact]
        public void RuleTests_EffectParameterMissingAllowedValues_EmptyAllowedValues()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingAllowedValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""Audit"",
                        ""allowedValues"": []
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
                RuleIdentifier: "effect-parameter-missing-allowed-values",
                Title: "Effect Parameter Missing Allowed Values",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 18,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' does not constrain its allowedValues, so any value can be assigned. Add an allowedValues array to restrict the effect to a known set of values (e.g. ['Audit', 'Deny', 'Disabled'])."));
        }

        [Fact]
        public void RuleTests_EffectParameterMissingAllowedValues_AllowedValuesPresent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingAllowedValues()
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

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_EffectParameterMissingAllowedValues_HardCodedEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingAllowedValues()
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
        public void RuleTests_EffectParameterMissingAllowedValues_CustomParameterName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterMissingAllowedValues()
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
                RuleIdentifier: "effect-parameter-missing-allowed-values",
                Title: "Effect Parameter Missing Allowed Values",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 64,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'policyEffect' does not constrain its allowedValues, so any value can be assigned. Add an allowedValues array to restrict the effect to a known set of values (e.g. ['Audit', 'Deny', 'Disabled'])."));
        }
    }
}
