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
    /// Tests for the <see cref="EffectParameterShouldHaveAllowedAndDefaultValues"/> rule.
    /// </summary>
    public class EffectParameterShouldHaveAllowedAndDefaultValuesTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_EffectParameterShouldHaveAllowedAndDefaultValues_BothMissing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""effect"": {
                        ""type"": ""String""
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

            results.Should().HaveCount(2);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'allowedValues'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'defaultValue'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }

        [Fact]
        public void RuleTests_EffectParameterShouldHaveAllowedAndDefaultValues_AllowedValuesMissing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
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
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 17,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'allowedValues'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }

        [Fact]
        public void RuleTests_EffectParameterShouldHaveAllowedAndDefaultValues_DefaultValueMissing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
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
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 21,
                LinePosition: 58,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'effect' is missing 'defaultValue'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }

        [Fact]
        public void RuleTests_EffectParameterShouldHaveAllowedAndDefaultValues_BothPresent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
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
        public void RuleTests_EffectParameterShouldHaveAllowedAndDefaultValues_HardCodedEffect()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
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
        public void RuleTests_EffectParameterShouldHaveAllowedAndDefaultValues_CustomParameterName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EffectParameterShouldHaveAllowedAndDefaultValues()
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

            results.Should().HaveCount(2);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 64,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'policyEffect' is missing 'allowedValues'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "effect-parameter-should-have-allowed-and-default-values",
                Title: "Effect Parameter Should Have allowedValues and defaultValue",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 16,
                LinePosition: 64,
                Path: "properties.policyRule.then.effect",
                Description: "The effect parameter 'policyEffect' is missing 'defaultValue'. Use allowedValues and defaultValue to constrain the effect to a known set of values and provide a sensible default when the parameter is not explicitly set."));
        }
    }
}
