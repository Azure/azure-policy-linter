namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ParameterMissingDescription"/> rule.
    /// </summary>
    public class ParameterMissingDescriptionTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_ParameterMissingDescription_NoMetadata()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new ParameterMissingDescription() },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array""
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""location"", ""in"": ""[parameters('allowedLocations')]"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-description",
                Title: "Parameter Missing Description",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 43,
                Path: "properties.parameters.allowedLocations",
                Description: "The parameter 'allowedLocations' has no 'metadata.description'. Without one, whoever assigns the policy gets no guidance on the parameter's purpose or acceptable values. Add a 'metadata.description'."));
        }

        [Fact]
        public void RuleTests_ParameterMissingDescription_MetadataWithoutDescription()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new ParameterMissingDescription() },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""displayName"": ""Allowed locations"" }
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""location"", ""in"": ""[parameters('allowedLocations')]"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-description",
                Title: "Parameter Missing Description",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 43,
                Path: "properties.parameters.allowedLocations",
                Description: "The parameter 'allowedLocations' has no 'metadata.description'. Without one, whoever assigns the policy gets no guidance on the parameter's purpose or acceptable values. Add a 'metadata.description'."));
        }

        [Fact]
        public void RuleTests_ParameterMissingDescription_EmptyDescription()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new ParameterMissingDescription() },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""description"": ""   "" }
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""location"", ""in"": ""[parameters('allowedLocations')]"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-description",
                Title: "Parameter Missing Description",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 43,
                Path: "properties.parameters.allowedLocations",
                Description: "The parameter 'allowedLocations' has no 'metadata.description'. Without one, whoever assigns the policy gets no guidance on the parameter's purpose or acceptable values. Add a 'metadata.description'."));
        }

        [Fact]
        public void RuleTests_ParameterMissingDescription_DescriptionPresent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new ParameterMissingDescription() },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""description"": ""The list of locations that resources can be deployed into."" }
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""location"", ""in"": ""[parameters('allowedLocations')]"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ParameterMissingDescription_CaseInsensitiveMetadataKeys()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new ParameterMissingDescription() },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""Description"": ""The list of allowed locations."" }
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""location"", ""in"": ""[parameters('allowedLocations')]"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ParameterMissingDescription_MultipleParameters()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new ParameterMissingDescription() },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""description"": ""The list of allowed locations."" }
                      },
                      ""effect"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""location"", ""in"": ""[parameters('allowedLocations')]"" },
                      ""then"": { ""effect"": ""[parameters('effect')]"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-description",
                Title: "Parameter Missing Description",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 10,
                LinePosition: 33,
                Path: "properties.parameters.effect",
                Description: "The parameter 'effect' has no 'metadata.description'. Without one, whoever assigns the policy gets no guidance on the parameter's purpose or acceptable values. Add a 'metadata.description'."));
        }
    }
}
