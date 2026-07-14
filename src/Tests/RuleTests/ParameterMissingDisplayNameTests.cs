namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="ParameterMissingDisplayName"/> rule.
    /// </summary>
    public class ParameterMissingDisplayNameTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_ParameterMissingDisplayName_NoMetadata()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ParameterMissingDisplayName()
                },
                metadata: MockMetadata);

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
                      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-display-name",
                Title: "Parameter Missing Display Name",
                Severity: Severity.Informational,
                Category: Category.Misc,
                LineNumber: 6,
                LinePosition: 43,
                Path: "properties.parameters",
                Description: "The parameter 'allowedLocations' has no 'displayName' in its metadata, so the portal shows the raw parameter name during assignment. Add a 'metadata.displayName' to give it a friendly label."));
        }

        [Fact]
        public void RuleTests_ParameterMissingDisplayName_MetadataWithoutDisplayName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ParameterMissingDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""description"": ""The list of allowed locations."" }
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-display-name",
                Title: "Parameter Missing Display Name",
                Severity: Severity.Informational,
                Category: Category.Misc,
                LineNumber: 6,
                LinePosition: 43,
                Path: "properties.parameters",
                Description: "The parameter 'allowedLocations' has no 'displayName' in its metadata, so the portal shows the raw parameter name during assignment. Add a 'metadata.displayName' to give it a friendly label."));
        }

        [Fact]
        public void RuleTests_ParameterMissingDisplayName_EmptyDisplayName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ParameterMissingDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""displayName"": """" }
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-display-name",
                Title: "Parameter Missing Display Name",
                Severity: Severity.Informational,
                Category: Category.Misc,
                LineNumber: 6,
                LinePosition: 43,
                Path: "properties.parameters",
                Description: "The parameter 'allowedLocations' has no 'displayName' in its metadata, so the portal shows the raw parameter name during assignment. Add a 'metadata.displayName' to give it a friendly label."));
        }

        [Fact]
        public void RuleTests_ParameterMissingDisplayName_WhitespaceDisplayName()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ParameterMissingDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""allowedLocations"": {
                        ""type"": ""Array"",
                        ""metadata"": { ""displayName"": ""   "" }
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-display-name",
                Title: "Parameter Missing Display Name",
                Severity: Severity.Informational,
                Category: Category.Misc,
                LineNumber: 6,
                LinePosition: 43,
                Path: "properties.parameters",
                Description: "The parameter 'allowedLocations' has no 'displayName' in its metadata, so the portal shows the raw parameter name during assignment. Add a 'metadata.displayName' to give it a friendly label."));
        }

        [Fact]
        public void RuleTests_ParameterMissingDisplayName_DisplayNamePresent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ParameterMissingDisplayName()
                },
                metadata: MockMetadata);

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
                      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ParameterMissingDisplayName_NoParameters()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ParameterMissingDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""policyRule"": {
                      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_ParameterMissingDisplayName_MultipleParameters()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new ParameterMissingDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""mode"": ""Indexed"",
                    ""parameters"": {
                      ""withName"": {
                        ""type"": ""String"",
                        ""metadata"": { ""displayName"": ""With Name"" }
                      },
                      ""withoutName"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": { ""field"": ""type"", ""equals"": ""Microsoft.Storage/storageAccounts"" },
                      ""then"": { ""effect"": ""deny"" }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "parameter-missing-display-name",
                Title: "Parameter Missing Display Name",
                Severity: Severity.Informational,
                Category: Category.Misc,
                LineNumber: 10,
                LinePosition: 38,
                Path: "properties.parameters",
                Description: "The parameter 'withoutName' has no 'displayName' in its metadata, so the portal shows the raw parameter name during assignment. Add a 'metadata.displayName' to give it a friendly label."));
        }
    }
}
