namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="MissingPolicyDefinitionDisplayName"/> rule.
    /// </summary>
    public class MissingPolicyDefinitionDisplayNameTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDisplayName_Absent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "missing-policy-definition-display-name",
                Title: "Missing Policy Definition Display Name",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 3,
                LinePosition: 33,
                Path: "properties",
                Description: "The policy definition does not specify a nonblank 'displayName'. Add a concise display name that identifies the definition and distinguishes it from other policies."));
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDisplayName_Empty()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""displayName"": """",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "missing-policy-definition-display-name",
                Title: "Missing Policy Definition Display Name",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 4,
                LinePosition: 37,
                Path: "properties.displayName",
                Description: "The policy definition does not specify a nonblank 'displayName'. Add a concise display name that identifies the definition and distinguishes it from other policies."));
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDisplayName_Whitespace()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""displayName"": ""   "",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "missing-policy-definition-display-name",
                Title: "Missing Policy Definition Display Name",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 4,
                LinePosition: 40,
                Path: "properties.displayName",
                Description: "The policy definition does not specify a nonblank 'displayName'. Add a concise display name that identifies the definition and distinguishes it from other policies."));
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDisplayName_Nonblank()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""displayName"": ""Audit storage accounts"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDisplayName_NonblankWithSurroundingWhitespace()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""displayName"": ""  Audit storage accounts  "",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDisplayName_PropertyNameCasing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDisplayName()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""DisplayName"": ""Audit storage accounts"",
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""type"",
                        ""equals"": ""Microsoft.Storage/storageAccounts""
                      },
                      ""then"": {
                        ""effect"": ""audit""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
