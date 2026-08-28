namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="MissingPolicyDefinitionDescription"/> rule.
    /// </summary>
    public class MissingPolicyDefinitionDescriptionTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDescription_Absent()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDescription()
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
                RuleIdentifier: "missing-policy-definition-description",
                Title: "Missing Policy Definition Description",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 3,
                LinePosition: 33,
                Path: "properties",
                Description: "The policy definition does not specify a nonblank 'description', so context for when it is used is missing. Add a concise description of what the policy checks and why."));
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDescription_Empty()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDescription()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""description"": """",
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
                RuleIdentifier: "missing-policy-definition-description",
                Title: "Missing Policy Definition Description",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 4,
                LinePosition: 37,
                Path: "properties.description",
                Description: "The policy definition does not specify a nonblank 'description', so context for when it is used is missing. Add a concise description of what the policy checks and why."));
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDescription_Whitespace()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDescription()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""description"": ""   "",
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
                RuleIdentifier: "missing-policy-definition-description",
                Title: "Missing Policy Definition Description",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 4,
                LinePosition: 40,
                Path: "properties.description",
                Description: "The policy definition does not specify a nonblank 'description', so context for when it is used is missing. Add a concise description of what the policy checks and why."));
        }

        [Fact]
        public void RuleTests_MissingPolicyDefinitionDescription_Nonblank()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDescription()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""description"": ""Audits storage accounts without secure transfer enabled."",
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
        public void RuleTests_MissingPolicyDefinitionDescription_NonblankWithSurroundingWhitespace()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDescription()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""description"": ""  Audits storage accounts without secure transfer enabled.  "",
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
        public void RuleTests_MissingPolicyDefinitionDescription_PropertyNameCasing()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MissingPolicyDefinitionDescription()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""Description"": ""Audits storage accounts without secure transfer enabled."",
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
