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
    /// Tests for the <see cref="MatchWithoutWildcards"/> rule.
    /// </summary>
    public class MatchWithoutWildcardsTests
    {
        /// <summary>
        /// The type metadata used for the tests.
        /// </summary>
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(metadataProvider: new OfflineMetadataProvider(), aliasResolver: new AliasResolver());

        [Fact]
        void RuleTests_MatchWithoutWildcards_MatchWithoutWildcards_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""match"": ""my-resource-name""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // match is case-sensitive with no case-insensitive equivalent, so no suggestion
            results.Should().BeEmpty();
        }

        [Fact]
        void RuleTests_MatchWithoutWildcards_NotMatchWithoutWildcards_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""notMatch"": ""my-resource-name""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = linter.Lint(policyDefinition);

            // notMatch is case-sensitive with no case-insensitive equivalent, so no suggestion
            results.Should().BeEmpty();
        }

        [Fact]
        void RuleTests_MatchWithoutWildcards_MatchInsensitivelyWithoutPlaceholders()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""matchInsensitively"": ""my-resource-name""
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
                RuleIdentifier: "match-without-wildcards",
                Title: "match/matchInsensitively Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 64,
                Path: "properties.policyRule.if.matchInsensitively",
                Description: "The condition uses the 'matchInsensitively' operator with value 'my-resource-name' which contains no wildcards (#, ?, or .). Use 'equals' instead to better reflect the intention of exact matching.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        void RuleTests_MatchWithoutWildcards_NotMatchInsensitivelyWithoutPlaceholders()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""notMatchInsensitively"": ""my-resource-name""
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
                RuleIdentifier: "match-without-wildcards",
                Title: "match/matchInsensitively Without Wildcards",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 67,
                Path: "properties.policyRule.if.notMatchInsensitively",
                Description: "The condition uses the 'notMatchInsensitively' operator with value 'my-resource-name' which contains no wildcards (#, ?, or .). Use 'notEquals' instead to better reflect the intention of exact matching.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("match", "my-resource-##")]
        [InlineData("match", "my-resource-?ame")]
        [InlineData("match", "my-resource-.ame")]
        [InlineData("matchInsensitively", "resource-##")]
        [InlineData("notMatch", "resource-?ame")]
        [InlineData("notMatchInsensitively", "resource-.")]
        void RuleTests_MatchWithoutWildcards_WithPlaceholders_NoViolation(string operatorName, string operandValue)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""{operatorName}"": ""{operandValue}""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        void RuleTests_MatchWithoutWildcards_ParameterizedValue_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""pattern"": {
                        ""type"": ""String""
                      }
                    },
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""match"": ""[parameters('pattern')]""
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

        [Theory]
        [InlineData("equals")]
        [InlineData("notEquals")]
        [InlineData("like")]
        [InlineData("contains")]
        void RuleTests_MatchWithoutWildcards_OtherOperators_NoViolation(string operatorName)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new MatchWithoutWildcards()
                },
                metadata: TypeMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""{operatorName}"": ""my-resource-name""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }
    }
}
