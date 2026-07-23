namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="LiteralAsteriskInMatchOperator"/> rule.
    /// </summary>
    public class LiteralAsteriskInMatchOperatorTests
    {
        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("match", "resource-*", "like", 45)]
        [InlineData("notMatch", "resource-*", "notLike", 48)]
        [InlineData("matchInsensitively", "resource-*", "like", 58)]
        [InlineData("notMatchInsensitively", "resource-*", "notLike", 61)]
        public void RuleTests_LiteralAsteriskInMatchOperator_MatchFamilyOperatorWithEmbeddedAsterisk(
            string operatorName,
            string operandValue,
            string replacement,
            int linePosition)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LiteralAsteriskInMatchOperator()
                },
                metadata: MockMetadata);

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

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "literal-asterisk-in-match-operator",
                Title: "Literal Asterisk in Match Operator",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: linePosition,
                Path: $"properties.policyRule.if.{operatorName}",
                Description: $"The condition uses the '{operatorName}' operator with value '{operandValue}'. Match operators treat '*' literally; supported placeholders are '#' for digits, '?' for letters, and '.' for any character. Keep '*' for a literal asterisk. Otherwise, use the supported placeholders or consider '{replacement}', whose wildcard syntax is different.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_LiteralAsteriskInMatchOperator_ExactlyAsterisk()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LiteralAsteriskInMatchOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""match"": ""*""
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
                RuleIdentifier: "literal-asterisk-in-match-operator",
                Title: "Literal Asterisk in Match Operator",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 36,
                Path: "properties.policyRule.if.match",
                Description: "The condition uses the 'match' operator with value '*'. Match operators treat '*' literally; supported placeholders are '#' for digits, '?' for letters, and '.' for any character. Keep '*' for a literal asterisk. Otherwise, use the supported placeholders or consider 'like', whose wildcard syntax is different.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_LiteralAsteriskInMatchOperator_PropertyNameIsCaseInsensitive()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LiteralAsteriskInMatchOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""MATCH"": ""resource-*""
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
                RuleIdentifier: "literal-asterisk-in-match-operator",
                Title: "Literal Asterisk in Match Operator",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 7,
                LinePosition: 45,
                Path: "properties.policyRule.if.match",
                Description: "The condition uses the 'match' operator with value 'resource-*'. Match operators treat '*' literally; supported placeholders are '#' for digits, '?' for letters, and '.' for any character. Keep '*' for a literal asterisk. Otherwise, use the supported placeholders or consider 'like', whose wildcard syntax is different.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("match")]
        [InlineData("notMatch")]
        [InlineData("matchInsensitively")]
        [InlineData("notMatchInsensitively")]
        public void RuleTests_LiteralAsteriskInMatchOperator_ValueWithoutAsterisk_NoViolation(string operatorName)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LiteralAsteriskInMatchOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""{operatorName}"": ""resource-name""
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

        [Theory]
        [InlineData("like")]
        [InlineData("notLike")]
        public void RuleTests_LiteralAsteriskInMatchOperator_LikeOperator_NoViolation(string operatorName)
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LiteralAsteriskInMatchOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""{operatorName}"": ""resource-*""
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
        public void RuleTests_LiteralAsteriskInMatchOperator_ParameterizedValue_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LiteralAsteriskInMatchOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""parameters"": {
                      ""pattern"": {
                        ""type"": ""String"",
                        ""defaultValue"": ""*""
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

        [Fact]
        public void RuleTests_LiteralAsteriskInMatchOperator_NonStringLiteral_NoViolation()
        {
            var linter = new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LiteralAsteriskInMatchOperator()
                },
                metadata: MockMetadata);

            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""match"": 1
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
    }
}
