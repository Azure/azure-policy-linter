namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="UnguardedSubstringOnResourceValue"/> rule.
    /// </summary>
    public class UnguardedSubstringOnResourceValueTests
    {
        private const string ExpectedDescription =
            "The value expression calls 'substring' directly on a resource value. If the value is shorter than the requested substring, policy evaluation fails and the policy acts as deny. Guard the call with 'if()' and 'length()'.";

        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Fact]
        public void RuleTests_UnguardedSubstringOnResourceValue_DirectFieldReference()
        {
            const string valueExpression = "[substring(field('name'), 0, 3)]";
            var results = LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateExpectedOutput(
                lineNumber: 6,
                linePosition: 35 + valueExpression.Length));
        }

        [Fact]
        public void RuleTests_UnguardedSubstringOnResourceValue_MixedFunctionCasing()
        {
            const string valueExpression = "[SuBsTrInG(FiElD('name'), 0, 3)]";
            var results = LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateExpectedOutput(
                lineNumber: 6,
                linePosition: 35 + valueExpression.Length));
        }

        [Fact]
        public void RuleTests_UnguardedSubstringOnResourceValue_TransitiveFieldReference()
        {
            const string valueExpression = "[substring(toLower(field('name')), 0, 3)]";
            var results = LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateExpectedOutput(
                lineNumber: 6,
                linePosition: 35 + valueExpression.Length));
        }

        [Fact]
        public void RuleTests_UnguardedSubstringOnResourceValue_PositiveStartWithZeroLength()
        {
            const string valueExpression = "[substring(field('name'), 2, 0)]";
            var results = LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateExpectedOutput(
                lineNumber: 6,
                linePosition: 35 + valueExpression.Length));
        }

        [Fact]
        public void RuleTests_UnguardedSubstringOnResourceValue_CurrentReferenceInValueCount()
        {
            const string valueExpression = "[substring(current('item'), 0, 3)]";
            var linter = CreateLinter();
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""count"": {{
                          ""value"": [""abc""],
                          ""name"": ""item"",
                          ""where"": {{
                            ""value"": ""{valueExpression}"",
                            ""equals"": ""abc""
                          }}
                        }},
                        ""greater"": 0
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(CreateExpectedOutput(
                lineNumber: 10,
                linePosition: 39 + valueExpression.Length,
                path: "properties.policyRule.if.count.where.value"));
        }

        [Theory]
        [InlineData("[if(greaterOrEquals(length(field('name')), 3), substring(field('name'), 0, 3), field('name'))]")]
        [InlineData("[substring('abcdef', 0, 3)]")]
        [InlineData("[substring(parameters('name'), 0, 3)]")]
        [InlineData("[toLower(substring(field('name'), 0, 3))]")]
        [InlineData("[substring(field('name'), 0)]")]
        [InlineData("[substring(field('name'), 0, parameters('length'))]")]
        [InlineData("[substring(field('name'), -1, 3)]")]
        [InlineData("[substring(field('name'), 0, '3')]")]
        [InlineData("[substring(field('name'), 0, 0)]")]
        [InlineData("[length(field('name'))]")]
        public void RuleTests_UnguardedSubstringOnResourceValue_NotApplicable(string valueExpression)
        {
            var results = LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedSubstringOnResourceValue_ExpressionIsOnlyPartOfRawValue()
        {
            var results = LintValueExpression("prefix-[substring(field('name'), 0, 3)]");

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedSubstringOnResourceValue()
                },
                metadata: MockMetadata);
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var linter = CreateLinter();
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""value"": ""{valueExpression}"",
                        ""equals"": ""abc""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            return linter.Lint(policyDefinition);
        }

        private static LinterOutput CreateExpectedOutput(
            int lineNumber,
            int linePosition,
            string path = "properties.policyRule.if.value")
        {
            return new LinterOutput(
                RuleIdentifier: "unguarded-substring-on-resource-value",
                Title: "Unguarded Substring on Resource Value",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: path,
                Description: ExpectedDescription);
        }
    }
}
