// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="UnguardedSubstringFunction"/> rule.
    /// </summary>
    public class UnguardedSubstringFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'substring' on a value that is not a literal, without checking its length first. When the value is shorter than the requested range the expression fails, and a failed expression makes the policy deny the request. Guard the call with 'if()' and 'length()'.";

        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[substring(field('name'), 0, 3)]")]
        [InlineData("[SuBsTrInG(field('name'), 0, 3)]")]
        [InlineData("[substring(parameters('name'), 0, 3)]")]
        [InlineData("[substring(field('name'), 2, 0)]")]
        [InlineData("[substring(field('name'), 0)]")]
        [InlineData("[substring(field('name'), 0, parameters('length'))]")]
        public void RuleTests_UnguardedSubstringFunction_NonLiteralInput_Fires(string valueExpression)
        {
            var results = UnguardedSubstringFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(UnguardedSubstringFunctionTests.CreateExpectedOutput(
                lineNumber: 6,
                linePosition: 35 + valueExpression.Length));
        }

        [Fact]
        public void RuleTests_UnguardedSubstringFunction_OperatorExpression()
        {
            const string operatorExpression = "[substring(field('name'), 0, 3)]";
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
                        ""equals"": ""{operatorExpression}""
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var results = UnguardedSubstringFunctionTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(UnguardedSubstringFunctionTests.CreateExpectedOutput(
                lineNumber: 7,
                linePosition: 36 + operatorExpression.Length,
                path: "properties.policyRule.if.equals"));
        }

        [Fact]
        public void RuleTests_UnguardedSubstringFunction_CurrentReferenceInFieldCount()
        {
            const string valueExpression = "[substring(current('Microsoft.Test/widgets/items[*].name'), 0, 3)]";
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""policyRule"": {{
                      ""if"": {{
                        ""count"": {{
                          ""field"": ""Microsoft.Test/widgets/items[*]"",
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

            var results = UnguardedSubstringFunctionTests.CreateLinter().Lint(policyDefinition);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(UnguardedSubstringFunctionTests.CreateExpectedOutput(
                lineNumber: 9,
                linePosition: 39 + valueExpression.Length,
                path: "properties.policyRule.if.count.where.value"));
        }

        [Theory]
        [InlineData("[substring('abcdef', 0, 3)]")]
        [InlineData("[length(field('name'))]")]
        [InlineData("prefix-[substring(field('name'), 0, 3)]")]
        public void RuleTests_UnguardedSubstringFunction_NotApplicable(string valueExpression)
        {
            var results = UnguardedSubstringFunctionTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedSubstringFunction_GuardedWithIf_NoFinding()
        {
            var results = UnguardedSubstringFunctionTests.LintValueExpression(
                "[if(greaterOrEquals(length(field('name')), 3), substring(field('name'), 0, 3), field('name'))]");

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("[toLower(substring(field('name'), 0, 3))]")]
        [InlineData("[concat(substring(field('name'), 0, 3), 'suffix')]")]
        public void RuleTests_UnguardedSubstringFunction_NestedInsideAnotherFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedSubstringFunctionTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_UnguardedSubstringFunction_FieldCondition_NoFinding()
        {
            var policyDefinition = @"
                {
                  ""properties"": {
                    ""policyRule"": {
                      ""if"": {
                        ""field"": ""name"",
                        ""equals"": ""abc""
                      },
                      ""then"": {
                        ""effect"": ""deny""
                      }
                    }
                  }
                }";

            var results = UnguardedSubstringFunctionTests.CreateLinter().Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new UnguardedSubstringFunction()
                },
                metadata: UnguardedSubstringFunctionTests.MockMetadata);
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
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

            return UnguardedSubstringFunctionTests.CreateLinter().Lint(policyDefinition);
        }

        private static LinterOutput CreateExpectedOutput(
            int lineNumber,
            int linePosition,
            string path = "properties.policyRule.if.value")
        {
            return new LinterOutput(
                RuleIdentifier: "unguarded-substring-function",
                Title: "Unguarded Substring Function",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: path,
                Description: UnguardedSubstringFunctionTests.ExpectedDescription);
        }
    }
}
