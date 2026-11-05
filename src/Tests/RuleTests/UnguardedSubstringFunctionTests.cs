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
            "The expression calls 'substring()' on a value that is known only when the policy is evaluated. When the value is shorter than the requested range the expression fails, and a failed expression makes the policy deny the request. Use 'take()' and 'skip()' instead; they don't fail on short values.";

        /// <summary>
        /// The mock type metadata used for the tests.
        /// </summary>
        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[substring(field('name'), 0, 3)]")]
        [InlineData("[SuBsTrInG(FiElD('name'), 0, 3)]")]
        [InlineData("[substring(field('name'), 2, 0)]")]
        [InlineData("[substring(field('name'), 0)]")]
        [InlineData("[substring(field('name'), 0, parameters('length'))]")]
        [InlineData("[toLower(substring(field('name'), 0, 3))]")]
        [InlineData("[concat(substring(field('name'), 0, 3), 'suffix')]")]
        [InlineData("[if(equals(substring(field('name'), 0, 3), 'abc'), 'a', 'b')]")]
        public void RuleTests_UnguardedSubstringFunction_EvaluationTimeInput_Fires(string valueExpression)
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
        [InlineData("[substring(parameters('name'), 0, 3)]")]
        [InlineData("[substring(concat(field('name'), '---'), 0, 3)]")]
        [InlineData("prefix-[substring(field('name'), 0, 3)]")]
        [InlineData("[take(skip(field('name'), 2), 3)]")]
        public void RuleTests_UnguardedSubstringFunction_NotApplicable(string valueExpression)
        {
            var results = UnguardedSubstringFunctionTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("[if(greaterOrEquals(length(field('name')), 3), substring(field('name'), 0, 3), field('name'))]")]
        [InlineData("[if(equals(field('type'), 'x'), '', toLower(substring(field('name'), 0, 3)))]")]
        public void RuleTests_UnguardedSubstringFunction_InIfBranch_Warning(string valueExpression)
        {
            var results = UnguardedSubstringFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(UnguardedSubstringFunctionTests.CreateExpectedOutput(
                lineNumber: 6,
                linePosition: 35 + valueExpression.Length,
                severity: Severity.Warning));
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
            string path = "properties.policyRule.if.value",
            Severity severity = Severity.Error)
        {
            return new LinterOutput(
                RuleIdentifier: "unguarded-substring-function",
                Title: "Unguarded Substring Function",
                Severity: severity,
                Category: Category.TemplateFunctions,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: path,
                Description: UnguardedSubstringFunctionTests.ExpectedDescription);
        }
    }
}
