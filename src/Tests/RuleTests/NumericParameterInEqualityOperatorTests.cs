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
    /// Tests for the <see cref="NumericParameterInEqualityOperator"/> rule.
    /// </summary>
    public class NumericParameterInEqualityOperatorTests
    {
        [Theory]
        [InlineData("Integer", "integer", "equals", 59)]
        [InlineData("Float", "floatingPoint", "notEquals", 68)]
        [InlineData("iNtEgEr", "integer", "eQuAlS", 59)]
        public void RuleTests_NumericParameterInEqualityOperator_NumericParameter(
            string parameterType,
            string parameterName,
            string operatorName,
            int linePosition)
        {
            var linter = NumericParameterInEqualityOperatorTests.CreateLinter();
            var policyDefinition = NumericParameterInEqualityOperatorTests.CreatePolicy(
                leftOperand: @"""value"": ""[field('tags.expectedValue')]""",
                operatorName: operatorName,
                operatorValue: $@"""[parameters('{parameterName}')]""",
                parameterType: parameterType);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName.Equals("equals", System.StringComparison.OrdinalIgnoreCase)
                ? "equals"
                : "notEquals";
            var output = new LinterOutput(
                RuleIdentifier: "numeric-parameter-in-equality-operator",
                Title: "Numeric Parameter in Equality Operator",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: linePosition,
                Path: "properties.policyRule.if." + expectedOperator,
                Description: $"The '{expectedOperator}' operator converts numeric parameter '{parameterName}' to a string before it compares the values, so the number 5 equals the string '5'. To also compare the value types, use the 'equals()' template function in a 'value' condition.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("String")]
        [InlineData("Boolean")]
        [InlineData("DateTime")]
        public void RuleTests_NumericParameterInEqualityOperator_NonNumericParameter(string parameterType)
        {
            var linter = NumericParameterInEqualityOperatorTests.CreateLinter();
            var policyDefinition = NumericParameterInEqualityOperatorTests.CreatePolicy(
                leftOperand: @"""value"": ""[field('tags.expectedValue')]""",
                operatorName: "equals",
                operatorValue: @"""[parameters('value')]""",
                parameterType: parameterType);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NumericParameterInEqualityOperator_NumericLeftSide_NoFinding()
        {
            var linter = NumericParameterInEqualityOperatorTests.CreateLinter();
            var policyDefinition = NumericParameterInEqualityOperatorTests.CreatePolicy(
                leftOperand: @"""value"": 5",
                operatorName: "equals",
                operatorValue: @"""[parameters('integer')]""",
                parameterType: "Integer");

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NumericParameterInEqualityOperator_ComputedValue_NoFinding()
        {
            var linter = NumericParameterInEqualityOperatorTests.CreateLinter();
            var policyDefinition = NumericParameterInEqualityOperatorTests.CreatePolicy(
                leftOperand: @"""value"": ""[field('tags.expectedValue')]""",
                operatorName: "equals",
                operatorValue: @"""[add(parameters('integer'), 1)]""",
                parameterType: "Integer");

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NumericParameterInEqualityOperator(),
                },
                metadata: new MockTypeMetadata());
        }

        private static string CreatePolicy(
            string leftOperand,
            string operatorName,
            string operatorValue,
            string parameterType)
        {
            return $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""integer"": {{ ""type"": ""{parameterType}"" }},
                      ""floatingPoint"": {{ ""type"": ""{parameterType}"" }},
                      ""value"": {{ ""type"": ""{parameterType}"" }}
                    }},
                    ""policyRule"": {{
                      ""if"": {{
                        {leftOperand},
                        ""{operatorName}"": {operatorValue}
                      }},
                      ""then"": {{
                        ""effect"": ""audit""
                      }}
                    }}
                  }}
                }}";
        }
    }
}
