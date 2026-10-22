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
    /// Tests for the <see cref="NumericComparisonValueInEqualityCondition"/> rule.
    /// </summary>
    public class NumericComparisonValueInEqualityConditionTests
    {
        [Theory]
        [InlineData("Integer", "integer", "equals", 59)]
        [InlineData("Float", "floatingPoint", "notEquals", 68)]
        [InlineData("iNtEgEr", "integer", "eQuAlS", 59)]
        public void RuleTests_NumericComparisonValueInEqualityCondition_NumericParameter(
            string parameterType,
            string parameterName,
            string operatorName,
            int linePosition)
        {
            var linter = NumericComparisonValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericComparisonValueInEqualityConditionTests.CreatePolicy(
                leftOperand: @"""value"": ""05""",
                operatorName: operatorName,
                operatorValue: $@"""[parameters('{parameterName}')]""",
                parameterType: parameterType);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName.Equals("equals", System.StringComparison.OrdinalIgnoreCase)
                ? "equals"
                : "notEquals";
            var output = new LinterOutput(
                RuleIdentifier: "numeric-comparison-value-in-equality-condition",
                Title: "Numeric Comparison Value in Equality Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: linePosition,
                Path: "properties.policyRule.if." + expectedOperator,
                Description: $"The '{expectedOperator}' condition converts comparison parameter '{parameterName}' of type '{parameterType}' to a string. Numerically equal values with different string representations can compare as unequal. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("String")]
        [InlineData("Boolean")]
        [InlineData("DateTime")]
        public void RuleTests_NumericComparisonValueInEqualityCondition_NonNumericParameter(string parameterType)
        {
            var linter = NumericComparisonValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericComparisonValueInEqualityConditionTests.CreatePolicy(
                leftOperand: @"""value"": ""05""",
                operatorName: "equals",
                operatorValue: @"""[parameters('value')]""",
                parameterType: parameterType);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NumericComparisonValueInEqualityCondition_NumericLeftSide_NoFinding()
        {
            var linter = NumericComparisonValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericComparisonValueInEqualityConditionTests.CreatePolicy(
                leftOperand: @"""value"": 5",
                operatorName: "equals",
                operatorValue: @"""[parameters('integer')]""",
                parameterType: "Integer");

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NumericComparisonValueInEqualityCondition_ComputedValue_NoFinding()
        {
            var linter = NumericComparisonValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericComparisonValueInEqualityConditionTests.CreatePolicy(
                leftOperand: @"""value"": ""05""",
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
                    new NumericComparisonValueInEqualityCondition(),
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
