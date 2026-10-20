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
    /// Tests for the <see cref="NonScalarParameterInEqualityCondition"/> rule.
    /// </summary>
    public class NonScalarParameterInEqualityConditionTests
    {
        [Theory]
        [InlineData("equals", "Array", "values")]
        [InlineData("notEquals", "Object", "settings")]
        [InlineData("eQuAlS", "aRrAy", "values")]
        public void RuleTests_NonScalarParameterInEqualityCondition_NonScalarParameter(
            string operatorName,
            string parameterType,
            string parameterName)
        {
            var linter = NonScalarParameterInEqualityConditionTests.CreateLinter();
            var policyDefinition = NonScalarParameterInEqualityConditionTests.CreatePolicy(
                operatorName: operatorName,
                operatorValue: $"\"[parameters('{parameterName}')]\"",
                parameterName: parameterName,
                parameterType: parameterType);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName.Equals("notEquals", System.StringComparison.OrdinalIgnoreCase)
                ? "notEquals"
                : "equals";
            var output = new LinterOutput(
                RuleIdentifier: "non-scalar-parameter-in-equality-condition",
                Title: "Non-Scalar Parameter in Equality Condition",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: expectedOperator == "equals" ? 58 : 63,
                Description: $"The '{expectedOperator}' condition uses parameter '{parameterName}' of type '{parameterType}' as its comparison value. Equality conditions require a scalar value. Use 'in' or 'notIn' for an array, or the 'equals()' function in a 'value' condition for complete-value equality.",
                Path: "properties.policyRule.if." + expectedOperator);

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("String")]
        [InlineData("Integer")]
        [InlineData("Float")]
        [InlineData("Boolean")]
        [InlineData("DateTime")]
        public void RuleTests_NonScalarParameterInEqualityCondition_ScalarParameter(string parameterType)
        {
            var linter = NonScalarParameterInEqualityConditionTests.CreateLinter();
            var policyDefinition = NonScalarParameterInEqualityConditionTests.CreatePolicy(
                operatorName: "equals",
                operatorValue: "\"[parameters('value')]\"",
                parameterName: "value",
                parameterType: parameterType);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("\"[first(parameters('values'))]\"")]
        [InlineData("\"[parameters('missing')]\"")]
        [InlineData("\"literal\"")]
        public void RuleTests_NonScalarParameterInEqualityCondition_OtherValue(string operatorValue)
        {
            var linter = NonScalarParameterInEqualityConditionTests.CreateLinter();
            var policyDefinition = NonScalarParameterInEqualityConditionTests.CreatePolicy(
                operatorName: "equals",
                operatorValue: operatorValue,
                parameterName: "values",
                parameterType: "Array");

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_NonScalarParameterInEqualityCondition_OtherOperator()
        {
            var linter = NonScalarParameterInEqualityConditionTests.CreateLinter();
            var policyDefinition = NonScalarParameterInEqualityConditionTests.CreatePolicy(
                operatorName: "in",
                operatorValue: "\"[parameters('values')]\"",
                parameterName: "values",
                parameterType: "Array");

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new NonScalarParameterInEqualityCondition(),
                },
                metadata: new MockTypeMetadata());
        }

        private static string CreatePolicy(
            string operatorName,
            string operatorValue,
            string parameterName,
            string parameterType)
        {
            return $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""{parameterName}"": {{
                        ""type"": ""{parameterType}""
                      }}
                    }},
                    ""policyRule"": {{
                      ""if"": {{
                        ""field"": ""name"",
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
