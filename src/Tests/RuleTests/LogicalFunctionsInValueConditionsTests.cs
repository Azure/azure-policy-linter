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
    /// Tests for the <see cref="LogicalFunctionsInValueConditions"/> rule.
    /// </summary>
    public class LogicalFunctionsInValueConditionsTests
    {
        [Theory]
        [InlineData("and", "[and(equals(field('name'), 'a'), equals(field('type'), 'Contoso/widgets'))]")]
        [InlineData("or", "[or(equals(field('name'), 'a'), equals(field('name'), 'b'))]")]
        [InlineData("not", "[not(equals(field('name'), 'a'))]")]
        [InlineData("if", "[if(equals(field('name'), 'a'), true(), false())]")]
        [InlineData("AnD", "[AnD(equals(field('name'), 'a'), equals(field('type'), 'Contoso/widgets'))]")]
        public void RuleTests_LogicalFunctionsInValueConditions_LogicalFunction(
            string expectedFunction,
            string valueExpression)
        {
            var linter = LogicalFunctionsInValueConditionsTests.CreateLinter();
            var policyDefinition = LogicalFunctionsInValueConditionsTests.CreatePolicy(
                valueExpression: valueExpression,
                operatorName: "equals",
                operatorValue: "true");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "logical-functions-in-value-conditions",
                Title: "Logical Functions in Value Conditions",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 35 + valueExpression.Length,
                Path: "properties.policyRule.if.value",
                Description: $"The value condition combines field checks with the '{expectedFunction}()' function, so compliance details show only the expression's final result. Use native policy conditions when they preserve the expression's behavior.");

            results.Should().ContainEquivalentOf(output);
        }

        [Fact]
        public void RuleTests_LogicalFunctionsInValueConditions_NotEqualsFalse()
        {
            var linter = LogicalFunctionsInValueConditionsTests.CreateLinter();
            var policyDefinition = LogicalFunctionsInValueConditionsTests.CreatePolicy(
                valueExpression: "[or(equals(field('name'), 'a'), equals(field('name'), 'b'))]",
                operatorName: "notEquals",
                operatorValue: "false");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
        }

        [Theory]
        [InlineData("[equals(field('name'), 'a')]", "equals", "true")]
        [InlineData("[and(true(), false())]", "equals", "true")]
        [InlineData("[concat(field('name'), '-suffix')]", "equals", "\"a-suffix\"")]
        [InlineData("[and(equals(field('name'), 'a'), true())]", "greater", "0")]
        [InlineData("[parameters('condition')]", "equals", "true")]
        public void RuleTests_LogicalFunctionsInValueConditions_NoFinding(
            string valueExpression,
            string operatorName,
            string operatorValue)
        {
            var linter = LogicalFunctionsInValueConditionsTests.CreateLinter();
            var policyDefinition = LogicalFunctionsInValueConditionsTests.CreatePolicy(
                valueExpression: valueExpression,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new LogicalFunctionsInValueConditions(),
                },
                metadata: new MockTypeMetadata());
        }

        private static string CreatePolicy(
            string valueExpression,
            string operatorName,
            string operatorValue)
        {
            return $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""condition"": {{ ""type"": ""Boolean"" }}
                    }},
                    ""policyRule"": {{
                      ""if"": {{
                        ""value"": ""{valueExpression}"",
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
