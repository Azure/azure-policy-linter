// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using FluentAssertions;
    using global::Azure.Deployments.ResourceMetadata.Offline;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="NumericFieldOrValueInEqualityCondition"/> rule.
    /// </summary>
    public class NumericFieldOrValueInEqualityConditionTests
    {
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Theory]
        [InlineData("Microsoft.KeyVault/vaults/softDeleteRetentionInDays")]
        [InlineData("Microsoft.Compute/virtualMachines/billingProfile.maxPrice")]
        public void RuleTests_NumericFieldOrValueInEqualityCondition_NumericField(string alias)
        {
            var linter = NumericFieldOrValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericFieldOrValueInEqualityConditionTests.CreatePolicy(
                leftOperand: $@"""field"": ""{alias}""",
                operatorName: "equals",
                operatorValue: @"""5""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "numeric-field-or-value-in-equality-condition",
                Title: "Numeric Field or Value in Equality Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: 35 + alias.Length,
                Path: "properties.policyRule.if.field",
                Description: $"The 'equals' condition converts field alias '{alias}' to a string before comparison. Numerically equal values with different string representations can compare as unequal. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("integer", "equals", 58)]
        [InlineData("floatingPoint", "notEquals", 64)]
        public void RuleTests_NumericFieldOrValueInEqualityCondition_NumericParameter(
            string parameterName,
            string operatorName,
            int linePosition)
        {
            var linter = NumericFieldOrValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericFieldOrValueInEqualityConditionTests.CreatePolicy(
                leftOperand: $@"""value"": ""[parameters('{parameterName}')]""",
                operatorName: operatorName,
                operatorValue: @"""5""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName == "equals" ? "equals" : "notEquals";
            var output = new LinterOutput(
                RuleIdentifier: "numeric-field-or-value-in-equality-condition",
                Title: "Numeric Field or Value in Equality Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: linePosition,
                Path: "properties.policyRule.if.value",
                Description: $"The '{expectedOperator}' condition converts value parameter '{parameterName}' to a string before comparison. Numerically equal values with different string representations can compare as unequal. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData("5", "equals", "Integer")]
        [InlineData("5.0", "nOtEqUaLs", "Float")]
        public void RuleTests_NumericFieldOrValueInEqualityCondition_NumericLiteral(
            string value,
            string operatorName,
            string expectedType)
        {
            var linter = NumericFieldOrValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericFieldOrValueInEqualityConditionTests.CreatePolicy(
                leftOperand: $@"""value"": {value}",
                operatorName: operatorName,
                operatorValue: @"""5""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName.Equals("equals", System.StringComparison.OrdinalIgnoreCase)
                ? "equals"
                : "notEquals";
            var linePosition = expectedType == "Integer" ? 34 : 36;
            var output = new LinterOutput(
                RuleIdentifier: "numeric-field-or-value-in-equality-condition",
                Title: "Numeric Field or Value in Equality Condition",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 11,
                LinePosition: linePosition,
                Path: "properties.policyRule.if.value",
                Description: $"The '{expectedOperator}' condition converts the numeric value to a string before comparison. Numerically equal values with different string representations can compare as unequal. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(@"""value"": ""text""", "equals", @"""text""")]
        [InlineData(@"""value"": ""[parameters('text')]""", "equals", @"""text""")]
        [InlineData(@"""value"": ""[parameters('integer')]""", "greater", "5")]
        [InlineData(@"""value"": ""[add(parameters('integer'), 1)]""", "equals", @"""5""")]
        [InlineData(@"""field"": ""Microsoft.Storage/storageAccounts/sku.name""", "equals", @"""5""")]
        public void RuleTests_NumericFieldOrValueInEqualityCondition_NoFinding(
            string leftOperand,
            string operatorName,
            string operatorValue)
        {
            var linter = NumericFieldOrValueInEqualityConditionTests.CreateLinter();
            var policyDefinition = NumericFieldOrValueInEqualityConditionTests.CreatePolicy(
                leftOperand: leftOperand,
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
                    new NumericFieldOrValueInEqualityCondition(),
                },
                metadata: NumericFieldOrValueInEqualityConditionTests.TypeMetadata);
        }

        private static string CreatePolicy(
            string leftOperand,
            string operatorName,
            string operatorValue)
        {
            return $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""integer"": {{ ""type"": ""Integer"" }},
                      ""floatingPoint"": {{ ""type"": ""Float"" }},
                      ""text"": {{ ""type"": ""String"" }}
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
