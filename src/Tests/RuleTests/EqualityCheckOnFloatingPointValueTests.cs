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
    /// Tests for the <see cref="EqualityCheckOnFloatingPointValue"/> rule.
    /// </summary>
    public class EqualityCheckOnFloatingPointValueTests
    {
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Fact]
        public void RuleTests_EqualityCheckOnFloatingPointValue_Field()
        {
            const string alias = "Microsoft.Compute/virtualMachines/billingProfile.maxPrice";
            var linter = EqualityCheckOnFloatingPointValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnFloatingPointValueTests.CreatePolicy(
                leftOperand: $@"""field"": ""{alias}""",
                operatorName: "equals",
                operatorValue: @"""5.0""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "equality-check-on-floating-point-value",
                Title: "Equality Check on Floating-Point Value",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 92,
                Path: "properties.policyRule.if.field",
                Description: $"The 'equals' condition compares a floating-point value as text (field alias '{alias}'). Numeric formatting can affect the result. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(@"""value"": ""[parameters('actual')]""", "equals", @"""5.0""", "actual", 12, 57)]
        [InlineData(@"""value"": 5", "notEquals", @"""[parameters('expected')]""", "expected", 13, 63)]
        public void RuleTests_EqualityCheckOnFloatingPointValue_FloatParameter(
            string leftOperand,
            string operatorName,
            string operatorValue,
            string parameterName,
            int lineNumber,
            int linePosition)
        {
            var linter = EqualityCheckOnFloatingPointValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnFloatingPointValueTests.CreatePolicy(
                leftOperand: leftOperand,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName == "equals" ? "equals" : "notEquals";
            var output = new LinterOutput(
                RuleIdentifier: "equality-check-on-floating-point-value",
                Title: "Equality Check on Floating-Point Value",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: "properties.policyRule.if." + (parameterName == "actual" ? "value" : expectedOperator),
                Description: $"The '{expectedOperator}' condition compares a floating-point value as text (parameter '{parameterName}'). Numeric formatting can affect the result. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(@"""value"": 5.0", "equals", @"""5.0""", 36)]
        [InlineData(@"""value"": 5.5", "eQuAlS", @"""5.5""", 36)]
        public void RuleTests_EqualityCheckOnFloatingPointValue_FloatLiteral(
            string leftOperand,
            string operatorName,
            string operatorValue,
            int linePosition)
        {
            var linter = EqualityCheckOnFloatingPointValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnFloatingPointValueTests.CreatePolicy(
                leftOperand: leftOperand,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "equality-check-on-floating-point-value",
                Title: "Equality Check on Floating-Point Value",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: linePosition,
                Path: "properties.policyRule.if.value",
                Description: "The 'equals' condition compares a floating-point value as text (floating-point literal). Numeric formatting can affect the result. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(@"""value"": ""[parameters('integer')]""", "equals", "5")]
        [InlineData(@"""value"": 5", "equals", @"""[parameters('text')]""")]
        [InlineData(@"""value"": 5", "greater", "5.0")]
        [InlineData(@"""value"": ""[add(parameters('actual'), 1)]""", "equals", @"""5.0""")]
        public void RuleTests_EqualityCheckOnFloatingPointValue_NoFinding(
            string leftOperand,
            string operatorName,
            string operatorValue)
        {
            var linter = EqualityCheckOnFloatingPointValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnFloatingPointValueTests.CreatePolicy(
                leftOperand: leftOperand,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_EqualityCheckOnFloatingPointValue_FieldAndParameter_OneFinding()
        {
            var linter = EqualityCheckOnFloatingPointValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnFloatingPointValueTests.CreatePolicy(
                leftOperand: @"""field"": ""Microsoft.Compute/virtualMachines/billingProfile.maxPrice""",
                operatorName: "equals",
                operatorValue: @"""[parameters('expected')]""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);
        }

        private static PolicyLinter CreateLinter()
        {
            return new PolicyLinter(
                rules: new ILinterRule[]
                {
                    new EqualityCheckOnFloatingPointValue(),
                },
                metadata: EqualityCheckOnFloatingPointValueTests.TypeMetadata);
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
                      ""actual"": {{ ""type"": ""Float"" }},
                      ""expected"": {{ ""type"": ""Float"" }},
                      ""integer"": {{ ""type"": ""Integer"" }},
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
