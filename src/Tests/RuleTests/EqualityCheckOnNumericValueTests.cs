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
    /// Tests for the <see cref="EqualityCheckOnNumericValue"/> rule.
    /// </summary>
    public class EqualityCheckOnNumericValueTests
    {
        private static readonly ITypeMetadata TypeMetadata = new TypeMetadata(
            metadataProvider: new OfflineMetadataProvider(),
            aliasResolver: new AliasResolver());

        [Theory]
        [InlineData("Microsoft.KeyVault/vaults/softDeleteRetentionInDays")]
        [InlineData("Microsoft.Compute/virtualMachines/billingProfile.maxPrice")]
        [InlineData("Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/diffBackupIntervalInHours")]
        public void RuleTests_EqualityCheckOnNumericValue_NumericField(string alias)
        {
            var linter = EqualityCheckOnNumericValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnNumericValueTests.CreatePolicy(
                leftOperand: $@"""field"": ""{alias}""",
                operatorName: "equals",
                operatorValue: @"""5""");

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "equality-check-on-numeric-value",
                Title: "Equality Check on Numeric Value",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 35 + alias.Length,
                Path: "properties.policyRule.if.field",
                Description: $"The 'equals' condition compares a numeric value as text (field alias '{alias}'). Numeric formatting can affect the result. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(@"""value"": ""[parameters('actual')]""", "equals", @"""5.0""", "actual", 12, 57)]
        [InlineData(@"""value"": 5", "notEquals", @"""[parameters('expected')]""", "expected", 13, 63)]
        public void RuleTests_EqualityCheckOnNumericValue_FloatParameter(
            string leftOperand,
            string operatorName,
            string operatorValue,
            string parameterName,
            int lineNumber,
            int linePosition)
        {
            var linter = EqualityCheckOnNumericValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnNumericValueTests.CreatePolicy(
                leftOperand: leftOperand,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var expectedOperator = operatorName == "equals" ? "equals" : "notEquals";
            var output = new LinterOutput(
                RuleIdentifier: "equality-check-on-numeric-value",
                Title: "Equality Check on Numeric Value",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: lineNumber,
                LinePosition: linePosition,
                Path: "properties.policyRule.if." + (parameterName == "actual" ? "value" : expectedOperator),
                Description: $"The '{expectedOperator}' condition compares a numeric value as text (parameter '{parameterName}'). Numeric formatting can affect the result. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(@"""value"": 5.0", "equals", @"""5.0""", 36)]
        [InlineData(@"""value"": 5.5", "eQuAlS", @"""5.5""", 36)]
        public void RuleTests_EqualityCheckOnNumericValue_FloatLiteral(
            string leftOperand,
            string operatorName,
            string operatorValue,
            int linePosition)
        {
            var linter = EqualityCheckOnNumericValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnNumericValueTests.CreatePolicy(
                leftOperand: leftOperand,
                operatorName: operatorName,
                operatorValue: operatorValue);

            var results = linter.Lint(policyDefinition);

            results.Should().HaveCount(1);

            var output = new LinterOutput(
                RuleIdentifier: "equality-check-on-numeric-value",
                Title: "Equality Check on Numeric Value",
                Severity: Severity.Informational,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: linePosition,
                Path: "properties.policyRule.if.value",
                Description: "The 'equals' condition compares a numeric value as text (floating-point literal). Numeric formatting can affect the result. Use the 'equals()' function in a 'value' condition for numeric equality.");

            results.Should().ContainEquivalentOf(output);
        }

        [Theory]
        [InlineData(@"""value"": ""[parameters('integer')]""", "equals", "5")]
        [InlineData(@"""value"": 5", "equals", @"""[parameters('text')]""")]
        [InlineData(@"""value"": 5", "greater", "5.0")]
        [InlineData(@"""value"": ""[add(parameters('actual'), 1)]""", "equals", @"""5.0""")]
        [InlineData(@"""field"": ""Microsoft.Storage/storageAccounts/sku.name""", "equals", @"""5""")]
        public void RuleTests_EqualityCheckOnNumericValue_NoFinding(
            string leftOperand,
            string operatorName,
            string operatorValue)
        {
            var linter = EqualityCheckOnNumericValueTests.CreateLinter();
            var policyDefinition = EqualityCheckOnNumericValueTests.CreatePolicy(
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
                    new EqualityCheckOnNumericValue(),
                },
                metadata: EqualityCheckOnNumericValueTests.TypeMetadata);
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
