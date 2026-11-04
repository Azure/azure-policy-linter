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
    /// Tests for the <see cref="InvalidIpRangeContainsFunctionArgument"/> rule.
    /// </summary>
    public class InvalidIpRangeContainsFunctionArgumentTests
    {
        private const string ExpectedDescription =
            "The call {0} fails when the policy is evaluated, because a value is not an IP address or range. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[ipRangeContains('AzureCloud', '10.0.0.1')]", "ipRangeContains('AzureCloud', '10.0.0.1')")]
        public void RuleTests_InvalidIpRangeContainsFunctionArgument_Fires(string valueExpression, string descriptionParameter)
        {
            var results = InvalidIpRangeContainsFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "invalid-iprangecontains-function-argument",
                Title: "Invalid ipRangeContains Function Argument",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(InvalidIpRangeContainsFunctionArgumentTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[ipRangeContains('10.0.0.0/8', '10.0.0.1')]")]
        public void RuleTests_InvalidIpRangeContainsFunctionArgument_NoFinding(string valueExpression)
        {
            var results = InvalidIpRangeContainsFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
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

            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new InvalidIpRangeContainsFunctionArgument() },
                metadata: InvalidIpRangeContainsFunctionArgumentTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}