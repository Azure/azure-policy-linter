// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Linq;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.CommonRules;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Xunit;

    /// <summary>
    /// Tests for the <see cref="InvalidIntFunctionArgument"/> rule.
    /// </summary>
    public class InvalidIntFunctionArgumentTests
    {
        private const string ExpectedDescription =
            "The call {0} fails when the policy is evaluated, because the value is not an integer. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[int('ten')]", "int('ten')")]
        [InlineData("[int(parameters('textParam'))]", "int('ten')")]
        public void RuleTests_InvalidIntFunctionArgument_Fires(string valueExpression, string descriptionParameter)
        {
            var results = InvalidIntFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "invalid-int-function-argument",
                Title: "Invalid Int Function Argument",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 10,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(InvalidIntFunctionArgumentTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[int('5')]")]
        [InlineData("[int(field('tags[a]'))]")]
        [InlineData("[int(parameters('noValuesParam'))]")]
        [InlineData("[if(equals(parameters('textParam'), 'ten'), 0, int(parameters('textParam')))]")]
        public void RuleTests_InvalidIntFunctionArgument_NoFinding(string valueExpression)
        {
            var results = InvalidIntFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        [Fact]
        public void RuleTests_InvalidIntFunctionArgument_OneFindingPerFailingValue()
        {
            var results = InvalidIntFunctionArgumentTests.LintValueExpression("[int(concat(parameters('textParam'), 'x'))]");

            results.Should().HaveCount(2);
            results.Select(result => result.Description).Should().BeEquivalentTo(
                string.Format(InvalidIntFunctionArgumentTests.ExpectedDescription, "int('1x')"),
                string.Format(InvalidIntFunctionArgumentTests.ExpectedDescription, "int('tenx')"));
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""textParam"": {{ ""type"": ""String"", ""allowedValues"": [ ""1"", ""ten"" ], ""defaultValue"": ""1"" }},
                      ""noValuesParam"": {{ ""type"": ""String"" }}
                    }},
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
                rules: new ILinterRule[] { new InvalidIntFunctionArgument() },
                metadata: InvalidIntFunctionArgumentTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}