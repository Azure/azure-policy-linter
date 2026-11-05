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
    /// Tests for the <see cref="InvalidTemplateFunctionArgument"/> rule.
    /// </summary>
    public class InvalidTemplateFunctionArgumentTests
    {
        private const string ExpectedDescription =
            "The call {0} fails when the policy is evaluated. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[int('ten')]", "int('ten')")]
        [InlineData("[int(parameters('count'))]", "int('ten')")]
        [InlineData("[less(INT('ten'), 5)]", "INT('ten')")]
        [InlineData("[addDays('01/31/2026', 30)]", "addDays('01/31/2026', 30)")]
        [InlineData("[ipRangeContains('AzureCloud', '10.0.0.1')]", "ipRangeContains('AzureCloud', '10.0.0.1')")]
        [InlineData("[div(10, parameters('zero'))]", "div(10, 0)")]
        [InlineData("[max(parameters('empty'))]", "max([])")]
        [InlineData("[replace('abc', '', '')]", "replace('abc', '', '')")]
        [InlineData("[substring('abc', 0, 5)]", "substring('abc', 0, 5)")]
        [InlineData("[padLeft('1', 20, '0')]", "padLeft('1', 20, '0')")]
        public void RuleTests_InvalidTemplateFunctionArgument_Fires(string valueExpression, string failingCall)
        {
            var results = InvalidTemplateFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(InvalidTemplateFunctionArgumentTests.CreateExpectedOutput(valueExpression, failingCall));
        }

        [Fact]
        public void RuleTests_InvalidTemplateFunctionArgument_OneFindingPerFailingValue()
        {
            const string valueExpression = "[int(concat(parameters('count'), 'x'))]";

            var results = InvalidTemplateFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(2);
            results.Should().ContainEquivalentOf(InvalidTemplateFunctionArgumentTests.CreateExpectedOutput(valueExpression, "int('1x')"));
            results.Should().ContainEquivalentOf(InvalidTemplateFunctionArgumentTests.CreateExpectedOutput(valueExpression, "int('tenx')"));
        }

        [Theory]
        [InlineData("[int('5')]")]
        [InlineData("[int(field('tags[a]'))]")]
        [InlineData("[int(parameters('noValues'))]")]
        [InlineData("[if(equals(parameters('count'), 'ten'), 0, int(parameters('count')))]")]
        [InlineData("[substring('abc', 0, 3)]")]
        [InlineData("[selectProperty(createObject(), 1)]")]
        public void RuleTests_InvalidTemplateFunctionArgument_NoFinding(string valueExpression)
        {
            var results = InvalidTemplateFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        private static LinterOutput CreateExpectedOutput(string valueExpression, string failingCall)
        {
            return new LinterOutput(
                RuleIdentifier: "invalid-template-function-argument",
                Title: "Invalid Template Function Argument",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 12,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(InvalidTemplateFunctionArgumentTests.ExpectedDescription, failingCall),
                Path: "properties.policyRule.if.value");
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""count"": {{ ""type"": ""String"", ""allowedValues"": [ ""1"", ""ten"" ], ""defaultValue"": ""1"" }},
                      ""zero"": {{ ""type"": ""Integer"", ""defaultValue"": 0 }},
                      ""empty"": {{ ""type"": ""Array"", ""defaultValue"": [] }},
                      ""noValues"": {{ ""type"": ""String"" }}
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
                rules: new ILinterRule[] { new InvalidTemplateFunctionArgument() },
                metadata: InvalidTemplateFunctionArgumentTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}
