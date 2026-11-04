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
    /// Tests for the <see cref="InvalidMinOrMaxFunctionArgument"/> rule.
    /// </summary>
    public class InvalidMinOrMaxFunctionArgumentTests
    {
        private const string ExpectedDescription =
            "The call {0} fails when the policy is evaluated, because the array is empty or a value is not a number. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[max(parameters('emptyArrayParam'))]", "max([])")]
        [InlineData("[min(1, 'a')]", "min(1, 'a')")]
        public void RuleTests_InvalidMinOrMaxFunctionArgument_Fires(string valueExpression, string descriptionParameter)
        {
            var results = InvalidMinOrMaxFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "invalid-min-or-max-function-argument",
                Title: "Invalid Min or Max Function Argument",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(InvalidMinOrMaxFunctionArgumentTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[max(1, 2)]")]
        public void RuleTests_InvalidMinOrMaxFunctionArgument_NoFinding(string valueExpression)
        {
            var results = InvalidMinOrMaxFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""textParam"": {{ ""type"": ""String"", ""allowedValues"": [ ""1"", ""ten"" ], ""defaultValue"": ""1"" }},
                      ""zeroParam"": {{ ""type"": ""Integer"", ""defaultValue"": 0 }},
                      ""emptyArrayParam"": {{ ""type"": ""Array"", ""defaultValue"": [] }},
                      ""emptyStringParam"": {{ ""type"": ""String"", ""defaultValue"": """" }},
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
                rules: new ILinterRule[] { new InvalidMinOrMaxFunctionArgument() },
                metadata: InvalidMinOrMaxFunctionArgumentTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}