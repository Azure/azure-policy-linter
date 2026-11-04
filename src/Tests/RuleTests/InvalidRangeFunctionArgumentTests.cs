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
    /// Tests for the <see cref="InvalidRangeFunctionArgument"/> rule.
    /// </summary>
    public class InvalidRangeFunctionArgumentTests
    {
        private const string ExpectedDescription =
            "The call {0} fails when the policy is evaluated, because an argument is not an integer, the count is less than 0 or greater than 10000, or the range is too large. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[range(0, 20000)]", "range(0, 20000)")]
        public void RuleTests_InvalidRangeFunctionArgument_Fires(string valueExpression, string descriptionParameter)
        {
            var results = InvalidRangeFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "invalid-range-function-argument",
                Title: "Invalid Range Function Argument",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(InvalidRangeFunctionArgumentTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[range(0, 5)]")]
        public void RuleTests_InvalidRangeFunctionArgument_NoFinding(string valueExpression)
        {
            var results = InvalidRangeFunctionArgumentTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new InvalidRangeFunctionArgument() },
                metadata: InvalidRangeFunctionArgumentTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}