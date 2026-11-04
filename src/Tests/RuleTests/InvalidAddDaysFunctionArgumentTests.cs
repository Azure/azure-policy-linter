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
    /// Tests for the <see cref="InvalidAddDaysFunctionArgument"/> rule.
    /// </summary>
    public class InvalidAddDaysFunctionArgumentTests
    {
        private const string ExpectedDescription =
            "The call {0} fails when the policy is evaluated, because the date is not in ISO 8601 format or the number of days is not an integer. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[addDays('01/31/2026', 30)]", "addDays('01/31/2026', 30)")]
        public void RuleTests_InvalidAddDaysFunctionArgument_Fires(string valueExpression, string descriptionParameter)
        {
            var results = InvalidAddDaysFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "invalid-adddays-function-argument",
                Title: "Invalid addDays Function Argument",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(InvalidAddDaysFunctionArgumentTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[addDays('2026-01-31T00:00:00Z', 30)]")]
        public void RuleTests_InvalidAddDaysFunctionArgument_NoFinding(string valueExpression)
        {
            var results = InvalidAddDaysFunctionArgumentTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new InvalidAddDaysFunctionArgument() },
                metadata: InvalidAddDaysFunctionArgumentTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}