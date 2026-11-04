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
    /// Tests for the <see cref="InvalidSubstringFunctionArgument"/> rule.
    /// </summary>
    public class InvalidSubstringFunctionArgumentTests
    {
        private const string ExpectedDescription =
            "The call {0} fails when the policy is evaluated, because the requested range is negative or runs past the end of the string. A failed expression makes the policy deny the request. Fix the value, or the parameter's defaultValue and allowedValues.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[substring('abc', 0, 5)]", "substring('abc', 0, 5)")]
        [InlineData("[substring('abc', -1)]", "substring('abc', -1)")]
        [InlineData("[substring(parameters('prefix'), 0, 4)]", "substring('dev', 0, 4)")]
        public void RuleTests_InvalidSubstringFunctionArgument_Fires(string valueExpression, string descriptionParameter)
        {
            var results = InvalidSubstringFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "invalid-substring-function-argument",
                Title: "Invalid Substring Function Argument",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(InvalidSubstringFunctionArgumentTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[substring('abc', 0, 3)]")]
        [InlineData("[substring(field('name'), 0, 3)]")]
        [InlineData("[if(equals(parameters('prefix'), 'dev'), 'dev', substring(parameters('prefix'), 0, 4))]")]
        public void RuleTests_InvalidSubstringFunctionArgument_NoFinding(string valueExpression)
        {
            var results = InvalidSubstringFunctionArgumentTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""prefix"": {{ ""type"": ""String"", ""allowedValues"": [ ""prod"", ""dev"" ] }}
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
                rules: new ILinterRule[] { new InvalidSubstringFunctionArgument() },
                metadata: InvalidSubstringFunctionArgumentTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}
