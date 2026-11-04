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
    /// Tests for the <see cref="UnguardedDivOrModFunction"/> rule.
    /// </summary>
    public class UnguardedDivOrModFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls '{0}()' with a value that is known only when the policy is evaluated. '{0}()' fails when an argument is not an integer or the divisor is zero, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the values with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[div(field('Microsoft.Test/widgets/size'), 2)]", "div")]
        [InlineData("[mod(10, field('Microsoft.Test/widgets/count'))]", "mod")]
        public void RuleTests_UnguardedDivOrModFunction_Fires(string valueExpression, string descriptionParameter)
        {
            var results = UnguardedDivOrModFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-div-or-mod-function",
                Title: "Unguarded Div or Mod Function",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(UnguardedDivOrModFunctionTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[div(10, parameters('zeroParam'))]")]
        [InlineData("[if(equals(field('Microsoft.Test/widgets/count'), 0), 0, div(10, field('Microsoft.Test/widgets/count')))]")]
        public void RuleTests_UnguardedDivOrModFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedDivOrModFunctionTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new UnguardedDivOrModFunction() },
                metadata: UnguardedDivOrModFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}