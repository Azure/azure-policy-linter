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
    /// Tests for the <see cref="UnguardedMinOrMaxFunction"/> rule.
    /// </summary>
    public class UnguardedMinOrMaxFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls '{0}()' with a value that is known only when the policy is evaluated. '{0}()' fails when the array is empty or a value is not a number, including the empty array or string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[max(field('Microsoft.Test/widgets/items[*].size'))]", "max")]
        [InlineData("[min(1, field('Microsoft.Test/widgets/size'))]", "min")]
        public void RuleTests_UnguardedMinOrMaxFunction_Fires(string valueExpression, string descriptionParameter)
        {
            var results = UnguardedMinOrMaxFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-min-or-max-function",
                Title: "Unguarded Min or Max Function",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(UnguardedMinOrMaxFunctionTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[max(1, 2)]")]
        [InlineData("[max(parameters('emptyArrayParam'))]")]
        [InlineData("[if(empty(field('Microsoft.Test/widgets/items[*].size')), 0, max(field('Microsoft.Test/widgets/items[*].size')))]")]
        public void RuleTests_UnguardedMinOrMaxFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedMinOrMaxFunctionTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new UnguardedMinOrMaxFunction() },
                metadata: UnguardedMinOrMaxFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}