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
    /// Tests for the <see cref="UnguardedBoolFunction"/> rule.
    /// </summary>
    public class UnguardedBoolFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'bool()' on a value that is known only when the policy is evaluated. 'bool()' fails when the value is not a boolean or the string 'true' or 'false', including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[bool(field('tags[backupEnabled]'))]", "")]
        [InlineData("[bool(claims().isAllowed)]", "")]
        public void RuleTests_UnguardedBoolFunction_Fires(string valueExpression, string descriptionParameter)
        {
            var results = UnguardedBoolFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-bool-function",
                Title: "Unguarded Bool Function",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(UnguardedBoolFunctionTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[if(equals(field('tags[backupEnabled]'), ''), false(), bool(field('tags[backupEnabled]')))]")]
        [InlineData("[bool('true')]")]
        public void RuleTests_UnguardedBoolFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedBoolFunctionTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new UnguardedBoolFunction() },
                metadata: UnguardedBoolFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}