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
    /// Tests for the <see cref="UnguardedSplitIndex"/> rule.
    /// </summary>
    public class UnguardedSplitIndexTests
    {
        private const string ExpectedDescription =
            "The expression selects an element by index from the result of 'split()' on a value that is known only when the policy is evaluated. The selection fails when the value has too few segments. A failed expression makes the policy deny the request. Use 'first()' or 'last()', or check 'length()' with 'if()' first.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[split(field('id'), '/')[2]]")]
        [InlineData("[toLower(split(field('id'), '/')[4])]")]
        [InlineData("[split(field('id'), '/')[parameters('zeroParam')]]")]
        public void RuleTests_UnguardedSplitIndex_Fires(string valueExpression)
        {
            var results = UnguardedSplitIndexTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-split-index",
                Title: "Unguarded Split Index",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 10,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedSplitIndexTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[split(field('id'), '/')[0]]")]
        [InlineData("[split(parameters('textParam'), '/')[1]]")]
        [InlineData("[last(split(field('id'), '/'))]")]
        [InlineData("[if(greater(length(split(field('id'), '/')), 2), split(field('id'), '/')[2], '')]")]
        public void RuleTests_UnguardedSplitIndex_NoFinding(string valueExpression)
        {
            var results = UnguardedSplitIndexTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""textParam"": {{ ""type"": ""String"", ""allowedValues"": [ ""1"", ""ten"" ], ""defaultValue"": ""1"" }},
                      ""zeroParam"": {{ ""type"": ""Integer"", ""defaultValue"": 0 }}
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
                rules: new ILinterRule[] { new UnguardedSplitIndex() },
                metadata: UnguardedSplitIndexTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}