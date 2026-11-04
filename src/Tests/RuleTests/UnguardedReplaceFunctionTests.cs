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
    /// Tests for the <see cref="UnguardedReplaceFunction"/> rule.
    /// </summary>
    public class UnguardedReplaceFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'replace()' with a string to replace that is known only when the policy is evaluated. 'replace()' fails when the string to replace is empty, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[replace(field('name'), field('tags[prefix]'), '')]")]
        public void RuleTests_UnguardedReplaceFunction_Fires(string valueExpression)
        {
            var results = UnguardedReplaceFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-replace-function",
                Title: "Unguarded Replace Function",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedReplaceFunctionTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[replace(field('name'), 'app-', '')]")]
        [InlineData("[if(equals(field('tags[prefix]'), ''), field('name'), replace(field('name'), field('tags[prefix]'), ''))]")]
        public void RuleTests_UnguardedReplaceFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedReplaceFunctionTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
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
                rules: new ILinterRule[] { new UnguardedReplaceFunction() },
                metadata: UnguardedReplaceFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}