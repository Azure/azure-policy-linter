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
    /// Tests for the <see cref="UnguardedIntFunction"/> rule.
    /// </summary>
    public class UnguardedIntFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'int()' on a value that is known only when the policy is evaluated. 'int()' fails when the value is not an integer, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[int(field('tags[costCenter]'))]")]
        [InlineData("[less(INT(field('tags[a]')), 5)]")]
        [InlineData("[int(resourceGroup().tags.size)]")]
        [InlineData("[if(true(), int(field('tags[a]')), 0)]")]
        [InlineData("[if(equals(field('tags[b]'), ''), 0, int(field('tags[a]')))]")]
        [InlineData("[or(empty(field('tags[a]')), less(int(field('tags[a]')), 5))]")]
        public void RuleTests_UnguardedIntFunction_Fires(string valueExpression)
        {
            var results = UnguardedIntFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-int-function",
                Title: "Unguarded Int Function",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedIntFunctionTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[if(equals(field('tags[a]'), ''), 0, int(field('tags[a]')))]")]
        [InlineData("[if(empty(field('tags[a]')), 0, add(int(field('tags[a]')), 1))]")]
        [InlineData("[if(not(equals(toLower(field('tags[a]')), '')), int(field('tags[a]')), 0)]")]
        [InlineData("[int(parameters('textParam'))]")]
        [InlineData("[int('5')]")]
        public void RuleTests_UnguardedIntFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedIntFunctionTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""textParam"": {{ ""type"": ""String"", ""allowedValues"": [ ""1"", ""ten"" ], ""defaultValue"": ""1"" }}
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
                rules: new ILinterRule[] { new UnguardedIntFunction() },
                metadata: UnguardedIntFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}