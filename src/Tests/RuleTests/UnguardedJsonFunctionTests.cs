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
    /// Tests for the <see cref="UnguardedJsonFunction"/> rule.
    /// </summary>
    public class UnguardedJsonFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'json()' on a value that is known only when the policy is evaluated. 'json()' fails when the value is not valid JSON, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[json(field('tags[config]'))]")]
        public void RuleTests_UnguardedJsonFunction_Fires(string valueExpression)
        {
            var results = UnguardedJsonFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-json-function",
                Title: "Unguarded Json Function",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 6,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedJsonFunctionTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[json('{}')]")]
        [InlineData("[if(equals(field('tags[config]'), ''), createObject(), json(field('tags[config]')))]")]
        public void RuleTests_UnguardedJsonFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedJsonFunctionTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new UnguardedJsonFunction() },
                metadata: UnguardedJsonFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}