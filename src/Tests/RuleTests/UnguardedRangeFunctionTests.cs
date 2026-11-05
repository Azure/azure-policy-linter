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
    /// Tests for the <see cref="UnguardedRangeFunction"/> rule.
    /// </summary>
    public class UnguardedRangeFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'range()' with a value that is known only when the policy is evaluated. 'range()' fails when an argument is not an integer or the count is less than 0 or greater than 10000, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the values with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[range(1, field('Microsoft.Test/widgets/count'))]")]
        public void RuleTests_UnguardedRangeFunction_Fires(string valueExpression)
        {
            var results = UnguardedRangeFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-range-function",
                Title: "Unguarded Range Function",
                Severity: Severity.Warning,
                Category: Category.TemplateFunctions,
                LineNumber: 6,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedRangeFunctionTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[range(1, 5)]")]
        [InlineData("[if(equals(field('Microsoft.Test/widgets/count'), ''), createArray(), range(1, field('Microsoft.Test/widgets/count')))]")]
        public void RuleTests_UnguardedRangeFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedRangeFunctionTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new UnguardedRangeFunction() },
                metadata: UnguardedRangeFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}