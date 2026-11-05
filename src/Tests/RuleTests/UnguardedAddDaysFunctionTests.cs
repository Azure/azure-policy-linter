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
    /// Tests for the <see cref="UnguardedAddDaysFunction"/> rule.
    /// </summary>
    public class UnguardedAddDaysFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'addDays()' with a value that is known only when the policy is evaluated. 'addDays()' fails when the date is not in ISO 8601 format or the number of days is not an integer, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the values with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[addDays(field('tags[createdOn]'), 90)]", Severity.Warning)]
        [InlineData("[addDays(utcNow(), field('tags[days]'))]", Severity.Warning)]
        [InlineData("[ADDDAYS(field('tags[createdOn]'), 90)]", Severity.Warning)]
        [InlineData("[less(addDays(field('tags[createdOn]'), 90), utcNow())]", Severity.Warning)]
        [InlineData("[if(equals(addDays(field('tags[createdOn]'), 90), 'x'), 'a', 'b')]", Severity.Warning)]
        [InlineData("[if(equals(field('tags[createdOn]'), ''), '9999-12-31T00:00:00Z', addDays(field('tags[createdOn]'), 90))]", Severity.Informational)]
        public void RuleTests_UnguardedAddDaysFunction_Fires(string valueExpression, Severity expectedSeverity)
        {
            var results = UnguardedAddDaysFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-adddays-function",
                Title: "Unguarded addDays Function",
                Severity: expectedSeverity,
                Category: Category.TemplateFunctions,
                LineNumber: 9,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedAddDaysFunctionTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[addDays(utcNow(), 30)]")]
        [InlineData("[addDays(utcNow(), parameters('zeroParam'))]")]
        public void RuleTests_UnguardedAddDaysFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedAddDaysFunctionTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
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
                rules: new ILinterRule[] { new UnguardedAddDaysFunction() },
                metadata: UnguardedAddDaysFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}