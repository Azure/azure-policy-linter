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
    /// Tests for the <see cref="UnguardedIpRangeContainsFunction"/> rule.
    /// </summary>
    public class UnguardedIpRangeContainsFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'ipRangeContains()' with a value that is known only when the policy is evaluated. 'ipRangeContains()' fails when a value is not an IP address or range, for example '*', a service tag, or the empty string returned for a missing property. A failed expression makes the policy deny the request. Make sure only IP values reach the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[ipRangeContains('10.0.0.0/8', field('Microsoft.Test/widgets/ipAddress'))]", "")]
        [InlineData("[ipRangeContains(field('Microsoft.Test/widgets/range'), '10.0.0.1')]", "")]
        public void RuleTests_UnguardedIpRangeContainsFunction_Fires(string valueExpression, string descriptionParameter)
        {
            var results = UnguardedIpRangeContainsFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-iprangecontains-function",
                Title: "Unguarded ipRangeContains Function",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(UnguardedIpRangeContainsFunctionTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[ipRangeContains('10.0.0.0/8', parameters('textParam'))]")]
        [InlineData("[if(equals(field('Microsoft.Test/widgets/ipAddress'), ''), true(), ipRangeContains('10.0.0.0/8', field('Microsoft.Test/widgets/ipAddress')))]")]
        public void RuleTests_UnguardedIpRangeContainsFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedIpRangeContainsFunctionTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new UnguardedIpRangeContainsFunction() },
                metadata: UnguardedIpRangeContainsFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}