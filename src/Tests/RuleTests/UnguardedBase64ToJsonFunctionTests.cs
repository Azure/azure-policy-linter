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
    /// Tests for the <see cref="UnguardedBase64ToJsonFunction"/> rule.
    /// </summary>
    public class UnguardedBase64ToJsonFunctionTests
    {
        private const string ExpectedDescription =
            "The expression calls 'base64ToJson()' on a value that is known only when the policy is evaluated. 'base64ToJson()' fails when the value is not base64-encoded JSON, including the empty string returned for a missing property. A failed expression makes the policy deny the request. Check the value with 'if()' before the call.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[base64ToJson(field('Microsoft.Test/widgets/settings'))]")]
        public void RuleTests_UnguardedBase64ToJsonFunction_Fires(string valueExpression)
        {
            var results = UnguardedBase64ToJsonFunctionTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-base64tojson-function",
                Title: "Unguarded base64ToJson Function",
                Severity: Severity.Warning,
                Category: Category.TemplateFunctions,
                LineNumber: 9,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedBase64ToJsonFunctionTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[base64ToJson(parameters('textParam'))]")]
        [InlineData("[if(equals(field('Microsoft.Test/widgets/settings'), ''), createObject(), base64ToJson(field('Microsoft.Test/widgets/settings')))]")]
        public void RuleTests_UnguardedBase64ToJsonFunction_NoFinding(string valueExpression)
        {
            var results = UnguardedBase64ToJsonFunctionTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new UnguardedBase64ToJsonFunction() },
                metadata: UnguardedBase64ToJsonFunctionTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}