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
    /// Tests for the <see cref="TryGetWithMultipleKeys"/> rule.
    /// </summary>
    public class TryGetWithMultipleKeysTests
    {
        private const string ExpectedDescription =
            "The expression calls 'tryGet()' with more than one key. Only the first key is looked up safely, and the expression fails when a later key is missing. A failed expression makes the policy deny the request. Use 'selectProperty()', or one 'tryGet()' for each key.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[tryGet(field('Microsoft.Test/widgets/properties'), 'settings', 'tier')]", "")]
        [InlineData("[coalesce(tryGet(field('Microsoft.Test/widgets/properties'), 'settings', 'tier'), '')]", "")]
        [InlineData("[if(true(), '', tryGet(parameters('emptyArrayParam'), 0, 1))]", "")]
        public void RuleTests_TryGetWithMultipleKeys_Fires(string valueExpression, string descriptionParameter)
        {
            var results = TryGetWithMultipleKeysTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "tryget-with-multiple-keys",
                Title: "tryGet with Multiple Keys",
                Severity: Severity.Warning,
                Category: Category.BestPractices,
                LineNumber: 13,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(TryGetWithMultipleKeysTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[tryGet(field('Microsoft.Test/widgets/properties'), 'settings')]")]
        [InlineData("[tryGet(tryGet(field('Microsoft.Test/widgets/properties'), 'settings'), 'tier')]")]
        public void RuleTests_TryGetWithMultipleKeys_NoFinding(string valueExpression)
        {
            var results = TryGetWithMultipleKeysTests.LintValueExpression(valueExpression);

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
                rules: new ILinterRule[] { new TryGetWithMultipleKeys() },
                metadata: TryGetWithMultipleKeysTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}