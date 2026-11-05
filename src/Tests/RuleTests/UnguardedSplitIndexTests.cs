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
            "The expression selects an element by index from the result of 'split()' on a value that is known only when the policy is evaluated. The selection fails when the value has too few segments, and a failed expression makes the policy deny the request. Use 'first()' or 'last()', or 'coalesce(first(skip(...)), <fallback>)'; they don't fail on short values.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[split(field('Microsoft.Test/widgets/subnet.id'), '/')[2]]", Severity.Error)]
        [InlineData("[SPLIT(field('Microsoft.Test/widgets/subnet.id'), '/')[2]]", Severity.Error)]
        [InlineData("[toLower(split(field('Microsoft.Test/widgets/subnet.id'), '/')[4])]", Severity.Error)]
        [InlineData("[split(field('Microsoft.Test/widgets/subnet.id'), '/')[parameters('zeroParam')]]", Severity.Error)]
        [InlineData("[if(equals(split(field('Microsoft.Test/widgets/subnet.id'), '/')[2], 'x'), 'a', 'b')]", Severity.Error)]
        [InlineData("[if(greater(length(split(field('Microsoft.Test/widgets/subnet.id'), '/')), 2), split(field('Microsoft.Test/widgets/subnet.id'), '/')[2], '')]", Severity.Warning)]
        public void RuleTests_UnguardedSplitIndex_Fires(string valueExpression, Severity expectedSeverity)
        {
            var results = UnguardedSplitIndexTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-split-index",
                Title: "Unguarded Split Index",
                Severity: expectedSeverity,
                Category: Category.TemplateFunctions,
                LineNumber: 10,
                LinePosition: 35 + valueExpression.Length,
                Description: UnguardedSplitIndexTests.ExpectedDescription,
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[split(field('Microsoft.Test/widgets/subnet.id'), '/')[0]]")]
        [InlineData("[split(parameters('textParam'), '/')[1]]")]
        [InlineData("[last(split(field('Microsoft.Test/widgets/subnet.id'), '/'))]")]
        [InlineData("[coalesce(first(skip(split(field('Microsoft.Test/widgets/subnet.id'), '/'), 2)), '')]")]
        [InlineData("[split(concat(field('Microsoft.Test/widgets/subnet.id'), '//'), '/')[2]]")]
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
