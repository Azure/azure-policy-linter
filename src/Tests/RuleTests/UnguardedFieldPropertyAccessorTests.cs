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
    /// Tests for the <see cref="UnguardedFieldPropertyAccessor"/> rule.
    /// </summary>
    public class UnguardedFieldPropertyAccessorTests
    {
        private const string ExpectedDescription =
            "The expression selects a property or an index from a '{0}()' value. The selection fails when the property is missing or the index is out of bounds. A failed expression makes the policy deny the request. Put the full path in the field reference, or use 'tryGet()' with 'coalesce()'.";

        private static readonly MockTypeMetadata MockMetadata = new MockTypeMetadata();

        [Theory]
        [InlineData("[field('tags')['env']]", "field")]
        [InlineData("[field('Microsoft.Test/widgets/items[*]')[0]]", "field")]
        [InlineData("[concat(field('tags').env, 'x')]", "field")]
        public void RuleTests_UnguardedFieldPropertyAccessor_Fires(string valueExpression, string descriptionParameter)
        {
            var results = UnguardedFieldPropertyAccessorTests.LintValueExpression(valueExpression);

            results.Should().HaveCount(1);
            results.Should().ContainEquivalentOf(new LinterOutput(
                RuleIdentifier: "unguarded-field-property-accessor",
                Title: "Unguarded Field Property Accessor",
                Severity: Severity.Error,
                Category: Category.BestPractices,
                LineNumber: 9,
                LinePosition: 35 + valueExpression.Length,
                Description: string.Format(UnguardedFieldPropertyAccessorTests.ExpectedDescription, descriptionParameter),
                Path: "properties.policyRule.if.value"));
        }

        [Theory]
        [InlineData("[field('tags[env]')]")]
        [InlineData("[parameters('emptyArrayParam')[0]]")]
        [InlineData("[requestContext().apiVersion]")]
        [InlineData("[if(contains(field('tags'), 'env'), field('tags')['env'], '')]")]
        public void RuleTests_UnguardedFieldPropertyAccessor_NoFinding(string valueExpression)
        {
            var results = UnguardedFieldPropertyAccessorTests.LintValueExpression(valueExpression);

            results.Should().BeEmpty();
        }

        [Theory]
        [InlineData("Microsoft.Test/widgets/items[*]", "[current('Microsoft.Test/widgets/items[*]').name]", 1)]
        [InlineData("[parameters('emptyArrayParam')]", "[current('item').name]", 0)]
        public void RuleTests_UnguardedFieldPropertyAccessor_CurrentInCount(string countedArray, string valueExpression, int expectedCount)
        {
            var countSource = countedArray.StartsWith("[")
                ? $@"""value"": ""{countedArray}"", ""name"": ""item"""
                : $@"""field"": ""{countedArray}""";
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""emptyArrayParam"": {{ ""type"": ""Array"", ""defaultValue"": [] }}
                    }},
                    ""policyRule"": {{
                      ""if"": {{
                        ""count"": {{
                          {countSource},
                          ""where"": {{ ""value"": ""{valueExpression}"", ""equals"": ""abc"" }}
                        }},
                        ""greater"": 0
                      }},
                      ""then"": {{
                        ""effect"": ""deny""
                      }}
                    }}
                  }}
                }}";

            var linter = new PolicyLinter(
                rules: new ILinterRule[] { new UnguardedFieldPropertyAccessor() },
                metadata: UnguardedFieldPropertyAccessorTests.MockMetadata);

            linter.Lint(policyDefinition).Should().HaveCount(expectedCount);
        }

        private static LinterOutput[] LintValueExpression(string valueExpression)
        {
            var policyDefinition = $@"
                {{
                  ""properties"": {{
                    ""parameters"": {{
                      ""emptyArrayParam"": {{ ""type"": ""Array"", ""defaultValue"": [] }}
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
                rules: new ILinterRule[] { new UnguardedFieldPropertyAccessor() },
                metadata: UnguardedFieldPropertyAccessorTests.MockMetadata);

            return linter.Lint(policyDefinition);
        }
    }
}