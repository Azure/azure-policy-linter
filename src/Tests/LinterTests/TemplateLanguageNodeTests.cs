// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Tests
{
    using System.Collections.Generic;
    using System.Linq;
    using FluentAssertions;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Newtonsoft.Json.Linq;
    using Xunit;

    /// <summary>
    /// Tests for <see cref="TemplateLanguageNode"/> and <see cref="TemplateLanguageExpression.Root"/>.
    /// </summary>
    public class TemplateLanguageNodeTests
    {
        private const string Parameters = @"
            'stringParam': { 'type': 'String' }";

        [Fact]
        public void TemplateLanguageNodeTests_ArgumentReferences()
        {
            var expression = TemplateLanguageNodeTests.LintValue("[replace(parameters('stringParam'), concat('a', field('a')), resourceGroup().name)]");

            var call = TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "replace");
            call.Arguments.Should().HaveCount(3);
            call.Arguments[0].Should().BeOfType<TemplateFunctionCall>().Which.Reference.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            call.Arguments.Select(argument => argument.IsEvaluationTimeReference()).Should().Equal(false, false, true);
            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "field").Reference.Should().BeSameAs(expression.References.Single(reference => reference.Kind == ReferenceKind.ResourceField));
        }

        [Theory]
        [InlineData("[field('a')]", true)]
        [InlineData("[field(parameters('stringParam'))]", true)]
        [InlineData("[requestContext().apiVersion]", true)]
        [InlineData("[claims().aud]", true)]
        [InlineData("[subscription().displayName]", true)]
        [InlineData("[resourceGroup().name]", true)]
        [InlineData("[parameters('stringParam')]", false)]
        [InlineData("[concat(field('a'), '-')]", false)]
        [InlineData("[1]", false)]
        public void TemplateLanguageNodeTests_IsEvaluationTimeReference(string valueExpression, bool expectedResult)
        {
            var expression = TemplateLanguageNodeTests.LintValue(valueExpression);

            expression.Root.IsEvaluationTimeReference().Should().Be(expectedResult);
        }

        [Fact]
        public void TemplateLanguageNodeTests_Selectors()
        {
            var expression = TemplateLanguageNodeTests.LintValue("[concat(split(field('a'), '/')[2], field('tags')['env'], field('b'))]");

            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "split").Selectors.Should().ContainSingle().Which.Should().BeOfType<TemplateLiteralValue>().Which.Value.Should().BeEquivalentTo(new JValue(2));

            var fieldCalls = TemplateLanguageNodeTests.GetCalls(expression).Where(call => call.Name == "field").ToArray();
            fieldCalls.Should().OnlyContain(call => call.Reference != null && call.Reference.Kind == ReferenceKind.ResourceField);
            fieldCalls.Single(call => call.Selectors.Length > 0).Selectors.Should().ContainSingle().Which.Should().BeOfType<TemplateLiteralValue>().Which.Value.Should().BeEquivalentTo(new JValue("env"));
        }

        [Fact]
        public void TemplateLanguageNodeTests_CurrentInValueCount_NotEvaluationTimeReference()
        {
            var policy = TemplateLanguageNodeTests.CreatePolicy(@"
                'count': {
                    'value': ""[parameters('stringParam')]"",
                    'name': 'item',
                    'where': { 'value': ""[int(current('item'))]"", 'equals': 1 }
                },
                'greater': 0");

            var expression = TemplateLanguageNodeTests.Lint(policy).Single(candidate => candidate.Expression.StartsWith("[int("));

            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "int").Arguments[0].IsEvaluationTimeReference().Should().BeFalse();
        }

        [Fact]
        public void TemplateLanguageNodeTests_CurrentInFieldCount_EvaluationTimeReference()
        {
            var policy = TemplateLanguageNodeTests.CreatePolicy(@"
                'count': {
                    'field': 'Microsoft.Test/widgets/items[*]',
                    'where': { 'value': ""[int(current('Microsoft.Test/widgets/items[*].size'))]"", 'equals': 1 }
                },
                'greater': 0");

            var expression = TemplateLanguageNodeTests.Lint(policy).Single(candidate => candidate.Expression.StartsWith("[int("));

            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "int").Arguments[0].IsEvaluationTimeReference().Should().BeTrue();
        }

        [Theory]
        [InlineData("[parameters(concat('string', 'Param'))]", "stringParam")]
        [InlineData("[parameters(split('a/stringParam', '/')[1])]", "stringParam")]
        [InlineData("[parameters(createObject('name', 'stringParam').name)]", "stringParam")]
        [InlineData("[parameters(if(true(), 'stringParam', 'otherParam'))]", "stringParam")]
        [InlineData("[claims()]", "claims")]
        public void TemplateLanguageNodeTests_ReferenceIdentifier_Evaluated(string valueExpression, string expectedIdentifier)
        {
            var expression = TemplateLanguageNodeTests.LintValue(valueExpression);

            var reference = expression.Root.Should().BeOfType<TemplateFunctionCall>().Which.Reference;
            reference.IsResolved.Should().BeTrue();
            reference.Identifier.Should().Be(expectedIdentifier);
        }

        [Fact]
        public void TemplateLanguageNodeTests_ReferenceIdentifier_DependsOnReference()
        {
            var expression = TemplateLanguageNodeTests.LintValue("[parameters(concat(field('a'), 'Param'))]");

            var reference = expression.Root.Should().BeOfType<TemplateFunctionCall>().Which.Reference;
            reference.IsResolved.Should().BeFalse();
            reference.Identifier.Should().BeEmpty();
        }

        [Theory]
        [InlineData("[field('tags')[concat('e', 'nv')]]", true, new[] { "env" })]
        [InlineData("[field('tags')[parameters('stringParam')]]", false, new string[0])]
        public void TemplateLanguageNodeTests_ReferencePropertySelectionPath(string valueExpression, bool expectedIsResolved, string[] expectedPath)
        {
            var expression = TemplateLanguageNodeTests.LintValue(valueExpression);

            var path = expression.Root.Should().BeOfType<TemplateFunctionCall>().Which.Reference.PropertySelectionPath;
            path.IsResolved.Should().Be(expectedIsResolved);
            path.Path.Should().Equal(expectedPath);
        }

        private static TemplateFunctionCall[] GetCalls(TemplateLanguageExpression expression)
        {
            var calls = new List<TemplateFunctionCall>();
            expression.Root.Visit(new PolicyExpressionVisitor { Visit = node => { if (node is TemplateFunctionCall call) { calls.Add(call); } } });
            return calls.ToArray();
        }

        private static TemplateLanguageExpression LintValue(string valueExpression)
        {
            var policy = TemplateLanguageNodeTests.CreatePolicy($@"'value': ""{valueExpression}"", 'equals': 'x'");
            return TemplateLanguageNodeTests.Lint(policy).Single(candidate => candidate.Expression == valueExpression);
        }

        private static string CreatePolicy(string condition)
        {
            return $@"
            {{
                'properties': {{
                    'parameters': {{ {TemplateLanguageNodeTests.Parameters} }},
                    'policyRule': {{
                        'if': {{ {condition} }},
                        'then': {{ 'effect': 'deny' }}
                    }}
                }}
            }}";
        }

        private static List<TemplateLanguageExpression> Lint(string policy)
        {
            var results = new List<TemplateLanguageExpression>();
            var rule = new TestTemplateLanguageExpressionLinterRule()
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    results.Add(expression);
                    return Enumerable.Empty<LinterOutput>();
                },
            };

            new PolicyLinter(rules: new ILinterRule[] { rule }, metadata: new MockTypeMetadata()).Lint(policy).Should().BeEmpty();
            return results;
        }
    }
}
