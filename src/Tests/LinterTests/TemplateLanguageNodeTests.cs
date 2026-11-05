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
            'stringParam': { 'type': 'String', 'allowedValues': [ '1', 'x' ], 'defaultValue': 'y' },
            'otherParam': { 'type': 'String', 'defaultValue': 'z' },
            'noValuesParam': { 'type': 'String' }";

        [Fact]
        public void TemplateLanguageNodeTests_NestedCalls_ConditionalEvaluation()
        {
            var (expression, _) = TemplateLanguageNodeTests.LintValue("[if(equals(field('a'), ''), int(field('a')), and(true(), bool(field('b'))))]");

            var calls = TemplateLanguageNodeTests.GetCalls(expression);
            calls.Select(call => call.Name).Should().BeEquivalentTo("if", "equals", "field", "int", "field", "and", "true", "bool", "field");
            calls.Where(call => !call.IsConditionallyEvaluated).Select(call => call.Name).Should().BeEquivalentTo("if", "equals", "field");
        }

        [Fact]
        public void TemplateLanguageNodeTests_AndOrArguments_NotConditionallyEvaluated()
        {
            var (expression, _) = TemplateLanguageNodeTests.LintValue("[or(empty(field('a')), less(int(field('a')), 5))]");

            TemplateLanguageNodeTests.GetCalls(expression).Should().OnlyContain(call => !call.IsConditionallyEvaluated);
        }

        [Fact]
        public void TemplateLanguageNodeTests_SelectorInIfBranch_ConditionallyEvaluated()
        {
            var (expression, _) = TemplateLanguageNodeTests.LintValue("[if(true(), split(field('a'), '/')[1], '')]");

            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "split").IsConditionallyEvaluated.Should().BeTrue();
        }

        [Fact]
        public void TemplateLanguageNodeTests_ArgumentReferences()
        {
            var (expression, _) = TemplateLanguageNodeTests.LintValue("[replace(parameters('stringParam'), concat('a', field('a')), resourceGroup().name)]");

            var call = TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "replace");
            call.Arguments.Should().HaveCount(3);
            call.Arguments[0].Should().BeOfType<TemplateFunctionCall>().Which.Reference.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            call.Arguments.Select(argument => argument.IsEvaluationTimeReference()).Should().Equal(false, false, true);
            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "field").Reference.Should().BeSameAs(expression.References.Single(reference => reference.Kind == ReferenceKind.ResourceField));
        }

        [Fact]
        public void TemplateLanguageNodeTests_Selectors()
        {
            var (expression, _) = TemplateLanguageNodeTests.LintValue("[concat(split(field('a'), '/')[2], field('tags')['env'], field('b'))]");

            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "split").Selectors.Should().ContainSingle().Which.Should().BeOfType<TemplateLiteralValue>().Which.Value.Should().BeEquivalentTo(new JValue(2));

            var fieldCalls = TemplateLanguageNodeTests.GetCalls(expression).Where(call => call.Name == "field").ToArray();
            fieldCalls.Should().OnlyContain(call => call.Reference != null && call.Reference.Kind == ReferenceKind.ResourceField);
            fieldCalls.Single(call => call.Selectors.Length > 0).Selectors.Should().ContainSingle().Which.Should().BeOfType<TemplateLiteralValue>().Which.Value.Should().BeEquivalentTo(new JValue("env"));
        }

        [Fact]
        public void TemplateLanguageNodeTests_CurrentInValueCount_NotEvaluationTimeValue()
        {
            var policy = TemplateLanguageNodeTests.CreatePolicy(@"
                'count': {
                    'value': ""[parameters('stringParam')]"",
                    'name': 'item',
                    'where': { 'value': ""[int(current('item'))]"", 'equals': 1 }
                },
                'greater': 0");

            var (expression, _) = TemplateLanguageNodeTests.Lint(policy).Single(result => result.Expression.Expression.StartsWith("[int("));

            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "int").Arguments[0].IsEvaluationTimeReference().Should().BeFalse();
        }

        [Fact]
        public void TemplateLanguageNodeTests_CurrentInFieldCount_EvaluationTimeValue()
        {
            var policy = TemplateLanguageNodeTests.CreatePolicy(@"
                'count': {
                    'field': 'Microsoft.Test/widgets/items[*]',
                    'where': { 'value': ""[int(current('Microsoft.Test/widgets/items[*].size'))]"", 'equals': 1 }
                },
                'greater': 0");

            var (expression, _) = TemplateLanguageNodeTests.Lint(policy).Single(result => result.Expression.Expression.StartsWith("[int("));

            TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "int").Arguments[0].IsEvaluationTimeReference().Should().BeTrue();
        }

        [Theory]
        [InlineData("[int('ten')]", new[] { "int('ten')" })]
        [InlineData("[int('10')]", new string[0])]
        [InlineData("[int(parameters('stringParam'))]", new[] { "int('x')", "int('y')" })]
        [InlineData("[int(concat(parameters('stringParam'), parameters('stringParam')))]", new[] { "int('xx')", "int('yy')" })]
        [InlineData("[addDays('01/31/2026', 30)]", new[] { "addDays('01/31/2026', 30)" })]
        [InlineData("[ipRangeContains(parameters('otherParam'), '10.0.0.1')]", new[] { "ipRangeContains('z', '10.0.0.1')" })]
        [InlineData("[replace('a''b', 'a''b', '')]", new string[0])]
        [InlineData("[div(4, 0)]", new[] { "div(4, 0)" })]
        [InlineData("[max(createArray())]", new[] { "max([])" })]
        [InlineData("[int(if(true(), 'ten', div(4, 0)))]", new[] { "int('ten')" })]
        [InlineData("[selectProperty(createObject(), 1)]", new string[0])]
        public void TemplateLanguageNodeTests_GetFailuresForKnownValues(string valueExpression, string[] expectedFailures)
        {
            var (expression, context) = TemplateLanguageNodeTests.LintValue(valueExpression);

            var rootCall = expression.Root.Should().BeOfType<TemplateFunctionCall>().Subject;
            rootCall.GetFailuresForKnownValues(context).Should().BeEquivalentTo(expectedFailures);
        }

        [Theory]
        [InlineData("[int(field('a'))]")]
        [InlineData("[int(concat(parameters('stringParam'), parameters('otherParam')))]")]
        [InlineData("[int(parameters('noValuesParam'))]")]
        [InlineData("[int(parameters('undeclared'))]")]
        [InlineData("[int(substring('abc', 5))]")]
        [InlineData("[int(selectProperty(createObject('a', 'b'), 'a'))]")]
        [InlineData("[int(substring(utcNow(), 17, 2))]")]
        public void TemplateLanguageNodeTests_GetFailuresForKnownValues_NotEvaluated(string valueExpression)
        {
            var (expression, context) = TemplateLanguageNodeTests.LintValue(valueExpression);

            var intCall = TemplateLanguageNodeTests.GetCalls(expression).Single(call => call.Name == "int");
            intCall.GetFailuresForKnownValues(context).Should().BeEmpty();
        }

        private static TemplateFunctionCall[] GetCalls(TemplateLanguageExpression expression)
        {
            var calls = new List<TemplateFunctionCall>();
            expression.Root.Visit(new PolicyExpressionVisitor { Visit = node => { if (node is TemplateFunctionCall call) { calls.Add(call); } } });
            return calls.ToArray();
        }

        private static (TemplateLanguageExpression Expression, LinterContext Context) LintValue(string valueExpression)
        {
            var policy = TemplateLanguageNodeTests.CreatePolicy($@"'value': ""{valueExpression}"", 'equals': 'x'");
            return TemplateLanguageNodeTests.Lint(policy).Single(result => result.Expression.Expression == valueExpression);
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

        private static List<(TemplateLanguageExpression Expression, LinterContext Context)> Lint(string policy)
        {
            var results = new List<(TemplateLanguageExpression, LinterContext)>();
            var rule = new TestTemplateLanguageExpressionLinterRule()
            {
                EvaluateFunc = (rule, expression, context) =>
                {
                    results.Add((expression, context));
                    return Enumerable.Empty<LinterOutput>();
                },
            };

            new PolicyLinter(rules: new ILinterRule[] { rule }, metadata: new MockTypeMetadata()).Lint(policy).Should().BeEmpty();
            return results;
        }
    }
}
