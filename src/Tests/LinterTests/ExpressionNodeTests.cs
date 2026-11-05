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
    /// Tests for <see cref="ExpressionNode"/> and <see cref="TemplateLanguageExpression.Root"/>.
    /// </summary>
    public class ExpressionNodeTests
    {
        private const string Parameters = @"
            'stringParam': { 'type': 'String' }";

        [Fact]
        public void ExpressionNodeTests_NestedCalls_ConditionalEvaluation()
        {
            var (expression, _) = ExpressionNodeTests.LintValue("[if(equals(field('a'), ''), int(field('a')), and(true(), bool(field('b'))))]");

            var calls = ExpressionNodeTests.GetCalls(expression);
            calls.Select(call => call.Name).Should().BeEquivalentTo("if", "equals", "field", "int", "field", "and", "true", "bool", "field");
            calls.Where(call => !call.IsConditionallyEvaluated).Select(call => call.Name).Should().BeEquivalentTo("if", "equals", "field");
        }

        [Fact]
        public void ExpressionNodeTests_OrArgumentsAfterFirst_ConditionallyEvaluated()
        {
            var (expression, _) = ExpressionNodeTests.LintValue("[or(empty(field('a')), less(int(field('a')), 5))]");

            ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "empty").IsConditionallyEvaluated.Should().BeFalse();
            ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "int").IsConditionallyEvaluated.Should().BeTrue();
        }

        [Fact]
        public void ExpressionNodeTests_SelectorInIfBranch_ConditionallyEvaluated()
        {
            var (expression, _) = ExpressionNodeTests.LintValue("[if(true(), split(field('a'), '/')[1], '')]");

            ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "split").IsConditionallyEvaluated.Should().BeTrue();
        }

        [Fact]
        public void ExpressionNodeTests_ArgumentReferences()
        {
            var (expression, _) = ExpressionNodeTests.LintValue("[replace(parameters('stringParam'), concat('a', field('a')), resourceGroup().name)]");

            var call = ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "replace");
            call.Arguments.Should().HaveCount(3);
            call.Arguments[0].Should().BeOfType<FunctionCall>().Which.Reference.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            call.Arguments.Select(argument => argument.IsEvaluationTimeReference()).Should().Equal(false, false, true);
            ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "field").Reference.Should().BeSameAs(expression.References.Single(reference => reference.Kind == ReferenceKind.ResourceField));
        }

        [Fact]
        public void ExpressionNodeTests_Selectors()
        {
            var (expression, _) = ExpressionNodeTests.LintValue("[concat(split(field('a'), '/')[2], field('tags')['env'], field('b'))]");

            ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "split").Selectors.Should().ContainSingle().Which.Should().BeOfType<LiteralValue>().Which.Value.Should().BeEquivalentTo(new JValue(2));

            var fieldCalls = ExpressionNodeTests.GetCalls(expression).Where(call => call.Name == "field").ToArray();
            fieldCalls.Should().OnlyContain(call => call.Reference != null && call.Reference.Kind == ReferenceKind.ResourceField);
            fieldCalls.Single(call => call.Selectors.Length > 0).Selectors.Should().ContainSingle().Which.Should().BeOfType<LiteralValue>().Which.Value.Should().BeEquivalentTo(new JValue("env"));
        }

        [Fact]
        public void ExpressionNodeTests_CurrentInValueCount_NotEvaluationTimeValue()
        {
            var policy = ExpressionNodeTests.CreatePolicy(@"
                'count': {
                    'value': ""[parameters('stringParam')]"",
                    'name': 'item',
                    'where': { 'value': ""[int(current('item'))]"", 'equals': 1 }
                },
                'greater': 0");

            var (expression, _) = ExpressionNodeTests.Lint(policy).Single(result => result.Expression.Expression.StartsWith("[int("));

            ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "int").Arguments[0].IsEvaluationTimeReference().Should().BeFalse();
        }

        [Fact]
        public void ExpressionNodeTests_CurrentInFieldCount_EvaluationTimeValue()
        {
            var policy = ExpressionNodeTests.CreatePolicy(@"
                'count': {
                    'field': 'Microsoft.Test/widgets/items[*]',
                    'where': { 'value': ""[int(current('Microsoft.Test/widgets/items[*].size'))]"", 'equals': 1 }
                },
                'greater': 0");

            var (expression, _) = ExpressionNodeTests.Lint(policy).Single(result => result.Expression.Expression.StartsWith("[int("));

            ExpressionNodeTests.GetCalls(expression).Single(call => call.Name == "int").Arguments[0].IsEvaluationTimeReference().Should().BeTrue();
        }

        private static FunctionCall[] GetCalls(TemplateLanguageExpression expression)
        {
            var calls = new List<FunctionCall>();
            expression.Root.Visit(new PolicyExpressionVisitor { Visit = node => { if (node is FunctionCall call) { calls.Add(call); } } });
            return calls.ToArray();
        }

        private static (TemplateLanguageExpression Expression, LinterContext Context) LintValue(string valueExpression)
        {
            var policy = ExpressionNodeTests.CreatePolicy($@"'value': ""{valueExpression}"", 'equals': 'x'");
            return ExpressionNodeTests.Lint(policy).Single(result => result.Expression.Expression == valueExpression);
        }

        private static string CreatePolicy(string condition)
        {
            return $@"
            {{
                'properties': {{
                    'parameters': {{ {ExpressionNodeTests.Parameters} }},
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
