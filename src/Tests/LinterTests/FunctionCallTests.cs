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
    /// Tests for <see cref="FunctionCall"/> and <see cref="TemplateLanguageExpression.FunctionCalls"/>.
    /// </summary>
    public class FunctionCallTests
    {
        private const string Parameters = @"
            'stringParam': { 'type': 'String', 'allowedValues': [ '1', 'x' ], 'defaultValue': 'y' },
            'otherParam': { 'type': 'String', 'defaultValue': 'z' },
            'noValuesParam': { 'type': 'String' }";

        [Fact]
        public void FunctionCallTests_NestedCalls_ConditionalEvaluation()
        {
            var (expression, _) = FunctionCallTests.LintValue("[if(equals(field('a'), ''), int(field('a')), and(true(), bool(field('b'))))]");

            var calls = expression.FunctionCalls;
            calls.Select(call => call.Name).Should().BeEquivalentTo("if", "equals", "field", "int", "field", "and", "true", "bool", "field");
            calls.Where(call => !call.IsConditionallyEvaluated).Select(call => call.Name).Should().BeEquivalentTo("if", "equals", "field");
        }

        [Fact]
        public void FunctionCallTests_OrArgumentsAfterFirst_ConditionallyEvaluated()
        {
            var (expression, _) = FunctionCallTests.LintValue("[or(empty(field('a')), less(int(field('a')), 5))]");

            expression.FunctionCalls.Single(call => call.Name == "empty").IsConditionallyEvaluated.Should().BeFalse();
            expression.FunctionCalls.Single(call => call.Name == "int").IsConditionallyEvaluated.Should().BeTrue();
        }

        [Fact]
        public void FunctionCallTests_ArgumentReferences()
        {
            var (expression, _) = FunctionCallTests.LintValue("[replace(parameters('stringParam'), concat('a', field('a')), resourceGroup().name)]");

            var call = expression.FunctionCalls.Single(call => call.Name == "replace");
            call.Arguments.Should().HaveCount(3);
            call.Arguments[0].References.Should().ContainSingle().Which.Kind.Should().Be(ReferenceKind.PolicyParameterName);
            call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 0).Should().BeFalse();
            call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 1).Should().BeTrue();
            call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 2).Should().BeTrue();
            call.ArgumentDependsOnEvaluationTimeValue(argumentIndex: 3).Should().BeFalse();
            call.Arguments[1].References.Single().Should().BeSameAs(expression.References.Single(reference => reference.Kind == ReferenceKind.ResourceField));
        }

        [Fact]
        public void FunctionCallTests_Selectors()
        {
            var (expression, _) = FunctionCallTests.LintValue("[concat(split(field('a'), '/')[2], field('tags')['env'], field('b'))]");

            expression.FunctionCalls.Single(call => call.Name == "split").Selectors.Should().BeEquivalentTo(new JToken[] { 2 });

            var fieldCalls = expression.FunctionCalls.Where(call => call.Name == "field").ToArray();
            fieldCalls.Should().OnlyContain(call => call.Reference != null && call.Reference.Kind == ReferenceKind.ResourceField);
            fieldCalls.Single(call => call.Selectors.Length > 0).Selectors.Should().BeEquivalentTo(new JToken[] { "env" });
        }

        [Fact]
        public void FunctionCallTests_CurrentInValueCount_NotEvaluationTimeValue()
        {
            var policy = FunctionCallTests.CreatePolicy(@"
                'count': {
                    'value': ""[parameters('stringParam')]"",
                    'name': 'item',
                    'where': { 'value': ""[int(current('item'))]"", 'equals': 1 }
                },
                'greater': 0");

            var (expression, _) = FunctionCallTests.Lint(policy).Single(result => result.Expression.Expression.StartsWith("[int("));

            expression.FunctionCalls.Single(call => call.Name == "int").ArgumentDependsOnEvaluationTimeValue(argumentIndex: 0).Should().BeFalse();
        }

        [Fact]
        public void FunctionCallTests_CurrentInFieldCount_EvaluationTimeValue()
        {
            var policy = FunctionCallTests.CreatePolicy(@"
                'count': {
                    'field': 'Microsoft.Test/widgets/items[*]',
                    'where': { 'value': ""[int(current('Microsoft.Test/widgets/items[*].size'))]"", 'equals': 1 }
                },
                'greater': 0");

            var (expression, _) = FunctionCallTests.Lint(policy).Single(result => result.Expression.Expression.StartsWith("[int("));

            expression.FunctionCalls.Single(call => call.Name == "int").ArgumentDependsOnEvaluationTimeValue(argumentIndex: 0).Should().BeTrue();
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
        public void FunctionCallTests_GetFailuresForKnownValues(string valueExpression, string[] expectedFailures)
        {
            var (expression, context) = FunctionCallTests.LintValue(valueExpression);

            expression.TryGetFunctionName(out var rootFunctionName).Should().BeTrue();
            var rootCall = expression.FunctionCalls.Single(call => call.Name == rootFunctionName);
            rootCall.GetFailuresForKnownValues(context).Should().BeEquivalentTo(expectedFailures);
        }

        [Theory]
        [InlineData("[int(field('a'))]")]
        [InlineData("[int(concat(parameters('stringParam'), parameters('otherParam')))]")]
        [InlineData("[int(parameters('noValuesParam'))]")]
        [InlineData("[int(parameters('undeclared'))]")]
        [InlineData("[int(substring('abc', 5))]")]
        [InlineData("[int(selectProperty(createObject('a', 'b'), 'a'))]")]
        public void FunctionCallTests_GetFailuresForKnownValues_NotEvaluated(string valueExpression)
        {
            var (expression, context) = FunctionCallTests.LintValue(valueExpression);

            var intCall = expression.FunctionCalls.Single(call => call.Name == "int");
            intCall.GetFailuresForKnownValues(context).Should().BeEmpty();
        }

        private static (TemplateLanguageExpression Expression, LinterContext Context) LintValue(string valueExpression)
        {
            var policy = FunctionCallTests.CreatePolicy($@"'value': ""{valueExpression}"", 'equals': 'x'");
            return FunctionCallTests.Lint(policy).Single(result => result.Expression.Expression == valueExpression);
        }

        private static string CreatePolicy(string condition)
        {
            return $@"
            {{
                'properties': {{
                    'parameters': {{ {FunctionCallTests.Parameters} }},
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
