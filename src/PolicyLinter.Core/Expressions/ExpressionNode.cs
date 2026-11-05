// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// A node in the parsed form of a <see cref="TemplateLanguageExpression"/>: a function call or a literal value.
    /// </summary>
    /// <remarks>
    /// Nodes have the line number, position and path of the template language expression they belong to.
    /// </remarks>
    public abstract class ExpressionNode : PolicyExpression
    {
        /// <summary>
        /// The parsed expression. Private by design, to keep expression engine types out of the linter rules.
        /// </summary>
        private readonly LanguageExpression expression;

        /// <summary>
        /// Creates a new instance of the <see cref="ExpressionNode"/> class.
        /// </summary>
        private protected ExpressionNode(LanguageExpression expression, PolicyExpression parent, ExpressionNode? guardCondition)
            : base(parent.LineNumber, parent.LinePosition, parent.PathSegments, parent)
        {
            this.expression = expression;
            this.GuardCondition = guardCondition;
        }

        /// <summary>
        /// The condition (first argument) of the nearest 'if()' whose second or third argument contains this node, otherwise null.
        /// </summary>
        public ExpressionNode? GuardCondition { get; }

        /// <summary>
        /// Whether this node is a reference that the condition of its guarding 'if()' also uses (see <see cref="GuardCondition"/>),
        /// e.g. the 'field('a')' call in "[if(empty(field('a')), 0, int(field('a')))]".
        /// </summary>
        /// <remarks>
        /// Checks only that the condition uses the same value, not what the condition does with it.
        /// </remarks>
        public bool IsCheckedByGuardCondition()
        {
            return this is FunctionCall { Reference: { } reference } &&
                this.GuardCondition != null &&
                this.GuardCondition
                    .GetReferences()
                    .Any(other => other.Kind == reference.Kind && other.Identifier.EqualsOrdinalInsensitively(reference.Identifier));
        }

        /// <summary>
        /// Whether this node is a reference to a value known only when the policy is evaluated (see <see cref="Reference.IsEvaluationTimeValue"/>),
        /// e.g. "field('name')" or "requestContext().apiVersion". A reference inside another function, e.g. "concat(field('name'), '-')", doesn't count.
        /// </summary>
        public bool IsEvaluationTimeReference()
        {
            return this is FunctionCall { Reference: { } reference } && reference.IsEvaluationTimeValue();
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
        }

        /// <summary>
        /// Creates the node for the given parsed expression.
        /// </summary>
        internal static ExpressionNode Create(
            LanguageExpression expression,
            PolicyExpression parent,
            bool isConditionallyEvaluated,
            ExpressionNode? guardCondition,
            IReadOnlyDictionary<FunctionExpression, Reference> references)
        {
            return expression is FunctionExpression function
                ? new FunctionCall(function, parent, isConditionallyEvaluated, guardCondition, references)
                : new LiteralValue(expression, parent, guardCondition);
        }

        /// <summary>
        /// Gets the references in this node and all nodes below it.
        /// </summary>
        internal virtual IEnumerable<Reference> GetReferences()
        {
            return Enumerable.Empty<Reference>();
        }

        /// <summary>
        /// Evaluates the node with the given context.
        /// </summary>
        /// <remarks>
        /// Function expressions cache their value after the first evaluation, so a copy is evaluated to keep the parsed policy unchanged.
        /// </remarks>
        internal JToken Evaluate(StaticTemplateFunctionEvaluationContext evaluationContext)
        {
            return ExpressionNode.Copy(this.expression).EvaluateExpression(evaluationContext);
        }

        private static LanguageExpression Copy(LanguageExpression expression)
        {
            return expression is FunctionExpression function
                ? new FunctionExpression(
                    function.Function,
                    function.Parameters.CoalesceEnumerable().SelectArray(ExpressionNode.Copy),
                    function.Properties.CoalesceEnumerable().SelectArray(ExpressionNode.Copy))
                : expression;
        }
    }

    /// <summary>
    /// A literal value in a template language expression, e.g. 'a' and 3 in "[substring('a', 3)]".
    /// </summary>
    public sealed class LiteralValue : ExpressionNode
    {
        /// <summary>
        /// The value.
        /// </summary>
        public JToken Value { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="LiteralValue"/> class.
        /// </summary>
        internal LiteralValue(LanguageExpression expression, PolicyExpression parent, ExpressionNode? guardCondition)
            : base(expression, parent, guardCondition)
        {
            this.Value = (expression as JTokenExpression)?.Value ?? JValue.CreateNull();
        }
    }

    /// <summary>
    /// A template function call, e.g. the 'int' call in "[less(int(field('a')), 5)]".
    /// </summary>
    public sealed class FunctionCall : ExpressionNode
    {
        /// <summary>
        /// The function name as written in the expression. Function names are case insensitive.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The function arguments.
        /// </summary>
        public ImmutableArray<ExpressionNode> Arguments { get; }

        /// <summary>
        /// The property and index selectors applied to the function result, e.g. [2] and 'name' in "[split(x, '/')[2].name]".
        /// </summary>
        public ImmutableArray<ExpressionNode> Selectors { get; }

        /// <summary>
        /// The reference for this call, when the function is a reference function such as field() or parameters().
        /// </summary>
        public Reference? Reference { get; }

        /// <summary>
        /// Whether the call is evaluated only for some values: it is inside the second or third argument of 'if()',
        /// or inside an argument after the first one of 'and()' or 'or()'. Policy evaluation skips these arguments when they don't affect the result.
        /// </summary>
        public bool IsConditionallyEvaluated { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="FunctionCall"/> class and the nodes below it.
        /// </summary>
        internal FunctionCall(
            FunctionExpression expression,
            PolicyExpression parent,
            bool isConditionallyEvaluated,
            ExpressionNode? guardCondition,
            IReadOnlyDictionary<FunctionExpression, Reference> references)
            : base(expression, parent, guardCondition)
        {
            this.Name = expression.Function;
            this.IsConditionallyEvaluated = isConditionallyEvaluated;
            this.Reference = references.TryGetValue(expression, out var reference) ? reference : null;

            // The condition of an if() is built first, so the nodes in its branches can point to it.
            var arguments = new List<ExpressionNode>();
            var parameters = expression.Parameters.CoalesceEnumerable().ToArray();
            for (var index = 0; index < parameters.Length; index++)
            {
                var isIfBranch = this.Name.EqualsOrdinalInsensitively("if") && index > 0;
                arguments.Add(ExpressionNode.Create(
                    expression: parameters[index],
                    parent: this,
                    isConditionallyEvaluated: isConditionallyEvaluated || FunctionCall.IsConditionallyEvaluatedArgument(functionName: this.Name, argumentIndex: index),
                    guardCondition: isIfBranch ? arguments[0] : guardCondition,
                    references: references));
            }

            this.Arguments = arguments.ToImmutableArray();
            this.Selectors = expression.Properties
                .CoalesceEnumerable()
                .Select(selector => ExpressionNode.Create(expression: selector, parent: this, isConditionallyEvaluated: isConditionallyEvaluated, guardCondition: guardCondition, references: references))
                .ToImmutableArray();
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            base.Visit(visitor);

            foreach (var node in this.Arguments.Concat(this.Selectors))
            {
                node.Visit(visitor);
            }
        }

        /// <summary>
        /// Evaluates the call for the values known from the policy definition and returns the calls that fail, e.g. "int('ten')".
        /// </summary>
        /// <remarks>
        /// Applies only to calls of functions the linter can evaluate, whose arguments are literals or use a single parameter.
        /// A parameter is evaluated with each of its allowed values and its default value.
        /// Calls with any other reference, and values for which an argument fails to evaluate, are skipped.
        /// Any error from the function itself is a failure, including a wrong number of arguments (e.g. max() of an empty array).
        /// </remarks>
        /// <param name="context">The linter context.</param>
        public string[] GetFailuresForKnownValues(LinterContext context)
        {
            var references = this.Arguments.SelectMany(argument => argument.GetReferences()).ToArray();
            if (!StaticTemplateFunctionEvaluationContext.IsBuiltInFunction(this.Name) ||
                references.Any(reference => reference.Kind != ReferenceKind.PolicyParameterName || !reference.IsResolved))
            {
                return Array.Empty<string>();
            }

            var parameterNames = references.Select(reference => reference.Identifier).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var evaluationContexts = parameterNames.Length switch
            {
                0 => new[] { new StaticTemplateFunctionEvaluationContext() },
                1 => FunctionCall.GetKnownValues(context: context, parameterName: parameterNames[0])
                    .Select(value => new StaticTemplateFunctionEvaluationContext(parameterName: parameterNames[0], parameterValue: value))
                    .ToArray(),
                _ => Array.Empty<StaticTemplateFunctionEvaluationContext>(),
            };

            return evaluationContexts
                .Select(this.GetFailure)
                .OfType<string>()
                .Distinct()
                .ToArray();
        }

        /// <inheritdoc/>
        internal override IEnumerable<Reference> GetReferences()
        {
            var references = this.Arguments.Concat(this.Selectors).SelectMany(node => node.GetReferences());
            return this.Reference == null ? references : references.Prepend(this.Reference);
        }

        /// <summary>
        /// Whether the argument at the given index of the given function is evaluated only for some values
        /// (the second and third arguments of 'if()', and the arguments after the first one of 'and()' and 'or()').
        /// </summary>
        private static bool IsConditionallyEvaluatedArgument(string functionName, int argumentIndex)
        {
            return (functionName.EqualsOrdinalInsensitively("if") && argumentIndex is 1 or 2) ||
                ((functionName.EqualsOrdinalInsensitively("and") || functionName.EqualsOrdinalInsensitively("or")) && argumentIndex > 0);
        }

        /// <summary>
        /// Gets the parameter's allowed values and default value.
        /// </summary>
        private static JToken[] GetKnownValues(LinterContext context, string parameterName)
        {
            if (context.Parameters == null || !context.Parameters.TryGetValue(parameterName, out var parameter))
            {
                return Array.Empty<JToken>();
            }

            return parameter.AllowedValues
                .CoalesceEnumerable()
                .Concat(new[] { parameter.DefaultValue })
                .OfType<JToken>()
                .ToArray();
        }

        /// <summary>
        /// Evaluates the arguments and then the function. Returns the evaluated call when the function fails, otherwise null.
        /// </summary>
        private string? GetFailure(StaticTemplateFunctionEvaluationContext evaluationContext)
        {
            JToken[] argumentValues;
            try
            {
                argumentValues = this.Arguments.Select(argument => argument.Evaluate(evaluationContext)).ToArray();
            }
            catch (Exception exception) when (!exception.IsFatal())
            {
                // The failure is not in this call (or the argument uses a function the linter can't evaluate).
                return null;
            }

            try
            {
                StaticTemplateFunctionEvaluationContext.EvaluateBuiltInFunction(functionName: this.Name, arguments: argumentValues);
                return null;
            }
            catch (Exception exception) when (!exception.IsFatal())
            {
                return $"{this.Name}({string.Join(", ", argumentValues.Select(FunctionCall.FormatValue))})";
            }
        }

        /// <summary>
        /// Formats a value the way it is written in a template language expression.
        /// </summary>
        private static string FormatValue(JToken value)
        {
            return value.Type == JTokenType.String
                ? $"'{value.ToString().Replace("'", "''")}'"
                : value.ToString(Formatting.None);
        }
    }
}
