// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// A template function call within a <see cref="TemplateLanguageExpression"/> (e.g. the 'int' call in "[less(int(field('a')), 5)]").
    /// </summary>
    public sealed class FunctionCall
    {
        /// <summary>
        /// The function name as written in the expression. Function names are case insensitive.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The function arguments.
        /// </summary>
        public ImmutableArray<FunctionCallArgument> Arguments { get; }

        /// <summary>
        /// The property and index selectors applied to the function result, e.g. [2] and 'name' in "[split(x, '/')[2].name]".
        /// A selector that is not a literal value is null.
        /// </summary>
        public ImmutableArray<JToken?> Selectors { get; }

        /// <summary>
        /// The reference created for this call, when the function is a reference function such as field() or parameters().
        /// </summary>
        public Reference? Reference { get; }

        /// <summary>
        /// Whether the call is evaluated only for some values: it is inside the second or third argument of 'if()',
        /// or inside an argument after the first one of 'and()' or 'or()'. Policy evaluation skips these arguments when they don't affect the result.
        /// </summary>
        public bool IsConditionallyEvaluated { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="FunctionCall"/> class.
        /// </summary>
        internal FunctionCall(FunctionExpression expression, ImmutableArray<FunctionCallArgument> arguments, Reference? reference, bool isConditionallyEvaluated)
        {
            this.Name = expression.Function;
            this.Arguments = arguments;
            this.Selectors = expression.Properties
                .CoalesceEnumerable()
                .Select(property => (property as JTokenExpression)?.Value)
                .ToImmutableArray();
            this.Reference = reference;
            this.IsConditionallyEvaluated = isConditionallyEvaluated;
        }

        /// <summary>
        /// Whether the argument at the given index of the given function is evaluated only for some values
        /// (the second and third arguments of 'if()', and the arguments after the first one of 'and()' and 'or()').
        /// </summary>
        /// <param name="functionName">The function name.</param>
        /// <param name="argumentIndex">The zero-based argument index.</param>
        internal static bool IsConditionallyEvaluatedArgument(string functionName, int argumentIndex)
        {
            return (functionName.EqualsOrdinalInsensitively("if") && argumentIndex is 1 or 2) ||
                ((functionName.EqualsOrdinalInsensitively("and") || functionName.EqualsOrdinalInsensitively("or")) && argumentIndex > 0);
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
            var references = this.Arguments.SelectMany(argument => argument.References).ToArray();
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

    /// <summary>
    /// An argument of a <see cref="FunctionCall"/>.
    /// </summary>
    public sealed class FunctionCallArgument
    {
        private readonly LanguageExpression expression;

        /// <summary>
        /// The references anywhere inside the argument.
        /// </summary>
        public ImmutableArray<Reference> References { get; }

        /// <summary>
        /// Whether the argument itself is a reference to a value known only when the policy is evaluated (see <see cref="Reference.IsEvaluationTimeValue"/>),
        /// e.g. "field('name')" or "requestContext().apiVersion". A reference inside another function, e.g. "concat(field('name'), '-')", doesn't count.
        /// </summary>
        public bool IsEvaluationTimeValue { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="FunctionCallArgument"/> class.
        /// </summary>
        internal FunctionCallArgument(LanguageExpression expression, ImmutableArray<Reference> references)
        {
            this.expression = expression;
            this.References = references;
            this.IsEvaluationTimeValue = Reference.IsReferenceFunction(expression, out _) && references.Single().IsEvaluationTimeValue();
        }

        /// <summary>
        /// Evaluates the argument with the given context.
        /// </summary>
        /// <remarks>
        /// Function expressions cache their value after the first evaluation, so a copy is evaluated to keep the parsed policy unchanged.
        /// </remarks>
        internal JToken Evaluate(StaticTemplateFunctionEvaluationContext evaluationContext)
        {
            return FunctionCallArgument.Copy(this.expression).EvaluateExpression(evaluationContext);
        }

        private static LanguageExpression Copy(LanguageExpression expression)
        {
            return expression is FunctionExpression function
                ? new FunctionExpression(
                    function.Function,
                    function.Parameters.CoalesceEnumerable().SelectArray(FunctionCallArgument.Copy),
                    function.Properties.CoalesceEnumerable().SelectArray(FunctionCallArgument.Copy))
                : expression;
        }
    }
}
