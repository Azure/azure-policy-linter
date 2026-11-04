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
        internal FunctionCall(FunctionExpression expression, ImmutableArray<Reference>[] argumentReferences, Reference? reference, bool isConditionallyEvaluated)
        {
            this.Name = expression.Function;
            this.Arguments = expression.Parameters
                .CoalesceEnumerable()
                .Select((argument, index) => new FunctionCallArgument(expression: argument, references: argumentReferences[index]))
                .ToImmutableArray();
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
        /// Whether the argument at the given index exists and depends on a value that is known only when the policy is evaluated.
        /// </summary>
        /// <param name="argumentIndex">The zero-based argument index.</param>
        public bool ArgumentDependsOnEvaluationTimeValue(int argumentIndex)
        {
            return argumentIndex < this.Arguments.Length && this.Arguments[argumentIndex].DependsOnEvaluationTimeValue;
        }

        /// <summary>
        /// Evaluates the call for the values known from the policy definition and returns the calls that fail, e.g. "int('ten')".
        /// </summary>
        /// <remarks>
        /// Applies only to calls whose arguments are literals or use a single parameter. A parameter is evaluated with its default value and each of its allowed values.
        /// Calls with any other reference, and values for which an argument fails to evaluate, are skipped.
        /// </remarks>
        /// <param name="context">The linter context.</param>
        public string[] GetFailuresForKnownValues(LinterContext context)
        {
            var references = this.Arguments.SelectMany(argument => argument.References).ToArray();
            if (references.Any(reference => reference.Kind != ReferenceKind.PolicyParameterName || !reference.IsResolved))
            {
                return Array.Empty<string>();
            }

            var parameterNames = references.Select(reference => reference.Identifier).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (parameterNames.Length > 1)
            {
                return Array.Empty<string>();
            }

            if (parameterNames.Length == 0)
            {
                return this.TryGetFailure(evaluationContext: new StaticTemplateFunctionEvaluationContext(), failure: out var failure)
                    ? new[] { failure! }
                    : Array.Empty<string>();
            }

            if (context.Parameters == null || !context.Parameters.TryGetValue(parameterNames[0], out var parameter))
            {
                return Array.Empty<string>();
            }

            var knownValues = parameter.DefaultValue == null
                ? parameter.AllowedValues.CoalesceEnumerable()
                : parameter.AllowedValues.CoalesceEnumerable().Append(parameter.DefaultValue);

            var failures = new List<string>();
            foreach (var value in knownValues)
            {
                var evaluationContext = new StaticTemplateFunctionEvaluationContext(parameterName: parameterNames[0], parameterValue: value);
                if (this.TryGetFailure(evaluationContext: evaluationContext, failure: out var failure) && !failures.Contains(failure!))
                {
                    failures.Add(failure!);
                }
            }

            return failures.ToArray();
        }

        /// <summary>
        /// Evaluates the arguments and then the function. Returns true with the evaluated call when the function fails.
        /// </summary>
        private bool TryGetFailure(StaticTemplateFunctionEvaluationContext evaluationContext, out string? failure)
        {
            failure = null;

            JToken[] argumentValues;
            try
            {
                argumentValues = this.Arguments.Select(argument => argument.Evaluate(evaluationContext)).ToArray();
            }
            catch (Exception exception) when (!exception.IsFatal())
            {
                // The failure is not in this call (or the argument uses a function the linter can't evaluate).
                return false;
            }

            try
            {
                StaticTemplateFunctionEvaluationContext.EvaluateBuiltInFunction(functionName: this.Name, arguments: argumentValues);
                return false;
            }
            catch (Exception exception) when (!exception.IsFatal() && exception is not global::Azure.Deployments.Expression.Exceptions.BuiltinFunctionNumberOfParametersException)
            {
                failure = $"{this.Name}({string.Join(", ", argumentValues.Select(FunctionCall.FormatValue))})";
                return true;
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
        /// Whether the argument depends on a value that is known only when the policy is evaluated (see <see cref="Reference.IsEvaluationTimeValue"/>).
        /// </summary>
        public bool DependsOnEvaluationTimeValue => this.References.Any(reference => reference.IsEvaluationTimeValue());

        /// <summary>
        /// Creates a new instance of the <see cref="FunctionCallArgument"/> class.
        /// </summary>
        internal FunctionCallArgument(LanguageExpression expression, ImmutableArray<Reference> references)
        {
            this.expression = expression;
            this.References = references;
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
