// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Diagnostics.CodeAnalysis;
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
    public abstract class TemplateLanguageNode : PolicyExpression
    {
        /// <summary>
        /// The linter's copy of the built-in template functions of policy evaluation.
        /// </summary>
        private protected static readonly EvaluationHelpers.ExpressionBuiltInFunctions BuiltInFunctions = new EvaluationHelpers.ExpressionBuiltInFunctions();

        /// <summary>
        /// Creates a new instance of the <see cref="TemplateLanguageNode"/> class.
        /// </summary>
        private protected TemplateLanguageNode(PolicyExpression parent, TemplateLanguageNode? guardCondition)
            : base(parent.LineNumber, parent.LinePosition, parent.PathSegments, parent)
        {
            this.GuardCondition = guardCondition;
        }

        /// <summary>
        /// The condition (first argument) of the nearest 'if()' whose second or third argument contains this node, otherwise null.
        /// </summary>
        public TemplateLanguageNode? GuardCondition { get; }

        /// <summary>
        /// Whether this node is a reference that the condition of its guarding 'if()' also uses (see <see cref="GuardCondition"/>),
        /// e.g. the 'field('a')' call in "[if(empty(field('a')), 0, int(field('a')))]".
        /// </summary>
        /// <remarks>
        /// Checks only that the condition uses the same value, not what the condition does with it.
        /// The same value means the same reference kind, identifier and property path, e.g. 'resourceGroup().name' and 'resourceGroup().tags.size' are different values.
        /// </remarks>
        public bool IsCheckedByGuardCondition()
        {
            return this is TemplateFunctionCall { Reference: { } reference } &&
                this.GuardCondition != null &&
                this.GuardCondition
                    .GetReferences()
                    .Any(other => TemplateLanguageNode.IsSameValue(reference, other));
        }

        private static bool IsSameValue(Reference first, Reference second)
        {
            var firstPath = first.PropertySelectionPath;
            var secondPath = second.PropertySelectionPath;
            return first.IsResolved &&
                second.IsResolved &&
                first.Kind == second.Kind &&
                first.Identifier.EqualsOrdinalInsensitively(second.Identifier) &&
                firstPath?.IsResolved != false &&
                secondPath?.IsResolved != false &&
                (firstPath?.Path ?? Array.Empty<string>()).SequenceEqual(secondPath?.Path ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Whether this node is a reference to a value known only when the policy is evaluated (see <see cref="Reference.IsEvaluationTimeValue"/>),
        /// e.g. "field('name')" or "requestContext().apiVersion". A reference inside another function, e.g. "concat(field('name'), '-')", doesn't count.
        /// </summary>
        public bool IsEvaluationTimeReference()
        {
            return this is TemplateFunctionCall { Reference: { } reference } && reference.IsEvaluationTimeValue();
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
        }

        /// <summary>
        /// Evaluates the node the way policy evaluation does.
        /// </summary>
        /// <remarks>
        /// Returns false when the value can't be known: the node uses a reference that has no value in <paramref name="referenceValues"/>,
        /// calls a function the linter can't evaluate, or the evaluation fails.
        /// </remarks>
        /// <param name="referenceValues">The values of the references the node can use, e.g. a parameter value.</param>
        /// <param name="value">The value.</param>
        internal abstract bool TryEvaluate(IReadOnlyDictionary<Reference, JToken> referenceValues, [NotNullWhen(true)] out JToken? value);

        /// <summary>
        /// Calls a built-in template function. Returns false when the linter can't evaluate the function or the function fails.
        /// </summary>
        /// <param name="functionName">The function name.</param>
        /// <param name="arguments">The argument values.</param>
        /// <param name="value">The function result.</param>
        internal static bool TryCallBuiltInFunction(string functionName, JToken[] arguments, [NotNullWhen(true)] out JToken? value)
        {
            value = null;
            if (!TemplateLanguageNode.BuiltInFunctions.IsBuiltInFunction(functionName))
            {
                return false;
            }

            try
            {
                value = TemplateLanguageNode.BuiltInFunctions.EvaluateFunction(functionName: functionName, parameters: arguments);
                return true;
            }
            catch (Exception exception) when (!exception.IsFatal())
            {
                return false;
            }
        }

        /// <summary>
        /// Creates the node for the given parsed expression.
        /// </summary>
        internal static TemplateLanguageNode Create(
            LanguageExpression expression,
            PolicyExpression parent,
            bool isConditionallyEvaluated,
            TemplateLanguageNode? guardCondition)
        {
            return expression is FunctionExpression function
                ? new TemplateFunctionCall(function, parent, isConditionallyEvaluated, guardCondition)
                : new TemplateLiteralValue(expression, parent, guardCondition);
        }

        /// <summary>
        /// Gets the references in this node and all nodes below it.
        /// </summary>
        internal virtual IEnumerable<Reference> GetReferences()
        {
            return Enumerable.Empty<Reference>();
        }
    }

    /// <summary>
    /// A literal value in a template language expression, e.g. 'a' and 3 in "[substring('a', 3)]".
    /// </summary>
    public sealed class TemplateLiteralValue : TemplateLanguageNode
    {
        /// <summary>
        /// The value.
        /// </summary>
        public JToken Value { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="TemplateLiteralValue"/> class.
        /// </summary>
        internal TemplateLiteralValue(LanguageExpression expression, PolicyExpression parent, TemplateLanguageNode? guardCondition)
            : base(parent, guardCondition)
        {
            this.Value = (expression as JTokenExpression)?.Value ?? JValue.CreateNull();
        }

        /// <inheritdoc/>
        internal override bool TryEvaluate(IReadOnlyDictionary<Reference, JToken> referenceValues, [NotNullWhen(true)] out JToken? value)
        {
            value = this.Value;
            return true;
        }
    }

    /// <summary>
    /// A template function call, e.g. the 'int' call in "[less(int(field('a')), 5)]".
    /// </summary>
    public sealed class TemplateFunctionCall : TemplateLanguageNode
    {
        /// <summary>
        /// The function name as written in the expression. Function names are case insensitive.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The function arguments.
        /// </summary>
        public ImmutableArray<TemplateLanguageNode> Arguments { get; }

        /// <summary>
        /// The property and index selectors applied to the function result, e.g. [2] and 'name' in "[split(x, '/')[2].name]".
        /// </summary>
        public ImmutableArray<TemplateLanguageNode> Selectors { get; }

        /// <summary>
        /// The reference for this call, when the function is a reference function such as field() or parameters().
        /// </summary>
        public Reference? Reference { get; internal set; }

        /// <summary>
        /// Whether the call is inside the second or third argument of 'if()'. Policy evaluation evaluates only the branch that the condition selects.
        /// </summary>
        /// <remarks>
        /// Only 'if()' is considered. Calls inside 'and()' and 'or()' are not conditionally evaluated, even though policy evaluation can skip their later arguments.
        /// </remarks>
        public bool IsConditionallyEvaluated { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="TemplateFunctionCall"/> class and the nodes below it.
        /// </summary>
        internal TemplateFunctionCall(
            FunctionExpression expression,
            PolicyExpression parent,
            bool isConditionallyEvaluated,
            TemplateLanguageNode? guardCondition)
            : base(parent, guardCondition)
        {
            this.Name = expression.Function;
            this.IsConditionallyEvaluated = isConditionallyEvaluated;

            // The condition of an if() is built first, so the nodes in its branches can point to it.
            var arguments = new List<TemplateLanguageNode>();
            var parameters = expression.Parameters.CoalesceEnumerable().ToArray();
            for (var index = 0; index < parameters.Length; index++)
            {
                var isIfBranch = this.Name.EqualsOrdinalInsensitively("if") && index > 0;
                arguments.Add(TemplateLanguageNode.Create(
                    expression: parameters[index],
                    parent: this,
                    isConditionallyEvaluated: isConditionallyEvaluated || isIfBranch,
                    guardCondition: isIfBranch ? arguments[0] : guardCondition));
            }

            this.Arguments = arguments.ToImmutableArray();
            this.Selectors = expression.Properties
                .CoalesceEnumerable()
                .Select(selector => TemplateLanguageNode.Create(expression: selector, parent: this, isConditionallyEvaluated: isConditionallyEvaluated, guardCondition: guardCondition))
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
        /// Calls with any other reference or with 'utcNow()' in an argument, and values for which an argument fails to evaluate, are skipped.
        /// Any error from the function itself is a failure, including a wrong number of arguments (e.g. max() of an empty array).
        /// </remarks>
        /// <param name="context">The linter context.</param>
        public string[] GetFailuresForKnownValues(LinterContext context)
        {
            var references = this.Arguments.SelectMany(argument => argument.GetReferences()).ToArray();
            if (!TemplateLanguageNode.BuiltInFunctions.IsBuiltInFunction(this.Name) ||
                references.Any(reference => reference.Kind != ReferenceKind.PolicyParameterName || !reference.IsResolved) ||
                this.Arguments.OfType<TemplateFunctionCall>().Any(argument => argument.UsesFunction("utcNow")))
            {
                return Array.Empty<string>();
            }

            var parameterNames = references.Select(reference => reference.Identifier).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var referenceValueSets = parameterNames.Length switch
            {
                0 => new[] { new Dictionary<Reference, JToken>() },
                1 => TemplateFunctionCall.GetKnownValues(context: context, parameterName: parameterNames[0])
                    .Select(value => references.ToDictionary(keySelector: reference => reference, elementSelector: _ => value))
                    .ToArray(),
                _ => Array.Empty<Dictionary<Reference, JToken>>(),
            };

            return referenceValueSets
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
        /// Gets the parameter's allowed values and default value.
        /// </summary>
        /// <remarks>
        /// The allowed values of an 'Array' parameter are the allowed array elements, not parameter values, so only its default value is used.
        /// </remarks>
        private static JToken[] GetKnownValues(LinterContext context, string parameterName)
        {
            if (context.Parameters == null || !context.Parameters.TryGetValue(parameterName, out var parameter))
            {
                return Array.Empty<JToken>();
            }

            var allowedValues = parameter.Type.EqualsOrdinalInsensitively("Array") ? null : parameter.AllowedValues;
            return allowedValues
                .CoalesceEnumerable()
                .Concat(new[] { parameter.DefaultValue })
                .OfType<JToken>()
                .ToArray();
        }

        /// <summary>
        /// Whether this call, or a call in its arguments or selectors, is a call to the given function.
        /// </summary>
        private bool UsesFunction(string functionName)
        {
            return this.Name.EqualsOrdinalInsensitively(functionName) ||
                this.Arguments.Concat(this.Selectors).OfType<TemplateFunctionCall>().Any(call => call.UsesFunction(functionName));
        }

        /// <summary>
        /// Evaluates the arguments and then the function. Returns the evaluated call when the function fails, otherwise null.
        /// </summary>
        private string? GetFailure(IReadOnlyDictionary<Reference, JToken> referenceValues)
        {
            var argumentValues = new List<JToken>();
            foreach (var argument in this.Arguments)
            {
                // The failure is not in this call, or the argument uses a function the linter can't evaluate.
                if (!argument.TryEvaluate(referenceValues: referenceValues, value: out var argumentValue))
                {
                    return null;
                }

                argumentValues.Add(argumentValue);
            }

            return TemplateLanguageNode.TryCallBuiltInFunction(functionName: this.Name, arguments: argumentValues.ToArray(), value: out _)
                ? null
                : $"{this.Name}({string.Join(", ", argumentValues.Select(TemplateFunctionCall.FormatValue))})";
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

        /// <inheritdoc/>
        internal override bool TryEvaluate(IReadOnlyDictionary<Reference, JToken> referenceValues, [NotNullWhen(true)] out JToken? value)
        {
            if (!this.TryEvaluateWithoutSelectors(referenceValues: referenceValues, value: out value))
            {
                return false;
            }

            foreach (var selector in this.Selectors)
            {
                if (!selector.TryEvaluate(referenceValues: referenceValues, value: out var property) ||
                    new JTokenSelectableFunctionResult(root: value).SelectProperty(property: property) is not JTokenSelectableFunctionResult result)
                {
                    value = null;
                    return false;
                }

                value = result.CurrentValue();
            }

            return true;
        }

        private bool TryEvaluateWithoutSelectors(IReadOnlyDictionary<Reference, JToken> referenceValues, [NotNullWhen(true)] out JToken? value)
        {
            value = null;
            if (this.Reference != null)
            {
                return referenceValues.TryGetValue(this.Reference, out value);
            }

            // Policy evaluation evaluates only the 'if()' branch that the condition selects,
            // and stops 'and()' and 'or()' at the first argument that decides the result.
            if (this.Name.EqualsOrdinalInsensitively("if") && this.Arguments.Length == 3)
            {
                return this.Arguments[0].TryEvaluate(referenceValues: referenceValues, value: out var condition) &&
                    condition.Type == JTokenType.Boolean &&
                    this.Arguments[condition.Value<bool>() ? 1 : 2].TryEvaluate(referenceValues: referenceValues, value: out value);
            }

            bool? decidingValue = this.Name.EqualsOrdinalInsensitively("and") ? false : this.Name.EqualsOrdinalInsensitively("or") ? true : null;
            var argumentValues = new List<JToken>();
            foreach (var argument in this.Arguments)
            {
                if (!argument.TryEvaluate(referenceValues: referenceValues, value: out var argumentValue))
                {
                    return false;
                }

                if (argumentValue.Type == JTokenType.Boolean && argumentValue.Value<bool>() == decidingValue)
                {
                    value = argumentValue;
                    return true;
                }

                argumentValues.Add(argumentValue);
            }

            return TemplateLanguageNode.TryCallBuiltInFunction(functionName: this.Name, arguments: argumentValues.ToArray(), value: out value);
        }
    }
}
