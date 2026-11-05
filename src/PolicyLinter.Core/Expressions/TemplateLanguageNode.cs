// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using global::Azure.Deployments.Expression.Expressions;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;
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
        /// Creates a new instance of the <see cref="TemplateLanguageNode"/> class.
        /// </summary>
        private protected TemplateLanguageNode(PolicyExpression parent)
            : base(parent.LineNumber, parent.LinePosition, parent.PathSegments, parent)
        {
        }

        /// <summary>
        /// Whether this node is a reference to a value known only when the policy is evaluated: a resource field (including current() in a field count),
        /// a request context or token claims property, or a resource group or subscription property, e.g. "field('name')" or "requestContext().apiVersion".
        /// </summary>
        /// <remarks>
        /// Policy parameters and current() in a value count are not evaluation time values.
        /// A reference inside another function, e.g. "concat(field('name'), '-')", doesn't count.
        /// </remarks>
        public bool IsEvaluationTimeReference()
        {
            return this is TemplateFunctionCall { Reference: { } reference } &&
                (reference.Kind is ReferenceKind.ResourceField
                    or ReferenceKind.RequestContextProperty
                    or ReferenceKind.PolicyTokenClaims
                    or ReferenceKind.ResourceGroupProperty
                    or ReferenceKind.SubscriptionProperty ||
                reference.IsResolvedFieldReference());
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
        }

        /// <summary>
        /// Evaluates a node that uses only literal values and built-in functions, e.g. "concat('a', 'b')".
        /// </summary>
        /// <remarks>
        /// Returns false when the node uses a reference function (e.g. field()), a function the linter can't evaluate, or the evaluation fails.
        /// </remarks>
        /// <param name="value">The value.</param>
        internal abstract bool TryEvaluate([NotNullWhen(true)] out JToken? value);

        /// <summary>
        /// Creates the node for the given parsed expression.
        /// </summary>
        internal static TemplateLanguageNode Create(LanguageExpression expression, PolicyExpression parent)
        {
            return expression is FunctionExpression function
                ? new TemplateFunctionCall(function, parent)
                : new TemplateLiteralValue(expression, parent);
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
        internal TemplateLiteralValue(LanguageExpression expression, PolicyExpression parent)
            : base(parent)
        {
            this.Value = (expression as JTokenExpression)?.Value ?? JValue.CreateNull();
        }

        /// <inheritdoc/>
        internal override bool TryEvaluate([NotNullWhen(true)] out JToken? value)
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
        /// The linter's copy of the built-in template functions of policy evaluation.
        /// </summary>
        private static readonly EvaluationHelpers.ExpressionBuiltInFunctions BuiltInFunctions = new EvaluationHelpers.ExpressionBuiltInFunctions();

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
        /// Creates a new instance of the <see cref="TemplateFunctionCall"/> class and the nodes below it.
        /// </summary>
        internal TemplateFunctionCall(FunctionExpression expression, PolicyExpression parent)
            : base(parent)
        {
            this.Name = expression.Function;
            this.Arguments = expression.Parameters
                .CoalesceEnumerable()
                .Select(argument => TemplateLanguageNode.Create(expression: argument, parent: this))
                .ToImmutableArray();
            this.Selectors = expression.Properties
                .CoalesceEnumerable()
                .Select(selector => TemplateLanguageNode.Create(expression: selector, parent: this))
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

        /// <inheritdoc/>
        internal override bool TryEvaluate([NotNullWhen(true)] out JToken? value)
        {
            value = null;
            if (this.Reference != null || !TemplateFunctionCall.BuiltInFunctions.IsBuiltInFunction(this.Name))
            {
                return false;
            }

            var argumentValues = new JToken[this.Arguments.Length];
            for (var index = 0; index < this.Arguments.Length; index++)
            {
                if (!this.Arguments[index].TryEvaluate(out var argumentValue))
                {
                    return false;
                }

                argumentValues[index] = argumentValue;
            }

            var properties = new JToken[this.Selectors.Length];
            for (var index = 0; index < this.Selectors.Length; index++)
            {
                if (!this.Selectors[index].TryEvaluate(out var property))
                {
                    return false;
                }

                properties[index] = property;
            }

            try
            {
                // Property selection follows policy evaluation: e.g. a missing property or an index out of range fails.
                FunctionResult result = new JTokenSelectableFunctionResult(root: TemplateFunctionCall.BuiltInFunctions.EvaluateFunction(functionName: this.Name, parameters: argumentValues));
                foreach (var property in properties)
                {
                    result = result.SelectProperty(property: property);
                }

                value = result.CurrentValue();
                return true;
            }
            catch (Exception exception) when (!exception.IsFatal())
            {
                value = null;
                return false;
            }
        }
    }
}
