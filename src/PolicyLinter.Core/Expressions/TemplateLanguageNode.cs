// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System.Collections.Immutable;
    using System.Linq;
    using global::Azure.Deployments.Expression.Expressions;
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
        /// The parsed expression. Private by design, to keep expression engine types out of the linter rules.
        /// </summary>
        private readonly LanguageExpression expression;

        /// <summary>
        /// Creates a new instance of the <see cref="TemplateLanguageNode"/> class.
        /// </summary>
        private protected TemplateLanguageNode(LanguageExpression expression, PolicyExpression parent)
            : base(parent.LineNumber, parent.LinePosition, parent.PathSegments, parent)
        {
            this.expression = expression;
        }

        /// <summary>
        /// Whether this node is a reference to a value known only when the policy is evaluated: a resource field (including current() in a field count),
        /// a request context or token claims property, or a resource group or subscription property, e.g. "field('name')" or "requestContext().apiVersion".
        /// </summary>
        /// <remarks>
        /// Policy parameters and current() in a value count are not treated as evaluation time values.
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
        /// Evaluates the node with the given evaluation context, e.g. 'a' in "field('a')".
        /// </summary>
        /// <param name="evaluationContext">The evaluation context.</param>
        internal JToken Evaluate(IEvaluationContext evaluationContext)
        {
            return this.expression.EvaluateExpression(evaluationContext);
        }

        /// <summary>
        /// Creates the node for the given parsed expression.
        /// </summary>
        internal static TemplateLanguageNode Create(LanguageExpression expression, PolicyExpression parent)
        {
            return expression is FunctionExpression function
                ? new TemplateFunctionCall(function, parent)
                : new TemplateLiteralValue((JTokenExpression)expression, parent);
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
        internal TemplateLiteralValue(JTokenExpression expression, PolicyExpression parent)
            : base(expression, parent)
        {
            this.Value = expression.Value;
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
        /// Creates a new instance of the <see cref="TemplateFunctionCall"/> class and the nodes below it.
        /// </summary>
        internal TemplateFunctionCall(FunctionExpression expression, PolicyExpression parent)
            : base(expression, parent)
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
    }
}
