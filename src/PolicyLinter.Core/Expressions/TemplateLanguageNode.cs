// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System.Collections.Generic;
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
        /// Creates a new instance of the <see cref="TemplateLanguageNode"/> class.
        /// </summary>
        private protected TemplateLanguageNode(PolicyExpression parent)
            : base(parent.LineNumber, parent.LinePosition, parent.PathSegments, parent)
        {
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
        /// Creates the node for the given parsed expression.
        /// </summary>
        internal static TemplateLanguageNode Create(
            LanguageExpression expression,
            PolicyExpression parent,
            bool isConditionallyEvaluated,
            IReadOnlyDictionary<FunctionExpression, Reference> references)
        {
            return expression is FunctionExpression function
                ? new TemplateFunctionCall(function, parent, isConditionallyEvaluated, references)
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
        public Reference? Reference { get; }

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
            IReadOnlyDictionary<FunctionExpression, Reference> references)
            : base(parent)
        {
            this.Name = expression.Function;
            this.IsConditionallyEvaluated = isConditionallyEvaluated;
            this.Reference = references.TryGetValue(expression, out var reference) ? reference : null;
            this.Arguments = expression.Parameters
                .CoalesceEnumerable()
                .Select((argument, index) => TemplateLanguageNode.Create(
                    expression: argument,
                    parent: this,
                    isConditionallyEvaluated: isConditionallyEvaluated || (this.Name.EqualsOrdinalInsensitively("if") && index > 0),
                    references: references))
                .ToImmutableArray();
            this.Selectors = expression.Properties
                .CoalesceEnumerable()
                .Select(selector => TemplateLanguageNode.Create(expression: selector, parent: this, isConditionallyEvaluated: isConditionallyEvaluated, references: references))
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
