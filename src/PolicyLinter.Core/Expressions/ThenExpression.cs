// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using Microsoft.Azure.Policy.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Rules.Contracts;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Represents the "then" expression in a policy rule.
    /// </summary>
    public class ThenExpression : PolicyExpression
    {
        /// <summary>
        /// The policy effect property.
        /// </summary>
        public Property Effect { get; }

        /// <summary>
        /// The effect details. Null when the policy has no details, or when their shape is unknown or malformed.
        /// </summary>
        public EffectDetails? Details { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="ThenExpression"/> class.
        /// </summary>
        /// <param name="then">The then expression.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public ThenExpression(
            GenericObjectProperty<ThenObject>? then,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(then?.LineNumber, then?.LinePosition, parentPath.Concat("then").ToImmutableArray(), parent)
        {
            this.Effect = new Property(
                name: "effect",
                value: then?.Value.Effect?.Value,
                jTokenMetadata: then?.Value.Effect,
                isFieldAccessor: false,
                parentPath: this.PathSegments,
                parent: this,
                countExpressionScopes: new Stack<CountExpressionScope>(),
                typeMetadata: typeMetadata);

            this.Details = EffectDetails.TryCreate(
                details: then?.Value.Details,
                parentPath: this.PathSegments,
                parent: this,
                typeMetadata: typeMetadata);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);
                this.Effect.Visit(visitor);
                this.Details?.Visit(visitor);
            }
        }

        /// <summary>
        /// Determines whether the policy can have one of the given effects: the effect is one of them, or is a simple
        /// parameter reference whose allowedValues include one of them. A parameter without allowedValues returns false.
        /// </summary>
        /// <param name="context">The linter rule evaluation context.</param>
        /// <param name="effects">The effects to look for, compared by the set's comparer.</param>
        public bool CanHaveEffect(LinterContext context, ISet<string> effects)
        {
            if (this.Effect.HasLiteralValue)
            {
                return effects.Contains(this.Effect.Value.ToString());
            }

            return this.Effect.HasSimpleParameterizedValue(context: context, out _, out var allowedValues, out _) &&
                allowedValues != null &&
                allowedValues.Any(effects.Contains);
        }
    }
}
