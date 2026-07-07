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
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);
                this.Effect.Visit(visitor);
            }
        }
    }
}
