// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions
{
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions.EvaluationHelpers;
    using System;
    using System.Collections.Generic;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Represents th "if" condition a policy rule.
    /// </summary>
    public class IfCondition : PolicyExpression
    {
        /// <summary>
        /// The condition expression.
        /// </summary>
        public Condition Condition { get; }

        /// <summary>
        /// Creates an instance of the <see cref="IfCondition"/> class.
        /// </summary>
        /// <param name="ifConditionProperty">The if condition expression.</param>
        /// <param name="parentPath">The path of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public IfCondition(
            GenericObjectProperty<ConditionObject>? ifConditionProperty,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(ifConditionProperty?.LineNumber, ifConditionProperty?.LinePosition, parentPath.Concat("if").ToImmutableArray(), parent)
        {
            if (ifConditionProperty == null)
            {
                // TODO: Better exception
                throw new ArgumentNullException(nameof(ifConditionProperty), "If condition cannot be null.");
            }

            this.Condition = ifConditionProperty.CreateCondition(
                conditionPath: this.PathSegments,
                typeMetadata: typeMetadata,
                parent: this,
                countExpressionScopes: new Stack<CountExpressionScope>());
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            if (visitor?.Visit != null)
            {
                visitor.Visit(this);
                this.Condition.Visit(visitor);
            }
        }
    }
}
