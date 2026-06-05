// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Metadata;
    using Microsoft.WindowsAzure.Governance.PolicyLinter.Core.Parsing;
    using Microsoft.WindowsAzure.ResourceStack.Common.Extensions;

    /// <summary>
    /// Represents a policy rule expression.
    /// </summary>
    public class PolicyRule : PolicyExpression
    {
        /// <summary>
        /// The if condition.
        /// </summary>
        public IfCondition If { get; }

        /// <summary>
        /// The then expression.
        /// </summary>
        public ThenExpression Then { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="PolicyRule"/> class.
        /// </summary>
        /// <param name="policyRuleProperty">The raw policy rule definition.</param>
        /// <param name="parentPath">The path of the parent of the current expression.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public PolicyRule(
            GenericObjectProperty<PolicyRuleObject>? policyRuleProperty,
            ImmutableArray<string> parentPath,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(policyRuleProperty?.LineNumber, policyRuleProperty?.LinePosition, parentPath.Concat("policyRule").ToImmutableArray(), parent)
        {
            if (policyRuleProperty == null)
            {
                throw new ArgumentNullException(nameof(policyRuleProperty), "Policy rule cannot be null.");
            }

            this.If = new IfCondition(
                ifConditionProperty: policyRuleProperty.Value.If,
                typeMetadata: typeMetadata,
                parentPath: this.PathSegments,
                parent: this);

            this.Then = new ThenExpression(
                then: policyRuleProperty.Value.Then,
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
                this.If.Visit(visitor);
                this.Then.Visit(visitor);
            }
        }
    }
}
