// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    /// <summary>
    /// The denyAction effect details.
    /// </summary>
    public class ActionDetails : PolicyExpression
    {
        /// <summary>
        /// The actions to deny.
        /// </summary>
        public Property? ActionNames { get; }

        /// <summary>
        /// The behavior on cascade deletion.
        /// </summary>
        public Property? CascadeBehaviors { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="ActionDetails"/> class.
        /// </summary>
        /// <param name="details">The parsed details.</param>
        /// <param name="path">The path of the details.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public ActionDetails(
            GenericObjectProperty<ActionDetailsObject> details,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(details.LineNumber, details.LinePosition, path, parent)
        {
            this.ActionNames = Property.CreateOptional(property: details.Value.ActionNames, name: "actionNames", parent: this, typeMetadata: typeMetadata);
            this.CascadeBehaviors = Property.CreateOptional(property: details.Value.CascadeBehaviors, name: "cascadeBehaviors", parent: this, typeMetadata: typeMetadata);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.ActionNames?.Visit(visitor);
            this.CascadeBehaviors?.Visit(visitor);
        }
    }
}
