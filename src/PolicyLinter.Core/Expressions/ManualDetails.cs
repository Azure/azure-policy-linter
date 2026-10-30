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
    /// The manual effect details.
    /// </summary>
    public class ManualDetails : PolicyExpression
    {
        /// <summary>
        /// The default compliance state.
        /// </summary>
        public Property? DefaultState { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="ManualDetails"/> class.
        /// </summary>
        /// <param name="details">The parsed details.</param>
        /// <param name="path">The path of the details.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public ManualDetails(
            GenericObjectProperty<ManualDetailsObject> details,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(details.LineNumber, details.LinePosition, path, parent)
        {
            this.DefaultState = details.Value.DefaultState.CreateProperty(name: "defaultState", parent: this, typeMetadata: typeMetadata);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.DefaultState?.Visit(visitor);
        }
    }
}
