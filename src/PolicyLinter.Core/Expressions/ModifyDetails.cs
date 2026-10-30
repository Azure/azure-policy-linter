// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using System.Linq;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    /// <summary>
    /// The modify effect details.
    /// </summary>
    public class ModifyDetails : PolicyExpression
    {
        /// <summary>
        /// The role definition IDs needed for remediation.
        /// </summary>
        public Property? RoleDefinitionIds { get; }

        /// <summary>
        /// The effect to apply on a conflict.
        /// </summary>
        public Property? ConflictEffect { get; }

        /// <summary>
        /// The modify operations.
        /// </summary>
        public ImmutableArray<ModifyOperation> Operations { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="ModifyDetails"/> class.
        /// </summary>
        /// <param name="details">The parsed details.</param>
        /// <param name="path">The path of the details.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public ModifyDetails(
            GenericObjectProperty<ModifyDetailsObject> details,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(details.LineNumber, details.LinePosition, path, parent)
        {
            this.RoleDefinitionIds = Property.CreateOptional(property: details.Value.RoleDefinitionIds, name: "roleDefinitionIds", parent: this, typeMetadata: typeMetadata);
            this.ConflictEffect = Property.CreateOptional(property: details.Value.ConflictEffect, name: "conflictEffect", parent: this, typeMetadata: typeMetadata);
            this.Operations = (details.Value.Operations?.Value ?? Array.Empty<GenericObjectProperty<ModifyOperationObject>>())
                .Select((operation, index) => new ModifyOperation(
                    operation: operation,
                    path: this.PathSegments.Add($"operations[{index}]"),
                    parent: this,
                    typeMetadata: typeMetadata))
                .ToImmutableArray();
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.RoleDefinitionIds?.Visit(visitor);
            this.ConflictEffect?.Visit(visitor);

            foreach (var operation in this.Operations)
            {
                operation.Visit(visitor);
            }
        }
    }
}
