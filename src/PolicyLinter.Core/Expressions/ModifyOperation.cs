// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License.
// ------------------------------------------------------------

namespace Microsoft.Azure.Policy.PolicyLinter.Core.Expressions
{
    using System;
    using System.Collections.Immutable;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Metadata;
    using Microsoft.Azure.Policy.PolicyLinter.Core.Parsing;

    /// <summary>
    /// A modify operation ("details.operations[i]").
    /// </summary>
    public class ModifyOperation : PolicyExpression
    {
        /// <summary>
        /// The operation kind, e.g. 'addOrReplace'.
        /// </summary>
        public Property? Operation { get; }

        /// <summary>
        /// The field accessor of the field to modify.
        /// </summary>
        public Property? Field { get; }

        /// <summary>
        /// The value to write.
        /// </summary>
        public Property? Value { get; }

        /// <summary>
        /// The condition for applying the operation.
        /// </summary>
        public Property? Condition { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="ModifyOperation"/> class.
        /// </summary>
        /// <param name="operation">The parsed operation.</param>
        /// <param name="path">The path of the operation.</param>
        /// <param name="parent">The parent of the current expression.</param>
        /// <param name="typeMetadata">The type metadata.</param>
        public ModifyOperation(
            GenericObjectProperty<ModifyOperationObject>? operation,
            ImmutableArray<string> path,
            PolicyExpression parent,
            ITypeMetadata typeMetadata) : base(operation?.LineNumber, operation?.LinePosition, path, parent)
        {
            if (operation?.Value == null)
            {
                throw new ArgumentNullException(nameof(operation), "Modify operation cannot be null.");
            }

            this.Operation = operation.Value.Operation.CreateProperty(name: "operation", parent: this, typeMetadata: typeMetadata);
            this.Field = operation.Value.Field.CreateProperty(name: "field", parent: this, typeMetadata: typeMetadata, isFieldAccessor: true);
            this.Value = operation.Value.Value.CreateProperty(name: "value", parent: this, typeMetadata: typeMetadata);
            this.Condition = operation.Value.Condition.CreateProperty(name: "condition", parent: this, typeMetadata: typeMetadata);
        }

        /// <inheritdoc/>
        public override void Visit(PolicyExpressionVisitor visitor)
        {
            visitor.Visit?.Invoke(this);
            this.Operation?.Visit(visitor);
            this.Field?.Visit(visitor);
            this.Value?.Visit(visitor);
            this.Condition?.Visit(visitor);
        }
    }
}
